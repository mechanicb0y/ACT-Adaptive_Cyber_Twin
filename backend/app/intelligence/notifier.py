#Instant out-of-band alerts when ACT sees a critical attack (risk >= threshold).
#
#Transport: Telegram Bot API - TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID, plain
#HTTPS, no SDK.
#
#Design rules, same spirit as the rest of ACT:
#   * everything degrades gracefully - not enabled, or no token, and
#     notify_critical() is a no-op that never raises;
#   * one alert per attacker per session (deduped), so a dashboard that polls
#     every second does not send the same alert 60 times a minute;
#   * the token comes from the environment (backend/.env) first, then the
#     config file, so it is never committed.

import json
import os
import threading
import urllib.request
from typing import Any, Dict, List, Optional

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"


def _email_sender():
    """Late import so the notifier stays usable if app.core is unavailable."""
    try:
        from app.core.email import EmailSender
        from app.core.settings import get_settings
        settings = get_settings()
        return EmailSender.from_settings(settings), settings
    except Exception:                                       # noqa: BLE001
        return None, None


class Notifier:

    def __init__(self, config=None):

        section: Dict[str, Any] = {}
        if config is not None:
            try:
                section = config.section("notifications") or {}
            except Exception:                               # noqa: BLE001
                section = {}

        self.enabled = bool(section.get("enabled", True))

        self.risk_threshold = int(section.get("risk_threshold", 90))

        #env wins over the config file so a real token stays out of git
        self.telegram_token = (
            os.environ.get("TELEGRAM_BOT_TOKEN") or section.get("telegram_bot_token") or ""
        ).strip()
        self.telegram_chat = str(
            os.environ.get("TELEGRAM_CHAT_ID") or section.get("telegram_chat_id") or ""
        ).strip()

        self.timeout = int(os.environ.get("ACT_NOTIFY_TIMEOUT", section.get("timeout", 8)))

        # optional email transport (SMTP), configured entirely via settings/.env
        self._email, _settings = _email_sender()
        self.email_alerts_enabled = bool(getattr(_settings, "email_alerts_enabled", False))
        self.alert_email_to = getattr(_settings, "alert_email_to", None) or ""

        self._sent: set = set()
        self._lock = threading.Lock()
        self._last_error: Optional[str] = None

    # ------------------------------------------------------------------ #
    # configuration
    # ------------------------------------------------------------------ #

    @property
    def telegram_ready(self) -> bool:
        return bool(self.telegram_token and self.telegram_chat)

    @property
    def email_ready(self) -> bool:
        return bool(
            self.email_alerts_enabled
            and self.alert_email_to
            and self._email is not None
            and self._email.configured
        )

    @property
    def configured(self) -> bool:
        return self.telegram_ready or self.email_ready

    def configure(
        self,
        enabled: Optional[bool] = None,
        risk_threshold: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Runtime toggle from the dashboard. Persistent config still lives in
        backend/config/detection.json and backend/.env."""

        if enabled is not None:
            self.enabled = bool(enabled)
        if risk_threshold is not None:
            self.risk_threshold = max(0, min(100, int(risk_threshold)))
        return self.status()

    def status(self) -> Dict[str, Any]:
        transports = []
        if self.telegram_ready:
            transports.append("telegram")
        if self.email_ready:
            transports.append("email")
        return {
            "enabled": self.enabled,
            "platform": "telegram",
            "transports": transports,
            "risk_threshold": self.risk_threshold,
            "telegram_ready": self.telegram_ready,
            "email_ready": self.email_ready,
            "configured": self.configured,
            "alerts_sent": len(self._sent),
            "last_error": self._last_error,
        }

    def reset(self) -> None:
        with self._lock:
            self._sent.clear()
        self._last_error = None

    # ------------------------------------------------------------------ #
    # sending
    # ------------------------------------------------------------------ #

    def _post(self, url: str, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url, data=data, headers={"content-type": "application/json"}
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            response.read()

    def send_text(self, text: str, *, subject: str = "ACT alert") -> List[Dict[str, Any]]:
        """Send `text` over every ready transport (Telegram, email). Returns one
        result row per transport. Never raises."""

        results: List[Dict[str, Any]] = []

        if self.telegram_ready:
            try:
                self._post(
                    TELEGRAM_API.format(token=self.telegram_token),
                    {"chat_id": self.telegram_chat, "text": text,
                     "parse_mode": "Markdown", "disable_web_page_preview": True},
                )
                results.append({"transport": "telegram", "ok": True})
            except Exception as error:                      # noqa: BLE001
                self._last_error = f"telegram: {error}"
                results.append({"transport": "telegram", "ok": False,
                                "error": str(error)})

        if self.email_ready:
            ok, error = self._email.send(self.alert_email_to, subject, text)
            row = {"transport": "email", "ok": ok}
            if not ok:
                self._last_error = f"email: {error}"
                row["error"] = error
            results.append(row)

        return results

    # ------------------------------------------------------------------ #

    @staticmethod
    def _format(actor: str, target: Optional[str], attack_type: str,
                risk: int, summary: str) -> str:
        return (
            f"🚨 *ACT critical alert*\n"
            f"*Attacker:* `{actor}`\n"
            f"*Target:* {target or 'monitored host'}\n"
            f"*Attack type:* {attack_type}\n"
            f"*Risk score:* {risk}/100\n"
            f"*Summary:* {summary}"
        )

    def should_notify(self, assessment) -> bool:
        if not self.enabled or not self.configured:
            return False
        risk = getattr(assessment.decision, "risk_score", 0) or 0
        if risk < self.risk_threshold:
            return False
        actor = assessment.actor or "unknown"
        with self._lock:
            return actor not in self._sent

    def notify_critical(self, assessment, target: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Alert on a critical incident, once per attacker. Returns the send
        result, or None when nothing was sent (disabled, below threshold,
        already alerted, not configured)."""

        if not self.should_notify(assessment):
            return None

        actor = assessment.actor or "unknown"

        with self._lock:
            if actor in self._sent:
                return None
            self._sent.add(actor)

        decision = assessment.decision
        prediction = assessment.prediction

        attack_type = prediction.current_stage_name or "multi-stage intrusion"
        if getattr(assessment, "succeeded", False):
            attack_type += " (host compromised)"

        summary = (assessment.narrative or prediction.summary or decision.rationale or "").strip()
        if len(summary) > 320:
            summary = summary[:317] + "..."

        text = self._format(actor, target, attack_type, decision.risk_score or 0, summary)
        results = self.send_text(text)

        return {
            "actor": actor,
            "risk_score": decision.risk_score,
            "sent": [r for r in results if r.get("ok")],
            "failed": [r for r in results if not r.get("ok")],
        }
