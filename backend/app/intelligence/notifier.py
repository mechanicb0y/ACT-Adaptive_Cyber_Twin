#Instant out-of-band alerts when ACT sees a critical attack (risk >= threshold).
#
#Two transports, both plain HTTPS with no SDK:
#   * Telegram Bot API   -  TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID
#   * Slack Incoming Webhook  -  SLACK_WEBHOOK_URL
#
#Design rules, same spirit as the rest of ACT:
#   * everything degrades gracefully - not enabled, or not configured, and
#     notify_critical() is a no-op that never raises;
#   * one alert per attacker per session (deduped), so a dashboard that polls
#     every second does not send the same alert 60 times a minute;
#   * secrets come from the environment (backend/.env) first, then the config
#     file, so tokens are never committed.

import json
import os
import threading
import urllib.request
from typing import Any, Dict, List, Optional

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"

VALID_PLATFORMS = ("telegram", "slack", "both")


class Notifier:

    def __init__(self, config=None):

        section: Dict[str, Any] = {}
        if config is not None:
            try:
                section = config.section("notifications") or {}
            except Exception:                               # noqa: BLE001
                section = {}

        self.enabled = bool(section.get("enabled", False))

        platform = str(section.get("platform", "both")).lower().strip()
        self.platform = platform if platform in VALID_PLATFORMS else "both"

        self.risk_threshold = int(section.get("risk_threshold", 90))

        #env wins over the config file so real tokens stay out of git
        self.telegram_token = (
            os.environ.get("TELEGRAM_BOT_TOKEN") or section.get("telegram_bot_token") or ""
        ).strip()
        self.telegram_chat = str(
            os.environ.get("TELEGRAM_CHAT_ID") or section.get("telegram_chat_id") or ""
        ).strip()
        self.slack_webhook = (
            os.environ.get("SLACK_WEBHOOK_URL") or section.get("slack_webhook_url") or ""
        ).strip()

        self.timeout = int(os.environ.get("ACT_NOTIFY_TIMEOUT", section.get("timeout", 8)))

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
    def slack_ready(self) -> bool:
        return bool(self.slack_webhook)

    def _targets(self) -> List[str]:
        want = ("telegram", "slack") if self.platform == "both" else (self.platform,)
        ready = []
        if "telegram" in want and self.telegram_ready:
            ready.append("telegram")
        if "slack" in want and self.slack_ready:
            ready.append("slack")
        return ready

    @property
    def configured(self) -> bool:
        return bool(self._targets())

    def configure(
        self,
        enabled: Optional[bool] = None,
        platform: Optional[str] = None,
        risk_threshold: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Runtime toggle from the dashboard. Persistent config still lives in
        backend/config/detection.json and backend/.env."""

        if enabled is not None:
            self.enabled = bool(enabled)
        if platform is not None:
            p = str(platform).lower().strip()
            if p in VALID_PLATFORMS:
                self.platform = p
        if risk_threshold is not None:
            self.risk_threshold = max(0, min(100, int(risk_threshold)))
        return self.status()

    def status(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "platform": self.platform,
            "risk_threshold": self.risk_threshold,
            "telegram_ready": self.telegram_ready,
            "slack_ready": self.slack_ready,
            "configured": self.configured,
            "active_transports": self._targets(),
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

    def _post(self, url: str, payload: dict, headers: Optional[dict] = None) -> None:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url, data=data, headers={"content-type": "application/json", **(headers or {})}
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            response.read()

    def _send_telegram(self, text: str) -> None:
        self._post(
            TELEGRAM_API.format(token=self.telegram_token),
            {"chat_id": self.telegram_chat, "text": text, "parse_mode": "Markdown",
             "disable_web_page_preview": True},
        )

    def _send_slack(self, text: str) -> None:
        self._post(self.slack_webhook, {"text": text})

    def send_text(self, text: str) -> List[Dict[str, Any]]:
        """Send `text` on every ready transport for the chosen platform.

        Returns one result row per transport. Used by notify_critical() and by
        the dashboard's 'send test' button. Never raises.
        """

        results: List[Dict[str, Any]] = []
        for transport in self._targets():
            try:
                if transport == "telegram":
                    self._send_telegram(text)
                else:
                    self._send_slack(text)
                results.append({"transport": transport, "ok": True})
            except Exception as error:                      # noqa: BLE001
                self._last_error = f"{transport}: {error}"
                results.append({"transport": transport, "ok": False, "error": str(error)})
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
