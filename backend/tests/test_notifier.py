"""The critical-attack notifier (Telegram).

No real HTTP is made: `_post` is replaced with a recorder.
"""

from types import SimpleNamespace

import pytest

from app.intelligence.notifier import Notifier


class _FakeConfig:
    def __init__(self, section):
        self._section = section

    def section(self, name):
        return self._section if name == "notifications" else {}


def _assessment(actor="203.0.113.66", risk=95, succeeded=True):
    decision = SimpleNamespace(risk_score=risk, rationale="Block it.")
    prediction = SimpleNamespace(current_stage_name="Persistence", summary="bad things")
    return SimpleNamespace(
        actor=actor, decision=decision, prediction=prediction,
        succeeded=succeeded, narrative="A concise incident summary.",
    )


@pytest.fixture
def sent(monkeypatch):
    calls = []
    monkeypatch.setattr(Notifier, "_post",
                        lambda self, url, payload: calls.append((url, payload)))
    return calls


def _notifier(**section):
    section.setdefault("enabled", True)
    section.setdefault("risk_threshold", 90)
    section.setdefault("telegram_bot_token", "123456:AA-token")
    section.setdefault("telegram_chat_id", "42")
    return Notifier(_FakeConfig(section))


def test_alerts_are_enabled_by_default():
    #a bare notifier with no config still comes up enabled
    n = Notifier(None)
    assert n.enabled is True
    #...but sends nothing until a bot token is set
    assert n.configured is False


def test_disabled_notifier_sends_nothing(sent):
    n = _notifier(enabled=False)
    assert n.notify_critical(_assessment()) is None
    assert sent == []


def test_below_threshold_sends_nothing(sent):
    n = _notifier(risk_threshold=90)
    assert n.notify_critical(_assessment(risk=80)) is None
    assert sent == []


def test_unconfigured_sends_nothing(sent):
    n = _notifier(telegram_bot_token="", telegram_chat_id="")
    assert n.configured is False
    assert n.notify_critical(_assessment()) is None
    assert sent == []


def test_critical_incident_fires_one_telegram_alert_with_the_key_facts(sent):
    n = _notifier()

    result = n.notify_critical(_assessment(actor="10.0.5.11", risk=97), target="db-01")

    assert result is not None and result["sent"] == [{"transport": "telegram", "ok": True}]
    assert len(sent) == 1

    url, payload = sent[0]
    assert url == "https://api.telegram.org/bot123456:AA-token/sendMessage"
    assert payload["chat_id"] == "42"
    text = payload["text"]
    assert "10.0.5.11" in text          # attacker
    assert "db-01" in text              # target
    assert "97/100" in text             # risk score
    assert "Persistence" in text        # attack type


def test_the_same_attacker_is_only_alerted_once(sent):
    n = _notifier()
    a = _assessment(actor="10.0.5.20", risk=99)

    assert n.notify_critical(a) is not None
    assert n.notify_critical(a) is None       # deduped
    assert len(sent) == 1

    n.reset()
    assert n.notify_critical(a) is not None   # reset clears the dedupe set
    assert len(sent) == 2


def test_send_text_reports_a_transport_failure(monkeypatch):
    def boom(self, url, payload):
        raise OSError("connection refused")

    monkeypatch.setattr(Notifier, "_post", boom)
    n = _notifier()

    results = n.send_text("hi")

    assert results == [{"transport": "telegram", "ok": False, "error": "connection refused"}]
    assert "connection refused" in n.status()["last_error"]


def test_status_shape():
    n = _notifier()
    status = n.status()
    for key in ("enabled", "platform", "risk_threshold", "telegram_ready",
                "configured", "alerts_sent"):
        assert key in status
    assert status["platform"] == "telegram"


def test_runtime_configure_toggles_state():
    n = _notifier(enabled=True)
    assert n.enabled is True

    n.configure(enabled=False, risk_threshold=75)

    assert n.enabled is False
    assert n.risk_threshold == 75
