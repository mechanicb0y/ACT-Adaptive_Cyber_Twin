"""Phase 5: EmailSender (SMTP over the standard library, fully mocked)."""

from __future__ import annotations

import pytest

from app.core.email import EmailSender


def _sender(**over):
    base = dict(host="smtp.test", port=587, username="u", password="p",
                sender="act@test", use_starttls=True, use_ssl=False, timeout=5)
    base.update(over)
    return EmailSender(**base)


def test_unconfigured_is_a_noop_not_an_error():
    s = EmailSender(host=None, port=587, username=None, password=None,
                    sender=None, use_starttls=True, use_ssl=False, timeout=5)
    assert s.configured is False
    ok, err = s.send("x@y.z", "hi", "body")
    assert ok is False and "not configured" in err


def test_send_uses_starttls_and_login(monkeypatch):
    events = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            events.append(("connect", host, port))
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def ehlo(self): events.append(("ehlo",))
        def starttls(self, context=None): events.append(("starttls",))
        def login(self, u, p): events.append(("login", u, p))
        def send_message(self, msg):
            events.append(("send", msg["To"], msg["Subject"], msg.get_content().strip()))

    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    ok, err = _sender().send("soc@test", "ACT alert", "something happened")
    assert ok is True and err is None
    assert ("starttls",) in events
    assert ("login", "u", "p") in events
    assert ("send", "soc@test", "ACT alert", "something happened") in events


def test_send_reports_failure_without_raising(monkeypatch):
    class Boom:
        def __init__(self, *a, **k): raise OSError("connection refused")
    monkeypatch.setattr("smtplib.SMTP", Boom)
    ok, err = _sender().send("x@y.z", "s", "b")
    assert ok is False and "connection refused" in err


def test_password_reset_template_contains_link(monkeypatch):
    captured = {}

    def fake_send(self, to, subject, body, html=None):
        captured.update(to=to, subject=subject, body=body)
        return True, None

    monkeypatch.setattr(EmailSender, "send", fake_send)
    _sender().send_password_reset("u@test", username="bob",
                                  reset_url="https://act/login?reset=abc",
                                  ttl_minutes=30)
    assert "https://act/login?reset=abc" in captured["body"]
    assert "30 minutes" in captured["body"]
    assert "reset" in captured["subject"].lower()
