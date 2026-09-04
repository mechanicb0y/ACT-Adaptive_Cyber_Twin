"""Phase 5: optional observability wiring (OpenTelemetry + Sentry)."""

from __future__ import annotations

import pytest

from app.core import tracing
from app.core.settings import reload_settings


def test_disabled_by_default_is_a_noop(monkeypatch):
    monkeypatch.delenv("ACT_OTEL_ENABLED", raising=False)
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    reload_settings()

    class DummyApp:
        pass

    tracing._STATE.update(otel=False, sentry=False)
    tracing.configure_observability(DummyApp())
    assert tracing.observability_status() == {"otel": False, "sentry": False}


def test_otel_enabled_without_packages_warns_not_raises(monkeypatch, caplog):
    monkeypatch.setenv("ACT_OTEL_ENABLED", "true")
    monkeypatch.setenv("ACT_OTEL_CONSOLE", "true")
    reload_settings()

    real_import = __import__

    def fake_import(name, *a, **k):
        if name.startswith("opentelemetry"):
            raise ImportError("simulated missing package")
        return real_import(name, *a, **k)

    monkeypatch.setattr("builtins.__import__", fake_import)
    tracing._STATE.update(otel=False, sentry=False)
    tracing.configure_observability(object())          # must not raise
    assert tracing.observability_status()["otel"] is False


def test_otel_enabled_with_packages_instruments(monkeypatch):
    pytest.importorskip("opentelemetry.sdk.trace")
    pytest.importorskip("opentelemetry.instrumentation.fastapi")
    from fastapi import FastAPI

    monkeypatch.setenv("ACT_OTEL_ENABLED", "true")
    monkeypatch.setenv("ACT_OTEL_CONSOLE", "true")
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    reload_settings()

    app = FastAPI()
    tracing._STATE.update(otel=False, sentry=False)
    try:
        tracing.configure_observability(app)
        assert tracing.observability_status()["otel"] is True
    finally:
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            FastAPIInstrumentor.uninstrument_app(app)
        except Exception:  # noqa: BLE001
            pass


def test_sentry_enabled_with_package(monkeypatch):
    sentry_sdk = pytest.importorskip("sentry_sdk")
    calls = {}
    monkeypatch.setattr(sentry_sdk, "init",
                        lambda **kw: calls.update(kw))
    monkeypatch.setenv("SENTRY_DSN", "https://example@o0.ingest.sentry.io/0")
    monkeypatch.setenv("SENTRY_TRACES_SAMPLE_RATE", "0.25")
    reload_settings()

    tracing._STATE.update(otel=False, sentry=False)
    tracing.configure_observability(object())
    assert calls["dsn"].startswith("https://example@")
    assert calls["traces_sample_rate"] == 0.25
    assert tracing.observability_status()["sentry"] is True
