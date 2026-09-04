"""Phase 3: Prometheus metrics endpoint and the recorders."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    from app.core.settings import reload_settings
    from app.db import reset_engine
    from app.api.deps import reset_engine_singleton

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'm.db').as_posix()}")
    monkeypatch.setenv("ACT_AUTH_ENABLED", "false")
    reload_settings()
    reset_engine()
    reset_engine_singleton()

    from app.api.main import app
    with TestClient(app) as c:
        yield c

    reset_engine()
    reload_settings()


def test_metrics_endpoint_serves_prometheus_text(client):
    client.get("/api/health")   # generate at least one HTTP sample
    r = client.get("/api/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    body = r.text
    for name in (
        "act_up ",
        "act_http_requests_total",
        "act_http_request_duration_seconds",
        "act_http_request_duration_p50_seconds",
        "act_active_attack_paths",
        "act_events ",
        "act_login_attempts_total",
    ):
        assert name in body, name


def test_metrics_reflect_engine_gauges(client):
    client.post("/api/ingest/file?path=auth_bruteforce.log")
    body = client.get("/api/v1/metrics").text
    # after ingesting a brute-force log there are events and at least one behaviour
    line = next(l for l in body.splitlines()
                if l.startswith("act_events ") and not l.startswith("#"))
    assert float(line.split()[1]) > 0


def test_metrics_token_gate(monkeypatch, tmp_path):
    from app.core.settings import reload_settings
    from app.db import reset_engine
    from app.api.deps import reset_engine_singleton

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'mt.db').as_posix()}")
    monkeypatch.setenv("ACT_AUTH_ENABLED", "false")
    monkeypatch.setenv("ACT_METRICS_TOKEN", "scrape-me")
    reload_settings()
    reset_engine()
    reset_engine_singleton()

    from app.api.main import app
    with TestClient(app) as c:
        assert c.get("/api/metrics").status_code == 401
        assert c.get("/api/metrics?token=wrong").status_code == 401
        assert c.get("/api/metrics?token=scrape-me").status_code == 200
        assert c.get("/api/metrics",
                     headers={"Authorization": "Bearer scrape-me"}).status_code == 200

    reset_engine()
    reload_settings()


def test_recorders_increment_counters():
    from app.core import metrics

    before = metrics.BLOCKS.labels(result="success")._value.get()
    metrics.record_block(True)
    after = metrics.BLOCKS.labels(result="success")._value.get()
    assert after == before + 1

    b2 = metrics.LOGIN_ATTEMPTS.labels(result="failure")._value.get()
    metrics.record_login(False)
    assert metrics.LOGIN_ATTEMPTS.labels(result="failure")._value.get() == b2 + 1


def test_metrics_disabled_returns_404(monkeypatch, tmp_path):
    from app.core.settings import reload_settings
    from app.db import reset_engine
    from app.api.deps import reset_engine_singleton

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'md.db').as_posix()}")
    monkeypatch.setenv("ACT_AUTH_ENABLED", "false")
    monkeypatch.setenv("ACT_METRICS_ENABLED", "false")
    reload_settings()
    reset_engine()
    reset_engine_singleton()

    from app.api.main import app
    with TestClient(app) as c:
        assert c.get("/api/metrics").status_code == 404

    reset_engine()
    reload_settings()
