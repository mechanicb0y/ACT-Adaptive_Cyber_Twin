"""Phase 4: ForceHTTPSMiddleware."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def make_client(monkeypatch, tmp_path):
    from app.core.settings import reload_settings
    from app.db import reset_engine
    from app.api.deps import reset_engine_singleton

    def _build(force_https: str):
        monkeypatch.setenv("DATABASE_URL",
                           f"sqlite:///{(tmp_path / 'h.db').as_posix()}")
        monkeypatch.setenv("ACT_AUTH_ENABLED", "false")
        monkeypatch.setenv("ACT_FORCE_HTTPS", force_https)
        reload_settings()
        reset_engine()
        reset_engine_singleton()
        from app.api.main import app
        return TestClient(app)

    yield _build
    reset_engine()
    reload_settings()


def test_no_redirect_when_disabled(make_client):
    c = make_client("false")
    with c:
        assert c.get("/api/health").status_code == 200


def test_redirects_plaintext_to_https_when_enabled(make_client):
    c = make_client("true")
    with c:
        r = c.get("/api/stats", follow_redirects=False)
        assert r.status_code == 307
        assert r.headers["location"].startswith("https://")


def test_health_is_never_redirected(make_client):
    c = make_client("true")
    with c:
        assert c.get("/api/health", follow_redirects=False).status_code == 200
        assert c.get("/api/v1/health", follow_redirects=False).status_code == 200


def test_forwarded_proto_https_is_accepted(make_client):
    c = make_client("true")
    with c:
        r = c.get("/api/stats", headers={"X-Forwarded-Proto": "https"},
                  follow_redirects=False)
        assert r.status_code == 200
