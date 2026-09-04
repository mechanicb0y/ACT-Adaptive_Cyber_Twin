"""Phase 3: API versioning, CORS, rate-limit headers, health payload."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    from app.core.settings import reload_settings
    from app.db import reset_engine

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'v1.db').as_posix()}")
    monkeypatch.setenv("ACT_AUTH_ENABLED", "false")
    monkeypatch.setenv("ACT_CORS_ORIGINS", "https://ops.example.com")
    reload_settings()
    reset_engine()
    from app.api.deps import reset_engine_singleton
    reset_engine_singleton()

    from app.api.main import app
    with TestClient(app) as c:
        yield c

    reset_engine()
    reload_settings()


# ------------------------------------------------------------- versioning #


@pytest.mark.parametrize("path", [
    "/api/health", "/api/stats", "/api/events", "/api/behaviors",
    "/api/attack-graph", "/api/logs", "/api/notifications",
])
def test_unversioned_and_v1_both_resolve(client, path):
    legacy = client.get(path)
    versioned = client.get(path.replace("/api/", "/api/v1/", 1))
    assert legacy.status_code == 200
    assert versioned.status_code == 200
    assert legacy.json() == versioned.json() or path in ("/api/health",)


def test_only_v1_is_in_the_openapi_schema(client):
    paths = client.get("/openapi.json").json()["paths"]
    assert any(p.startswith("/api/v1/") for p in paths)
    assert not any(p.startswith("/api/") and not p.startswith("/api/v1/")
                   for p in paths)


def test_unknown_route_is_404_under_both_prefixes(client):
    assert client.get("/api/nonexistent").status_code == 404
    assert client.get("/api/v1/nonexistent").status_code == 404


# ------------------------------------------------------------------- CORS #


def test_cors_allows_the_configured_origin_only(client):
    good = client.get("/api/health", headers={"Origin": "https://ops.example.com"})
    assert good.headers.get("access-control-allow-origin") == "https://ops.example.com"

    bad = client.get("/api/health", headers={"Origin": "https://evil.example.com"})
    assert bad.headers.get("access-control-allow-origin") != "https://evil.example.com"


def test_cors_preflight_needs_no_auth(client):
    r = client.options("/api/v1/stats", headers={
        "Origin": "https://ops.example.com",
        "Access-Control-Request-Method": "GET",
    })
    assert r.status_code in (200, 204)


# ---------------------------------------------------- rate-limit headers #


def test_rate_limit_headers_present_when_enabled(monkeypatch, tmp_path):
    from app.core.settings import reload_settings
    from app.db import reset_engine
    from app.api.deps import reset_engine_singleton
    from app.api.ratelimit import get_limiter

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'rl.db').as_posix()}")
    monkeypatch.setenv("ACT_AUTH_ENABLED", "false")
    monkeypatch.setenv("ACT_RATE_LIMIT_ENABLED", "true")
    reload_settings()
    reset_engine()
    reset_engine_singleton()
    get_limiter().reset()

    from app.api.main import app
    with TestClient(app) as c:
        r = c.get("/api/health")
        assert "X-RateLimit-Limit" in r.headers
        assert int(r.headers["X-RateLimit-Remaining"]) >= 0

    get_limiter().reset()
    reset_engine()
    reload_settings()


# ------------------------------------------------------------------ health #


def test_health_payload_shape(client):
    body = client.get("/api/v1/health").json()
    for key in ("status", "version", "uptime_seconds", "auth_enabled",
                "database", "ollama", "events", "active_attack_paths",
                "last_attack_time"):
        assert key in body
    assert body["ollama"]["provider"] in ("none", "ollama", "gemini",
                                           "anthropic", "unknown")
    assert body["database"]["connected"] is True
