"""Phase 3: the rate limiter - counting core and the middleware in context."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.ratelimit import RateLimiter


# --------------------------------------------------------------- unit core #


def test_limiter_allows_up_to_the_limit_then_blocks():
    rl = RateLimiter()
    now = 1000.0
    for i in range(5):
        allowed, remaining, retry = rl.hit("1.2.3.4", "api", limit=5, now=now)
        assert allowed is True
        assert remaining == 5 - (i + 1)
    allowed, remaining, retry = rl.hit("1.2.3.4", "api", limit=5, now=now)
    assert allowed is False and remaining == 0 and retry >= 1


def test_limiter_window_resets_after_60s():
    rl = RateLimiter()
    for _ in range(5):
        rl.hit("k", "api", 5, now=0.0)
    assert rl.hit("k", "api", 5, now=0.0)[0] is False
    assert rl.hit("k", "api", 5, now=61.0)[0] is True


def test_limiter_keys_are_independent():
    rl = RateLimiter()
    for _ in range(5):
        rl.hit("a", "api", 5, now=0.0)
    assert rl.hit("a", "api", 5, now=0.0)[0] is False
    assert rl.hit("b", "api", 5, now=0.0)[0] is True          # other client
    assert rl.hit("a", "auth", 5, now=0.0)[0] is True         # other bucket


# ------------------------------------------------------- middleware in app #


@pytest.fixture
def client(monkeypatch, tmp_path):
    from app.core.settings import reload_settings
    from app.db import reset_engine
    from app.api.deps import reset_engine_singleton
    from app.api.ratelimit import get_limiter

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'rl.db').as_posix()}")
    monkeypatch.setenv("ACT_AUTH_ENABLED", "true")
    monkeypatch.setenv("ACT_JWT_SECRET", "rate-limit-test-secret-0123456789abc")
    monkeypatch.setenv("ACT_ADMIN_PASSWORD", "ratelimitadmin1")
    monkeypatch.setenv("ACT_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("ACT_RATE_LIMIT_PER_MIN", "1000")
    monkeypatch.setenv("ACT_RATE_LIMIT_AUTH_PER_MIN", "4")
    reload_settings()
    reset_engine()
    reset_engine_singleton()
    get_limiter().reset()

    from app.api.main import app
    with TestClient(app) as c:
        yield c

    get_limiter().reset()
    reset_engine()
    reload_settings()


def test_login_bucket_returns_429_with_retry_after(client):
    body = {"username": "admin", "password": "wrong"}
    seen_429 = False
    for _ in range(8):
        r = client.post("/api/auth/login", json=body)
        if r.status_code == 429:
            seen_429 = True
            assert int(r.headers["Retry-After"]) >= 1
            assert r.json()["detail"].startswith("rate limit")
            break
    assert seen_429, "auth bucket (limit 4) should have tripped within 8 tries"


def test_regular_api_bucket_is_far_more_generous(client):
    # 20 quick reads must not trip the 1000/min api bucket
    for _ in range(20):
        assert client.get("/api/health").status_code == 200


def test_non_api_paths_are_never_limited(client):
    monkeypatch_limit = client
    for _ in range(30):
        assert monkeypatch_limit.get("/login").status_code == 200
