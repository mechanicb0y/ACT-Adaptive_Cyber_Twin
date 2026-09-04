"""Phase 5 (security follow-up): Host-header allowlist + reset-link base.

The password-reset link base must never come from the request Host - a forged
Host would send the victim a link to the attacker's site.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.hosts import host_allowed


# ------------------------------------------------------------- unit: matcher #


@pytest.mark.parametrize("host,allow,ok", [
    ("act.example.com", ["act.example.com"], True),
    ("act.example.com:443", ["act.example.com"], True),
    ("evil.com", ["act.example.com"], False),
    ("api.act.example.com", [".act.example.com"], True),
    ("act.example.com", [".act.example.com"], True),
    ("evil.com", ["*"], True),
    ("anything", [], True),
])
def test_host_allowed(host, allow, ok):
    assert host_allowed(host, allow) is ok


# ----------------------------------------------------- middleware in the app #


@pytest.fixture
def make_client(monkeypatch, tmp_path):
    from app.core.settings import reload_settings
    from app.db import reset_engine
    from app.api.deps import reset_engine_singleton

    def _build(allowed_hosts: str):
        monkeypatch.setenv("DATABASE_URL",
                           f"sqlite:///{(tmp_path / 'th.db').as_posix()}")
        monkeypatch.setenv("ACT_AUTH_ENABLED", "false")
        monkeypatch.setenv("ACT_ALLOWED_HOSTS", allowed_hosts)
        reload_settings()
        reset_engine()
        reset_engine_singleton()
        from app.api.main import app
        return TestClient(app, base_url="http://act.example.com")

    yield _build
    reset_engine()
    reload_settings()


def test_wildcard_allows_any_host(make_client):
    c = make_client("*")
    with c:
        r = c.get("/api/v1/health", headers={"Host": "whatever.test"})
        assert r.status_code == 200


def test_allowlist_blocks_a_foreign_host(make_client):
    c = make_client("act.example.com")
    with c:
        assert c.get("/api/v1/stats").status_code == 200            # matches base_url
        bad = c.get("/api/v1/stats", headers={"Host": "evil.example.com"})
        assert bad.status_code == 400
        assert "invalid host" in bad.text.lower()


def test_health_is_exempt_from_the_host_check(make_client):
    c = make_client("act.example.com")
    with c:
        r = c.get("/api/health", headers={"Host": "10.0.0.5"})
        assert r.status_code == 200


# --------------------------------------------- reset link base is not the Host #


def test_reset_link_uses_public_base_url_not_the_request(monkeypatch, tmp_path, caplog):
    import logging
    from app.core.settings import reload_settings
    from app.db import reset_engine
    from app.api.deps import reset_engine_singleton

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'r.db').as_posix()}")
    monkeypatch.setenv("ACT_AUTH_ENABLED", "true")
    monkeypatch.setenv("ACT_JWT_SECRET", "reset-host-secret-0123456789-abcdefg")
    monkeypatch.setenv("ACT_ADMIN_USERNAME", "root")
    monkeypatch.setenv("ACT_ADMIN_PASSWORD", "rootpassword1")
    monkeypatch.setenv("ACT_PUBLIC_BASE_URL", "https://act.example.com")
    reload_settings()
    reset_engine()
    reset_engine_singleton()

    from app.api.main import app
    with TestClient(app) as c:
        # give the admin an email so a reset can be issued
        tok = c.post("/api/auth/login", json={
            "username": "root", "password": "rootpassword1"}).json()["access_token"]
        me = c.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"}).json()
        c.patch(f"/api/auth/users/{me['id']}",
                headers={"Authorization": f"Bearer {tok}"},
                json={"email": "root@example.com"})

        with caplog.at_level(logging.WARNING, logger="app.auth.router"):
            r = c.post("/api/auth/password-reset/request",
                       json={"email": "root@example.com"},
                       headers={"Host": "attacker.evil"})
        assert r.status_code == 202
        logged = " ".join(rec.message for rec in caplog.records)
        assert "https://act.example.com/login?reset=" in logged
        assert "attacker.evil" not in logged

    reset_engine()
    reload_settings()
