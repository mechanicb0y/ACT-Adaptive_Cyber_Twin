"""Phase 5: the audit-log read API (admin only)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    from app.core.settings import reload_settings
    from app.db import reset_engine
    from app.api.deps import reset_engine_singleton

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'a.db').as_posix()}")
    monkeypatch.setenv("ACT_AUTH_ENABLED", "true")
    monkeypatch.setenv("ACT_JWT_SECRET", "audit-secret-0123456789-abcdefghijkl")
    monkeypatch.setenv("ACT_ADMIN_PASSWORD", "auditadminpw1")
    reload_settings()
    reset_engine()
    reset_engine_singleton()
    from app.api.main import app
    with TestClient(app) as c:
        yield c
    reset_engine()
    reload_settings()


def _tok(client, user="admin", pw="auditadminpw1"):
    return client.post("/api/auth/login",
                       json={"username": user, "password": pw}).json()["access_token"]


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def test_login_writes_an_audit_row_visible_to_admin(client):
    admin = _tok(client)
    body = client.get("/api/v1/audit", headers=_h(admin)).json()
    actions = {e["action"] for e in body["entries"]}
    assert "login" in actions
    assert body["total"] >= 1


def test_failed_login_is_audited(client):
    client.post("/api/auth/login", json={"username": "admin", "password": "nope"})
    admin = _tok(client)
    body = client.get("/api/v1/audit?action=login.failed", headers=_h(admin)).json()
    assert body["count"] >= 1
    assert all(e["action"] == "login.failed" for e in body["entries"])


def test_sensitive_engine_actions_are_audited(client):
    admin = _tok(client)
    client.post("/api/v1/arm", headers=_h(admin))
    client.post("/api/v1/disarm", headers=_h(admin))
    client.post("/api/v1/reset", headers=_h(admin))

    body = client.get("/api/v1/audit?action=responder.*", headers=_h(admin)).json()
    got = {e["action"] for e in body["entries"]}
    assert {"responder.arm", "responder.disarm"} <= got


def test_audit_requires_admin(client):
    admin = _tok(client)
    client.post("/api/auth/users", headers=_h(admin), json={
        "username": "view", "password": "viewerpass1", "role": "viewer"})
    viewer = _tok(client, "view", "viewerpass1")
    assert client.get("/api/v1/audit", headers=_h(viewer)).status_code == 403
    assert client.get("/api/v1/audit").status_code == 401


def test_audit_filters_and_pagination(client):
    admin = _tok(client)
    for _ in range(3):
        client.post("/api/auth/login", json={"username": "admin", "password": "x"})

    page1 = client.get("/api/v1/audit?limit=2&offset=0", headers=_h(admin)).json()
    page2 = client.get("/api/v1/audit?limit=2&offset=2", headers=_h(admin)).json()
    assert page1["count"] == 2 and page1["offset"] == 0
    ids1 = {e["id"] for e in page1["entries"]}
    ids2 = {e["id"] for e in page2["entries"]}
    assert ids1.isdisjoint(ids2)

    by_actor = client.get("/api/v1/audit?actor=admin", headers=_h(admin)).json()
    assert all(e["actor"] == "admin" for e in by_actor["entries"])
