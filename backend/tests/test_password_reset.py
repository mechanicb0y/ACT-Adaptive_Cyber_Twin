"""Phase 5: password-reset request + confirm flow."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    from app.core.settings import reload_settings
    from app.db import reset_engine
    from app.api.deps import reset_engine_singleton

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'pr.db').as_posix()}")
    monkeypatch.setenv("ACT_AUTH_ENABLED", "true")
    monkeypatch.setenv("ACT_JWT_SECRET", "pw-reset-secret-0123456789-abcdefgh")
    monkeypatch.setenv("ACT_ADMIN_PASSWORD", "firstadminpw1")
    reload_settings()
    reset_engine()
    reset_engine_singleton()
    from app.api.main import app
    with TestClient(app) as c:
        yield c
    reset_engine()
    reload_settings()


def _admin_token(client):
    return client.post("/api/auth/login", json={
        "username": "admin", "password": "firstadminpw1"}).json()["access_token"]


def _make_user(client, username, email, password):
    t = _admin_token(client)
    client.post("/api/auth/users", headers={"Authorization": f"Bearer {t}"},
                json={"username": username, "email": email,
                      "password": password, "role": "analyst"})


def _issue_reset_token(username_email):
    """Read the raw token straight from the DB (email is not sent in tests)."""
    from app.db import session_scope
    from app.db.models import PasswordResetToken, User
    from app.auth import service
    with session_scope() as db:
        user, raw = service.create_password_reset(db, username_email)
        return raw


def test_request_always_returns_202_regardless_of_account(client):
    r1 = client.post("/api/auth/password-reset/request",
                     json={"email": "nobody@example.com"})
    r2 = client.post("/api/auth/password-reset/request",
                     json={"email": "admin@example.com"})
    assert r1.status_code == 202 and r2.status_code == 202
    assert r1.json() == r2.json()          # identical body -> no enumeration


def test_full_reset_cycle_changes_the_password(client):
    _make_user(client, "dana", "dana@example.com", "originalpw1")
    raw = _issue_reset_token("dana@example.com")

    bad = client.post("/api/auth/login",
                      json={"username": "dana", "password": "brandnewpw2"})
    assert bad.status_code == 401

    r = client.post("/api/auth/password-reset/confirm",
                    json={"token": raw, "new_password": "brandnewpw2"})
    assert r.status_code == 200

    assert client.post("/api/auth/login",
                       json={"username": "dana", "password": "originalpw1"}
                       ).status_code == 401
    assert client.post("/api/auth/login",
                       json={"username": "dana", "password": "brandnewpw2"}
                       ).status_code == 200


def test_reset_token_is_single_use(client):
    _make_user(client, "erin", "erin@example.com", "originalpw1")
    raw = _issue_reset_token("erin@example.com")
    assert client.post("/api/auth/password-reset/confirm",
                       json={"token": raw, "new_password": "secondpw22"}
                       ).status_code == 200
    again = client.post("/api/auth/password-reset/confirm",
                        json={"token": raw, "new_password": "thirdpw333"})
    assert again.status_code == 400


def test_confirm_rejects_garbage_token(client):
    r = client.post("/api/auth/password-reset/confirm",
                    json={"token": "not-a-real-token", "new_password": "whatever12"})
    assert r.status_code == 400


def test_reset_revokes_existing_sessions(client):
    _make_user(client, "finn", "finn@example.com", "originalpw1")
    login = client.post("/api/auth/login",
                        json={"username": "finn", "password": "originalpw1"}).json()

    raw = _issue_reset_token("finn@example.com")
    client.post("/api/auth/password-reset/confirm",
                json={"token": raw, "new_password": "afterresetpw9"})

    # the refresh token issued before the reset must no longer work
    r = client.post("/api/auth/refresh",
                    json={"refresh_token": login["refresh_token"]})
    assert r.status_code == 401
