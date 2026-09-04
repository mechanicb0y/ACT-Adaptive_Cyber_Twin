"""Phase 2: authentication, JWT sessions, refresh-token rotation and RBAC.

Runs the real FastAPI app through a TestClient with ``ACT_AUTH_ENABLED=true`` and
a fresh temp-file SQLite database per test. The app's lifespan bootstraps the
first admin from ``ACT_ADMIN_PASSWORD``.
"""

from __future__ import annotations

import datetime as _dt

import pytest
from fastapi.testclient import TestClient

ADMIN_USER = "admin"
ADMIN_PASS = "bootstrap-admin-pw-123"


@pytest.fixture
def client(monkeypatch, tmp_path):
    from app.core.settings import reload_settings
    from app.db import reset_engine

    db_path = tmp_path / "auth_test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("ACT_AUTH_ENABLED", "true")
    monkeypatch.setenv("ACT_JWT_SECRET", "unit-test-secret-0123456789-abcdefghij")
    monkeypatch.setenv("ACT_ADMIN_USERNAME", ADMIN_USER)
    monkeypatch.setenv("ACT_ADMIN_PASSWORD", ADMIN_PASS)
    monkeypatch.setenv("ACT_ACCESS_TOKEN_TTL_MIN", "30")
    reload_settings()
    reset_engine()

    from app.api.main import app

    with TestClient(app) as c:
        yield c

    reset_engine()
    reload_settings()


def _login(client, username=ADMIN_USER, password=ADMIN_PASS, remember_me=False):
    return client.post("/api/auth/login", json={
        "username": username, "password": password, "remember_me": remember_me,
    })


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def as_admin(client):
    return _login(client).json()["access_token"]


# ------------------------------------------------------------------- login #


def test_login_succeeds_and_returns_tokens(client):
    r = _login(client)
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["role"] == "admin"
    assert body["username"] == ADMIN_USER
    assert body["access_token"] and body["refresh_token"]
    assert body["expires_in"] == 30 * 60


def test_login_rejects_bad_password(client):
    r = _login(client, password="wrong")
    assert r.status_code == 401
    assert r.json()["detail"] == "invalid username or password"


def test_login_rejects_unknown_user(client):
    r = _login(client, username="nobody", password="whatever")
    assert r.status_code == 401


# --------------------------------------------------------- protected routes #


def test_protected_route_needs_a_token(client):
    r = client.get("/api/stats")
    assert r.status_code == 401
    assert r.headers.get("WWW-Authenticate") == "Bearer"


def test_protected_route_accepts_a_valid_token(client):
    token = as_admin(client)
    r = client.get("/api/stats", headers=_bearer(token))
    assert r.status_code == 200


def test_garbage_token_is_rejected(client):
    r = client.get("/api/stats", headers=_bearer("not.a.jwt"))
    assert r.status_code == 401
    assert "invalid token" in r.json()["detail"]


def test_open_routes_need_no_token(client):
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/auth/providers").status_code == 200
    assert client.get("/docs").status_code == 200
    assert client.get("/login").status_code == 200


def test_health_reports_auth_and_database(client):
    body = client.get("/api/health").json()
    assert body["auth_enabled"] is True
    assert body["database"]["connected"] is True


# --------------------------------------------------------------- /api/auth/me #


def test_me_returns_the_current_user(client):
    token = as_admin(client)
    r = client.get("/api/auth/me", headers=_bearer(token))
    assert r.status_code == 200
    assert r.json()["username"] == ADMIN_USER
    assert r.json()["role"] == "admin"


# -------------------------------------------------------- refresh + rotation #


def test_refresh_issues_a_new_pair_and_rotates(client):
    first = _login(client).json()
    r = client.post("/api/auth/refresh",
                    json={"refresh_token": first["refresh_token"]})
    assert r.status_code == 200
    second = r.json()
    assert second["access_token"] != first["access_token"]
    assert second["refresh_token"] != first["refresh_token"]


def test_old_refresh_token_is_dead_after_rotation_and_revokes_chain(client):
    first = _login(client).json()
    client.post("/api/auth/refresh", json={"refresh_token": first["refresh_token"]})

    reuse = client.post("/api/auth/refresh",
                        json={"refresh_token": first["refresh_token"]})
    assert reuse.status_code == 401
    assert "all sessions revoked" in reuse.json()["detail"]


def test_logout_kills_the_refresh_token(client):
    tok = _login(client).json()
    assert client.post("/api/auth/logout",
                       json={"refresh_token": tok["refresh_token"]}).status_code == 200
    again = client.post("/api/auth/refresh",
                        json={"refresh_token": tok["refresh_token"]})
    assert again.status_code == 401


def test_remember_me_extends_refresh_lifetime(client):
    from app.core.settings import get_settings
    from app.db import session_scope
    from app.db.models import RefreshToken

    _login(client, remember_me=True)
    s = get_settings()
    with session_scope() as db:
        row = db.query(RefreshToken).order_by(RefreshToken.id.desc()).first()
        lifetime = row.expires_at.replace(tzinfo=_dt.timezone.utc) - row.issued_at.replace(
            tzinfo=_dt.timezone.utc
        )
    assert lifetime > _dt.timedelta(days=s.refresh_token_ttl_days + 1)


# ------------------------------------------------------------------- RBAC #


def test_rbac_viewer_cannot_ingest_or_administer(client):
    admin = as_admin(client)
    client.post("/api/auth/users", headers=_bearer(admin), json={
        "username": "val", "password": "viewerpass1", "role": "viewer",
    })
    viewer = _login(client, "val", "viewerpass1").json()["access_token"]

    assert client.get("/api/stats", headers=_bearer(viewer)).status_code == 200
    assert client.post("/api/ingest/file?path=x.log",
                       headers=_bearer(viewer)).status_code == 403
    assert client.post("/api/arm", headers=_bearer(viewer)).status_code == 403
    assert client.get("/api/auth/users", headers=_bearer(viewer)).status_code == 403


def test_rbac_analyst_can_ingest_but_not_arm_or_administer(client):
    admin = as_admin(client)
    client.post("/api/auth/users", headers=_bearer(admin), json={
        "username": "ana", "password": "analystpass1", "role": "analyst",
    })
    analyst = _login(client, "ana", "analystpass1").json()["access_token"]

    # ingest reaches the engine (404 = file missing, not 403 = forbidden)
    assert client.post("/api/ingest/file?path=missing.log",
                       headers=_bearer(analyst)).status_code == 404
    assert client.post("/api/arm", headers=_bearer(analyst)).status_code == 403
    assert client.get("/api/auth/users",
                      headers=_bearer(analyst)).status_code == 403


def test_admin_can_manage_users(client):
    admin = as_admin(client)
    created = client.post("/api/auth/users", headers=_bearer(admin), json={
        "username": "bob", "password": "bobpassword1", "role": "analyst",
    })
    assert created.status_code == 201
    uid = created.json()["id"]

    listing = client.get("/api/auth/users", headers=_bearer(admin)).json()
    assert {u["username"] for u in listing} == {"admin", "bob"}

    promoted = client.patch(f"/api/auth/users/{uid}", headers=_bearer(admin),
                            json={"role": "admin"})
    assert promoted.json()["role"] == "admin"

    assert client.delete(f"/api/auth/users/{uid}",
                         headers=_bearer(admin)).status_code == 200
    assert len(client.get("/api/auth/users", headers=_bearer(admin)).json()) == 1


def test_admin_cannot_delete_or_demote_self(client):
    admin = as_admin(client)
    me = client.get("/api/auth/me", headers=_bearer(admin)).json()
    assert client.delete(f"/api/auth/users/{me['id']}",
                         headers=_bearer(admin)).status_code == 400
    assert client.patch(f"/api/auth/users/{me['id']}", headers=_bearer(admin),
                        json={"role": "viewer"}).status_code == 400


def test_duplicate_username_rejected(client):
    admin = as_admin(client)
    payload = {"username": "dup", "password": "password12", "role": "viewer"}
    assert client.post("/api/auth/users", headers=_bearer(admin),
                       json=payload).status_code == 201
    assert client.post("/api/auth/users", headers=_bearer(admin),
                       json=payload).status_code == 409


# --------------------------------------------------------- change password #


def test_change_password_then_old_password_fails(client):
    admin = as_admin(client)
    client.post("/api/auth/users", headers=_bearer(admin), json={
        "username": "carl", "password": "oldpassword1", "role": "viewer",
    })
    carl = _login(client, "carl", "oldpassword1").json()["access_token"]

    r = client.post("/api/auth/change-password", headers=_bearer(carl), json={
        "current_password": "oldpassword1", "new_password": "newpassword2",
    })
    assert r.status_code == 200
    assert _login(client, "carl", "oldpassword1").status_code == 401
    assert _login(client, "carl", "newpassword2").status_code == 200


def test_change_password_rejects_wrong_current(client):
    admin = as_admin(client)
    r = client.post("/api/auth/change-password", headers=_bearer(admin), json={
        "current_password": "nope", "new_password": "whateverlong1",
    })
    assert r.status_code == 400


# ------------------------------------------------------------------- OAuth #


def test_oauth_login_is_501_when_unconfigured(client):
    r = client.get("/api/auth/oauth/google/login", follow_redirects=False)
    assert r.status_code == 501


def test_oauth_unknown_provider_is_404(client):
    assert client.get("/api/auth/oauth/twitter/login").status_code == 404


def test_oauth_login_redirects_when_configured(client, monkeypatch):
    from app.core.settings import reload_settings
    monkeypatch.setenv("ACT_OAUTH_GITHUB_CLIENT_ID", "cid")
    monkeypatch.setenv("ACT_OAUTH_GITHUB_CLIENT_SECRET", "csecret")
    reload_settings()

    r = client.get("/api/auth/oauth/github/login", follow_redirects=False)
    assert r.status_code == 307
    assert r.headers["location"].startswith("https://github.com/login/oauth/authorize?")
    assert "client_id=cid" in r.headers["location"]


def test_oauth_handoff_is_single_use_and_never_puts_tokens_in_url(client):
    """The callback hands the SPA a one-time code via httpOnly cookie; the SPA
    trades it once at /oauth/complete."""
    from app.auth import service
    from app.db import session_scope

    with session_scope() as db:
        user = service.create_user(db, username="oauthy", password=None,
                                   email="o@example.com", role="viewer")
        db.flush()
        code = service.create_oauth_handoff(db, user_id=user.id, remember_me=False)

    client.cookies.set("act_oauth_handoff", code)
    first = client.post("/api/auth/oauth/complete")
    assert first.status_code == 200
    body = first.json()
    assert body["username"] == "oauthy" and body["access_token"]

    client.cookies.set("act_oauth_handoff", code)
    reuse = client.post("/api/auth/oauth/complete")
    assert reuse.status_code == 401


def test_oauth_complete_without_cookie_is_400(client):
    assert client.post("/api/auth/oauth/complete").status_code == 400


# ------------------------------------- OAuth account-linking safety (unit) #


def test_oauth_verified_email_provisions_new_account(db_session):
    from app.auth import service

    user = service.upsert_oauth_user(
        db_session, provider="google", subject="g-1",
        email="new@example.com", email_verified=True, username_hint="new",
    )
    assert user.email == "new@example.com"
    assert user.oauth_provider == "google" and user.hashed_password is None


def test_oauth_unverified_email_is_never_used_for_matching(db_session):
    from app.auth import service

    # a real local account owns this address
    victim = service.create_user(db_session, username="victim",
                                 password="victimpassword1",
                                 email="victim@example.com", role="admin")
    db_session.flush()

    linked = service.upsert_oauth_user(
        db_session, provider="github", subject="gh-9",
        email="victim@example.com", email_verified=False,
        username_hint="victim",
    )
    # a brand new, distinct account with no email - not the admin
    assert linked.id != victim.id
    assert linked.email is None
    assert linked.role == "viewer"
    db_session.refresh(victim)
    assert victim.oauth_provider is None


def test_oauth_verified_email_collision_with_password_account_is_refused(db_session):
    from app.auth import service
    from app.auth.service import AuthError

    service.create_user(db_session, username="realuser",
                        password="realpassword1",
                        email="real@example.com", role="analyst")
    db_session.flush()

    with pytest.raises(AuthError) as err:
        service.upsert_oauth_user(
            db_session, provider="google", subject="g-777",
            email="real@example.com", email_verified=True,
            username_hint="real",
        )
    assert err.value.status == 409


def test_oauth_verified_email_links_to_dormant_passwordless_account(db_session):
    from app.auth import service

    dormant = service.create_user(db_session, username="pending",
                                  password=None, email="pending@example.com",
                                  role="analyst")
    db_session.flush()

    linked = service.upsert_oauth_user(
        db_session, provider="github", subject="gh-42",
        email="pending@example.com", email_verified=True,
        username_hint="pending",
    )
    assert linked.id == dormant.id
    assert linked.oauth_provider == "github"
    assert linked.role == "analyst"  # unchanged


def test_oauth_returning_user_matched_by_subject_not_email(db_session):
    from app.auth import service

    first = service.upsert_oauth_user(
        db_session, provider="google", subject="stable-1",
        email="a@example.com", email_verified=True, username_hint="a",
    )
    db_session.flush()
    again = service.upsert_oauth_user(
        db_session, provider="google", subject="stable-1",
        email="a@example.com", email_verified=True, username_hint="a",
    )
    assert again.id == first.id


# ----------------------------------------------------------- websocket auth #


def test_websocket_requires_token(client):
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/stream"):
            pass


def test_websocket_accepts_valid_token(client):
    token = as_admin(client)
    with client.websocket_connect(f"/api/stream?token={token}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "connected"


# ------------------------------------------------- auth-disabled prototype #


def test_auth_disabled_lets_everything_through(monkeypatch, tmp_path):
    from app.core.settings import reload_settings
    from app.db import reset_engine

    monkeypatch.setenv("DATABASE_URL",
                       f"sqlite:///{(tmp_path / 'p.db').as_posix()}")
    monkeypatch.setenv("ACT_AUTH_ENABLED", "false")
    reload_settings()
    reset_engine()

    from app.api.main import app

    with TestClient(app) as c:
        assert c.get("/api/stats").status_code == 200
        assert c.post("/api/arm").status_code == 200
        me = c.get("/api/auth/me")
        assert me.status_code == 200 and me.json()["role"] == "admin"

    reset_engine()
    reload_settings()
