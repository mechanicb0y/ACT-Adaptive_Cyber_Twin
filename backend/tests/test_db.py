"""Phase 1 persistence layer: models, session handling, retry, health probe.

These tests run entirely on an in-memory SQLite database (the ``db_session``
fixture). They do not touch the pipeline and keep the suite hermetic.
"""

import datetime as _dt

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.settings import Settings, reload_settings
from app.db import check_connection, init_db, reset_engine, session_scope
from app.db.models import (
    Alert,
    AttackPath,
    AuditLog,
    Behavior,
    Config,
    Event,
    RefreshToken,
    Report,
    Response,
    Role,
    User,
)
from app.db.repository import config_all, config_get, config_set, record_audit


# ------------------------------------------------------------------ models #


def test_every_model_round_trips(db_session):
    db_session.add_all(
        [
            User(username="alice", email="a@example.com", hashed_password="x",
                 role=Role.admin.value),
            Event(event_type="ssh_failed_login", source_ip="10.0.0.9", user="root",
                  details={"port": 22}, raw_log="..."),
            Behavior(behavior_type="brute-force", risk_score=80, confidence=0.9,
                     event_ids=[1, 2, 3], mitre_techniques=["T1110"],
                     kill_chain_stage="exploitation", evidence=[{"k": "v"}]),
            AttackPath(attacker_ip="10.0.0.9", behavior_ids=[1], path_type="external",
                       stages=["recon", "exploit"], compromised=True),
            Response(attacker_ip="10.0.0.9", action_type="iptables_block",
                     command="iptables -A INPUT -s 10.0.0.9 -j DROP", status="done",
                     result={"rc": 0}),
            Report(attack_id="10.0.0.9", report_data={"summary": "s"}, format="html"),
            Config(key="notifications.enabled", value=True),
        ]
    )
    db_session.flush()

    assert db_session.scalar(select(User).where(User.username == "alice")).role == "admin"
    assert db_session.scalar(select(Event)).details["port"] == 22
    assert db_session.scalar(select(Behavior)).mitre_techniques == ["T1110"]
    assert db_session.scalar(select(AttackPath)).compromised is True
    assert db_session.scalar(select(Response)).result["rc"] == 0
    assert db_session.scalar(select(Report)).report_data["summary"] == "s"
    assert db_session.scalar(select(Config)).value is True


def test_defaults_are_applied(db_session):
    user = User(username="bob")
    db_session.add(user)
    db_session.flush()

    assert user.role == Role.viewer.value
    assert user.is_active is True
    assert isinstance(user.created_at, _dt.datetime)
    assert user.last_login is None


def test_username_unique_constraint(db_session):
    db_session.add(User(username="dup"))
    db_session.flush()
    db_session.add(User(username="dup"))
    with pytest.raises(IntegrityError):
        db_session.flush()


def test_alert_behavior_fk_set_null_on_delete(db_session):
    behavior = Behavior(behavior_type="persistence", risk_score=50, confidence=0.5)
    db_session.add(behavior)
    db_session.flush()

    alert = Alert(behavior_id=behavior.id, platform="telegram", status="sent")
    db_session.add(alert)
    db_session.flush()

    db_session.delete(behavior)
    db_session.flush()
    db_session.refresh(alert)
    assert alert.behavior_id is None  # ondelete=SET NULL, FK pragma is on


def test_refresh_token_cascade_on_user_delete(db_session):
    user = User(username="carol")
    db_session.add(user)
    db_session.flush()
    db_session.add(
        RefreshToken(
            user_id=user.id,
            token_hash="deadbeef",
            expires_at=_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1),
        )
    )
    db_session.flush()
    db_session.delete(user)
    db_session.flush()
    assert db_session.scalar(select(RefreshToken)) is None


# -------------------------------------------------------------- repository #


def test_config_get_set_roundtrip(db_session):
    assert config_get(db_session, "missing", default="fallback") == "fallback"
    config_set(db_session, "graph.max_gap_seconds", 120)
    config_set(db_session, "graph.max_gap_seconds", 300)  # update path
    db_session.flush()
    assert config_get(db_session, "graph.max_gap_seconds") == 300
    assert config_all(db_session) == {"graph.max_gap_seconds": 300}


def test_record_audit_appends_row(db_session):
    record_audit(db_session, action="login", actor="alice", source_ip="1.2.3.4",
                 detail={"remember_me": True})
    db_session.flush()
    row = db_session.scalar(select(AuditLog))
    assert row.action == "login"
    assert row.actor == "alice"
    assert row.detail["remember_me"] is True


# ------------------------------------------------- session / engine plumbing #


def test_session_scope_rolls_back_on_error(db_session):
    from app.db import session_scope as scope

    with pytest.raises(RuntimeError):
        with scope() as s:
            s.add(User(username="ghost"))
            s.flush()
            raise RuntimeError("boom")

    with scope() as s:
        assert s.scalar(select(User).where(User.username == "ghost")) is None


def test_check_connection_reports_healthy(db_session):
    health = check_connection()
    assert health["connected"] is True
    assert health["dialect"] == "sqlite"
    assert health["error"] is None


def test_check_connection_reports_failure_for_bad_url(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://x:y@127.0.0.1:1/none")
    monkeypatch.setenv("ACT_DB_CONNECT_RETRIES", "1")
    reload_settings()
    reset_engine()
    try:
        health = check_connection()
        assert health["connected"] is False
        assert health["error"]
    finally:
        reset_engine()
        reload_settings()


# --------------------------------------------------------------- settings #


def test_settings_sqlite_by_default(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    s = Settings()
    assert s.is_sqlite
    assert s.database_url.startswith("sqlite:///")


def test_settings_redacts_postgres_password(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://act:s3cret@db:5432/act")
    s = Settings()
    assert "s3cret" not in s.redacted()["database_url"]
    assert "act:***@db" in s.redacted()["database_url"]
