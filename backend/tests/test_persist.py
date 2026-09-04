"""Phase 3: mirroring pipeline output into the database (best effort)."""

from __future__ import annotations

import datetime as _dt
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from app.db import persist
from app.db.models import (
    AttackPath as AttackPathRow,
    Behavior as BehaviorRow,
    Event as EventRow,
    Response as ResponseRow,
)
from app.models.attack_graph import AttackGraph, AttackNode, AttackPath
from app.models.behavior import Behavior
from app.models.response import ResponseResult, ResponseStatus
from app.models.security_event import SecurityEvent


def _event(eid, ip="10.0.0.9"):
    return SecurityEvent(
        id=eid, timestamp=_dt.datetime(2026, 9, 1, 4, 0, 0), source="Linux",
        host="h", event_type="ssh_failed_login", description="d",
        user="root", ip_address=ip,
    )


def _behavior(bid, evidence):
    return Behavior(id=bid, name="Brute force", description="",
                    severity="High", confidence=0.9, rule="brute-force",
                    risk_score=80, stage=3, stage_name="Exploitation",
                    evidence=evidence,
                    attributes={"ip_address": "10.0.0.9"})


class FakeEngine:
    def __init__(self, events, behaviors, paths):
        self.store = SimpleNamespace(all=lambda: events)
        self._behaviors = behaviors
        self._graph = AttackGraph(paths=paths)

    def behaviors(self, **_):
        return self._behaviors

    def attack_graph(self):
        return self._graph


@pytest.fixture(autouse=True)
def _persist_on(monkeypatch):
    monkeypatch.setenv("ACT_PERSIST_ENABLED", "true")
    from app.core.settings import reload_settings
    reload_settings()


def test_persist_snapshot_writes_events_behaviors_paths(db_session):
    events = [_event("e1"), _event("e2"), _event("e3")]
    behaviors = [_behavior("b1", events[:2])]
    path = AttackPath(nodes=[AttackNode(id="n1", behavior=behaviors[0])])
    engine = FakeEngine(events, behaviors, [path])

    summary = persist.persist_snapshot(engine)
    assert summary["events_persisted"] == 3
    assert summary["behaviors"] == 1
    assert summary["attack_paths"] == 1

    assert db_session.scalar(select(func.count()).select_from(EventRow)) == 3
    assert db_session.scalar(select(func.count()).select_from(BehaviorRow)) == 1
    assert db_session.scalar(select(func.count()).select_from(AttackPathRow)) == 1


def test_persist_snapshot_is_incremental_for_events_and_rewrites_derived(db_session):
    events = [_event("e1"), _event("e2")]
    engine = FakeEngine(events, [_behavior("b1", events)], [])
    persist.persist_snapshot(engine)

    events.append(_event("e3"))
    engine._behaviors = [_behavior("b1", events), _behavior("b2", events)]
    second = persist.persist_snapshot(engine)

    assert second["events_persisted"] == 1                    # only the new one
    assert db_session.scalar(select(func.count()).select_from(EventRow)) == 3
    assert db_session.scalar(select(func.count()).select_from(BehaviorRow)) == 2


def test_persist_response_row(db_session):
    result = ResponseResult(action="block", target="10.0.0.9",
                            status=ResponseStatus.EXECUTED, armed=True,
                            command="iptables ...", at=_dt.datetime.now())
    persist.persist_response(result, attacker_ip="10.0.0.9")
    row = db_session.scalar(select(ResponseRow))
    assert row.attacker_ip == "10.0.0.9" and row.status == "executed"


def test_clear_all_wipes_mirrored_data(db_session):
    events = [_event("e1")]
    persist.persist_snapshot(FakeEngine(events, [_behavior("b1", events)], []))
    persist.clear_all()
    assert db_session.scalar(select(func.count()).select_from(EventRow)) == 0
    assert db_session.scalar(select(func.count()).select_from(BehaviorRow)) == 0


def test_persist_is_a_noop_when_disabled(db_session, monkeypatch):
    monkeypatch.setenv("ACT_PERSIST_ENABLED", "false")
    from app.core.settings import reload_settings
    reload_settings()

    events = [_event("e1")]
    out = persist.persist_snapshot(FakeEngine(events, [_behavior("b1", events)], []))
    assert out is None
    assert db_session.scalar(select(func.count()).select_from(EventRow)) == 0


def test_persist_snapshot_swallows_db_errors(monkeypatch):
    # point the engine at a broken DB URL; persist must not raise
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://x:y@127.0.0.1:1/none")
    monkeypatch.setenv("ACT_DB_CONNECT_RETRIES", "1")
    from app.core.settings import reload_settings
    from app.db import reset_engine
    reload_settings()
    reset_engine()
    try:
        events = [_event("e1")]
        out = persist.persist_snapshot(FakeEngine(events, [_behavior("b1", events)], []))
        assert out is None            # logged and swallowed
    finally:
        reset_engine()
        reload_settings()
