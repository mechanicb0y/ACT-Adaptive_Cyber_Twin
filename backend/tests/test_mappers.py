"""Phase 3: dataclass -> ORM row mappers (pure, no database)."""

from __future__ import annotations

import datetime as _dt

from app.db import mappers
from app.models.attack_graph import AttackNode, AttackPath
from app.models.behavior import Behavior
from app.models.response import ResponseResult, ResponseStatus
from app.models.security_event import SecurityEvent


def _event(eid="e1", ip="10.0.0.5", etype="ssh_failed_login"):
    return SecurityEvent(
        id=eid,
        timestamp=_dt.datetime(2026, 9, 1, 3, 15, 0),
        source="Linux", host="web-01", event_type=etype,
        description="Failed password for root", user="root", ip_address=ip,
        metadata={"port": 22}, raw_log="raw line",
    )


def test_event_to_row_carries_the_facts():
    row = mappers.event_to_row(_event())
    assert row.event_type == "ssh_failed_login"
    assert row.source_ip == "10.0.0.5"
    assert row.user == "root"
    assert row.details["port"] == 22
    assert row.details["host"] == "web-01"
    assert row.raw_log == "raw line"
    assert row.timestamp.tzinfo is not None       # made timezone-aware


def test_behavior_to_row_flattens_evidence_and_techniques():
    b = Behavior(
        id="b1", name="Brute force", description="many failures",
        severity="High", confidence=0.9, rule="brute-force",
        risk_score=82, stage=3, stage_name="Exploitation",
        evidence=[_event("e1"), _event("e2")],
    )
    row = mappers.behavior_to_row(b)
    assert row.behavior_type == "brute-force"
    assert row.risk_score == 82
    assert row.confidence == 0.9
    assert row.kill_chain_stage == "Exploitation"
    assert row.event_ids == ["e1", "e2"]
    assert len(row.evidence) == 2 and row.evidence[0]["id"] == "e1"
    assert row.resolved is False


def test_attack_path_to_row():
    b = Behavior(id="b1", name="x", description="", severity="High",
                 confidence=0.8, rule="persistence", stage=6,
                 stage_name="Persistence",
                 attributes={"ip_address": "10.0.0.5", "compromised": True})
    path = AttackPath(nodes=[AttackNode(id="n1", behavior=b)])
    row = mappers.attack_path_to_row(path)
    assert row.attacker_ip == "10.0.0.5"
    assert row.behavior_ids == ["b1"]
    assert row.compromised is True
    assert row.stages[0]["stage_name"] == "Persistence"


def test_response_to_row():
    result = ResponseResult(
        action="block", target="10.0.0.5", status=ResponseStatus.EXECUTED,
        command="iptables -A INPUT -s 10.0.0.5 -j DROP", armed=True,
        detail="rule added", at=_dt.datetime(2026, 9, 1, 3, 20, 0),
    )
    row = mappers.response_to_row(result, attacker_ip="10.0.0.5")
    assert row.attacker_ip == "10.0.0.5"
    assert row.action_type == "block"
    assert row.status == "executed"
    assert row.result["armed"] is True
    assert row.executed_at.tzinfo is not None
