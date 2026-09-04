"""Translate the pipeline's dataclasses into ORM rows.

Pure functions - they build an unattached ``Base`` instance and never touch a
session. The detection code keeps working with the dataclasses in
:mod:`app.models`; only :mod:`app.db.persist` calls these, at the API edge.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any, Optional

from app.db.models import (
    AttackPath as AttackPathRow,
    Behavior as BehaviorRow,
    Event as EventRow,
    Response as ResponseRow,
)
from app.models.attack_graph import AttackPath
from app.models.behavior import Behavior
from app.models.response import ResponseResult
from app.models.security_event import SecurityEvent


def _aware(value: Optional[_dt.datetime]) -> Optional[_dt.datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=_dt.timezone.utc)


def event_to_row(event: SecurityEvent) -> EventRow:
    return EventRow(
        timestamp=_aware(event.timestamp) or _dt.datetime.now(_dt.timezone.utc),
        source_ip=event.ip_address,
        event_type=event.event_type,
        user=event.user,
        details={
            "source": event.source,
            "host": event.host,
            "process": event.process,
            "description": event.description,
            **(event.metadata or {}),
        },
        raw_log=event.raw_log,
        attack_id=event.ip_address,   # the graph keys attackers by address
    )


def behavior_to_row(behavior: Behavior) -> BehaviorRow:
    return BehaviorRow(
        event_ids=[e.id for e in behavior.evidence],
        behavior_type=behavior.rule or behavior.name,
        risk_score=int(behavior.risk_score),
        confidence=float(behavior.confidence),
        mitre_techniques=list(behavior.technique_ids),
        kill_chain_stage=behavior.stage_name,
        evidence=[
            {
                "id": e.id,
                "timestamp": str(e.timestamp),
                "event_type": e.event_type,
                "user": e.user,
                "ip_address": e.ip_address,
                "description": e.description,
            }
            for e in behavior.evidence
        ],
        resolved=False,
    )


def attack_path_to_row(path: AttackPath) -> AttackPathRow:
    return AttackPathRow(
        attacker_ip=path.actor,
        behavior_ids=[node.behavior.id for node in path.nodes],
        path_type="internal" if len(path.nodes) > 1 else "external",
        stages=[
            {"stage": node.stage, "stage_name": node.stage_name,
             "behavior": node.behavior.id}
            for node in path.nodes
        ],
        compromised=bool(path.succeeded),
    )


def response_to_row(result: ResponseResult, *, attacker_ip: str) -> ResponseRow:
    return ResponseRow(
        attacker_ip=attacker_ip,
        action_type=result.action,
        command=result.command,
        status=result.status,
        executed_at=_aware(result.at),
        result={
            "armed": result.armed,
            "detail": result.detail,
            "retryable": result.retryable,
            "target": result.target,
        },
    )
