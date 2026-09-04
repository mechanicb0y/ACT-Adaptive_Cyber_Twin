"""Write pipeline output into the durable store - best effort, never fatal.

The engine stays in memory and authoritative. This module mirrors its current
state into the database so other tools (SQL, Grafana, a future UI) can read it
and so history survives a restart. Every entry point swallows its own errors:
a database problem must never break an API response or the pipeline.

Events are append-only and mirrored incrementally. Behaviours and attack paths
are *derived* - they are recomputed every cycle - so they are cleared and
rewritten atomically each time.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable, Optional

from sqlalchemy import delete, func, select

from app.core import metrics
from app.core.settings import get_settings
from app.db import mappers
from app.db.models import AttackPath as AttackPathRow
from app.db.models import Behavior as BehaviorRow
from app.db.models import Event as EventRow
from app.db.models import Report as ReportRow
from app.db.models import Alert as AlertRow
from app.db.models import Response as ResponseRow
from app.db.session import session_scope

log = logging.getLogger("app.db.persist")


def enabled() -> bool:
    return get_settings().persist_enabled


# ------------------------------------------------------------------- events #


def _mirror_events(session, events: list) -> int:
    persisted = session.scalar(select(func.count()).select_from(EventRow)) or 0
    if persisted >= len(events):
        return 0
    new = events[persisted:]
    session.add_all(mappers.event_to_row(e) for e in new)
    return len(new)


# --------------------------------------------------------------- derived data #


def _rewrite_analysis(session, behaviors: list, paths: Iterable) -> tuple[int, int, int]:
    before = session.scalar(select(func.count()).select_from(BehaviorRow)) or 0

    session.execute(delete(BehaviorRow))
    session.execute(delete(AttackPathRow))

    session.add_all(mappers.behavior_to_row(b) for b in behaviors)
    path_list = list(paths)
    session.add_all(mappers.attack_path_to_row(p) for p in path_list)

    new_attacks = max(0, len(behaviors) - before)
    return len(behaviors), len(path_list), new_attacks


# --------------------------------------------------------------- public API #


def persist_snapshot(
    engine: Any,
    *,
    behaviors: Optional[list] = None,
    graph: Optional[Any] = None,
) -> Optional[dict]:
    """Mirror events + current behaviours/paths. Returns a summary or ``None``."""
    if not enabled():
        return None
    try:
        events = engine.store.all()
        behaviors = engine.behaviors() if behaviors is None else behaviors
        graph = engine.attack_graph() if graph is None else graph

        with session_scope() as session:
            new_events = _mirror_events(session, events)
            n_beh, n_paths, new_attacks = _rewrite_analysis(
                session, behaviors, graph.paths
            )

        if new_attacks:
            metrics.record_attacks(new_attacks)
        return {
            "events_persisted": new_events,
            "behaviors": n_beh,
            "attack_paths": n_paths,
            "new_attacks": new_attacks,
        }
    except Exception:  # noqa: BLE001
        log.warning("persist_snapshot failed; continuing in-memory only",
                    exc_info=True)
        return None


def persist_response(result: Any, *, attacker_ip: str) -> None:
    if not enabled() or result is None:
        return
    try:
        with session_scope() as session:
            session.add(mappers.response_to_row(result, attacker_ip=attacker_ip))
    except Exception:  # noqa: BLE001
        log.warning("persist_response failed", exc_info=True)


def persist_alert(
    *, platform: str, ok: bool, detail: Optional[dict] = None,
    behavior_id: Optional[int] = None,
) -> None:
    if not enabled():
        return
    try:
        with session_scope() as session:
            session.add(AlertRow(
                behavior_id=behavior_id,
                platform=platform,
                status="sent" if ok else "failed",
                sent_at=func.now() if ok else None,
                detail=detail or {},
            ))
    except Exception:  # noqa: BLE001
        log.warning("persist_alert failed", exc_info=True)


def persist_report(*, attack_id: str, fmt: str, report_data: dict) -> None:
    if not enabled():
        return
    try:
        with session_scope() as session:
            session.add(ReportRow(
                attack_id=attack_id, format=fmt, report_data=report_data,
            ))
    except Exception:  # noqa: BLE001
        log.warning("persist_report failed", exc_info=True)


def clear_all() -> None:
    """Wipe mirrored pipeline data (called when the engine is reset)."""
    if not enabled():
        return
    try:
        with session_scope() as session:
            for table in (EventRow, BehaviorRow, AttackPathRow, ResponseRow):
                session.execute(delete(table))
    except Exception:  # noqa: BLE001
        log.warning("clear_all failed", exc_info=True)
