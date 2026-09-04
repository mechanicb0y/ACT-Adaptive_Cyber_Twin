"""Small, dependency-free helpers over the ORM.

Only the cross-cutting bits live here in Phase 1 - runtime config key/value and
the audit trail. Domain repositories (events, behaviours, ...) arrive with the
API-versioning phase, when the pipeline output starts being persisted.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AuditLog, Config

log = logging.getLogger("app.db.repository")

_SENTINEL = object()


def config_get(session: Session, key: str, default: Any = None) -> Any:
    row = session.scalar(select(Config).where(Config.key == key))
    return row.value if row is not None else default


def config_set(session: Session, key: str, value: Any) -> Config:
    row = session.scalar(select(Config).where(Config.key == key))
    if row is None:
        row = Config(key=key, value=value)
        session.add(row)
    else:
        row.value = value
    return row


def config_all(session: Session) -> dict[str, Any]:
    return {row.key: row.value for row in session.scalars(select(Config)).all()}


def record_audit(
    session: Session,
    *,
    action: str,
    actor: Optional[str] = None,
    target: Optional[str] = None,
    source_ip: Optional[str] = None,
    detail: Optional[dict[str, Any]] = None,
) -> AuditLog:
    """Append one row to the audit trail. Caller owns the transaction."""
    entry = AuditLog(
        action=action,
        actor=actor,
        target=target,
        source_ip=source_ip,
        detail=detail or {},
    )
    session.add(entry)
    log.info(
        "audit",
        extra={"action": action, "actor": actor, "target": target,
               "source_ip": source_ip},
    )
    return entry
