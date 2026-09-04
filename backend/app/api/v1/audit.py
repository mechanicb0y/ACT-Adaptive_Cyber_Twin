"""Read the audit trail. Admin only.

Every security-relevant action (sign-in, user change, arm/disarm, response,
reset, password reset) writes an ``audit_log`` row via
:func:`app.db.repository.record_audit`. This endpoint is the read side.
"""

from __future__ import annotations

import datetime as _dt
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser, require_admin
from app.db.models import AuditLog
from app.db.session import get_db

router = APIRouter(tags=["audit"])


@router.get("/audit")
def list_audit(
    actor: Optional[str] = None,
    action: Optional[str] = Query(None, description="exact match or 'prefix.*'"),
    since: Optional[_dt.datetime] = None,
    until: Optional[_dt.datetime] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _admin: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    filters = []
    if actor:
        filters.append(AuditLog.actor == actor)
    if action:
        if action.endswith(".*"):
            filters.append(AuditLog.action.like(action[:-1] + "%"))
        else:
            filters.append(AuditLog.action == action)
    if since:
        filters.append(AuditLog.at >= since)
    if until:
        filters.append(AuditLog.at <= until)

    total = db.scalar(
        select(func.count()).select_from(AuditLog).where(*filters)
    ) or 0
    rows = db.scalars(
        select(AuditLog).where(*filters)
        .order_by(AuditLog.at.desc(), AuditLog.id.desc())
        .limit(limit).offset(offset)
    ).all()

    return {
        "total": total,
        "count": len(rows),
        "offset": offset,
        "entries": [
            {
                "id": r.id,
                "at": r.at.isoformat() if r.at else None,
                "actor": r.actor,
                "action": r.action,
                "target": r.target,
                "source_ip": r.source_ip,
                "detail": r.detail or {},
            }
            for r in rows
        ],
    }
