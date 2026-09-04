"""The engine-backed API routes.

Ported verbatim from the old flat ``main.py`` - each handler still just reads the
query, calls :class:`AnalysisEngine`, and serialises. Two things are new:

* the engine arrives as a dependency (:func:`app.api.deps.get_engine`) instead of
  a module global, so this module does not import ``main``;
* mutating routes mirror the result into the database via
  :mod:`app.db.persist` (best effort - a DB error is logged, never raised).
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from app.api.deps import get_engine
from app.api.engine import AnalysisEngine
from app.api.serializers import (
    assessments_to_list,
    behaviors_to_list,
    events_to_list,
    response_to_dict,
)
from app.auth.dependencies import CurrentUser, require_admin, require_analyst
from app.core import metrics
from app.db import persist
from app.db.repository import record_audit
from app.db.session import get_db

log = logging.getLogger("app.api.v1")

router = APIRouter()


def _client_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


def _audit(db: Session, request: Request, actor: CurrentUser, action: str,
           **detail) -> None:
    try:
        record_audit(db, action=action, actor=actor.username,
                     source_ip=_client_ip(request), detail=detail or {})
        db.commit()
    except Exception:  # noqa: BLE001  (auditing must never break the action)
        log.warning("audit write failed for %s", action, exc_info=True)
        db.rollback()


# ------------------------------------------------------------------ events #


@router.get("/events", tags=["events"])
def get_events(
    user: Optional[str] = None,
    ip: Optional[str] = None,
    type: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=0, le=5000),
    offset: int = Query(0, ge=0),
    engine: AnalysisEngine = Depends(get_engine),
):
    events, total = engine.events(
        user=user, ip_address=ip, event_type=type, search=search,
        limit=limit, offset=offset,
    )
    return {
        "total": total,
        "count": len(events),
        "offset": offset,
        "events": events_to_list(events),
    }


# --------------------------------------------------------------- behaviors #


@router.get("/behaviors", tags=["behaviors"])
def get_behaviors(
    min_risk: int = Query(0, ge=0, le=100),
    rule: Optional[str] = None,
    severity: Optional[str] = None,
    evidence: int = Query(20, ge=0, le=500),
    engine: AnalysisEngine = Depends(get_engine),
):
    behaviors = engine.behaviors(min_risk=min_risk, rule=rule, severity=severity)
    return {
        "count": len(behaviors),
        "behaviors": behaviors_to_list(behaviors, evidence_limit=evidence),
    }


@router.get("/behaviors/{behavior_id}", tags=["behaviors"])
def get_behavior(behavior_id: str, engine: AnalysisEngine = Depends(get_engine)):
    for behavior in engine.behaviors():
        if behavior.id == behavior_id:
            return behaviors_to_list([behavior], evidence_limit=0)[0]
    raise HTTPException(status_code=404, detail="Behavior not found")


# ------------------------------------------------------------ attack graph #


@router.get("/attack-graph", tags=["attack graph"])
def get_attack_graph(engine: AnalysisEngine = Depends(get_engine)):
    return engine.attack_graph().to_dict()


# ------------------------------------------------------ the AI layer / twin #


@router.get("/intelligence", tags=["intelligence"])
def get_intelligence(engine: AnalysisEngine = Depends(get_engine)):
    """Prediction, decision, response and narrative for every attacker."""
    assessments = assessments_to_list(engine.assessments())   # triggers the refresh
    data = engine.response_mode()
    data["assessments"] = assessments
    persist.persist_snapshot(engine)
    return data


@router.post("/arm", tags=["intelligence"])
def arm(request: Request, account_lock: bool = False,
        user: CurrentUser = Depends(require_admin),
        engine: AnalysisEngine = Depends(get_engine),
        db: Session = Depends(get_db)):
    """Point ACT's responder at the known SSH machine (normally automatic)."""
    result = engine.arm(allow_account_lock=account_lock)
    _audit(db, request, user, "responder.arm", account_lock=account_lock)
    return result


@router.post("/disarm", tags=["intelligence"])
def disarm(request: Request, user: CurrentUser = Depends(require_admin),
           engine: AnalysisEngine = Depends(get_engine),
           db: Session = Depends(get_db)):
    """Emergency stand-down: forget the SSH target so nothing executes."""
    result = engine.disarm()
    _audit(db, request, user, "responder.disarm")
    return result


@router.post("/respond", tags=["intelligence"])
def respond(
    request: Request,
    actor: str = Query(..., description="the attacker's address"),
    user: CurrentUser = Depends(require_admin),
    engine: AnalysisEngine = Depends(get_engine),
    db: Session = Depends(get_db),
):
    """Carry out the recommended action for one attacker (executes only if armed)."""
    result = engine.respond(actor)
    if result is None:
        raise HTTPException(status_code=404, detail="No attack path for that actor")

    metrics.record_response(result.action, result.status)
    if result.action in ("block", "iptables_block"):
        metrics.record_block(result.took_effect)
    persist.persist_response(result, attacker_ip=actor)
    _audit(db, request, user, "responder.respond", target=actor,
           action_taken=result.action, status=result.status, armed=result.armed)
    return response_to_dict(result)


# ----------------------------------------------------------------- reports #


@router.get("/report/{actor}", tags=["reports"])
def get_report(
    actor: str,
    format: str = Query("html", pattern="^(html|pdf)$"),
    engine: AnalysisEngine = Depends(get_engine),
):
    """Analyst-ready incident report for one attacker (html preview or pdf)."""
    built = engine.report(actor, fmt=format)
    if built is None:
        raise HTTPException(status_code=404, detail="No attack path for that actor")

    content, media_type, filename = built
    disposition = "attachment" if format == "pdf" else "inline"
    persist.persist_report(attack_id=actor, fmt=format,
                           report_data={"filename": filename, "bytes": len(content)})
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'{disposition}; filename="{filename}"'},
    )


# ---------------------------------------------------------- notifications #


@router.get("/notifications", tags=["notifications"])
def notifications_status(engine: AnalysisEngine = Depends(get_engine)):
    return engine.notifier.status()


@router.post("/notifications/config", tags=["notifications"])
def notifications_config(
    enabled: Optional[bool] = None,
    risk_threshold: Optional[int] = Query(None, ge=0, le=100),
    _role=Depends(require_analyst),
    engine: AnalysisEngine = Depends(get_engine),
):
    return engine.notifier.configure(enabled=enabled, risk_threshold=risk_threshold)


@router.post("/notifications/test", tags=["notifications"])
def notifications_test(_role=Depends(require_analyst),
                       engine: AnalysisEngine = Depends(get_engine)):
    if not engine.notifier.configured:
        raise HTTPException(
            status_code=400,
            detail=("Telegram is not configured. Set TELEGRAM_BOT_TOKEN and "
                    "TELEGRAM_CHAT_ID in backend/.env."),
        )
    results = engine.notifier.send_text(
        "✅ *ACT test alert* — Telegram notifications are wired up correctly."
    )
    for entry in results or []:
        metrics.record_alert(entry.get("transport", "telegram"),
                             bool(entry.get("ok")))
        persist.persist_alert(platform=entry.get("transport", "telegram"),
                              ok=bool(entry.get("ok")), detail={"test": True})
    return {"results": results}


# ------------------------------------------------------------------- stats #


@router.get("/stats", tags=["system"])
def get_stats(engine: AnalysisEngine = Depends(get_engine)):
    return engine.stats()


@router.get("/logs", tags=["system"])
def get_sample_logs(engine: AnalysisEngine = Depends(get_engine)):
    return {"logs": engine.available_logs()}


# ----------------------------------------------------------------- ingest #


def _ingest_result(stats) -> dict:
    return {
        "lines_read": stats.lines_read,
        "events_created": stats.events_created,
        "lines_unmatched": stats.lines_unmatched,
        "parse_errors": getattr(stats, "parse_errors", None),
        "coverage": stats.coverage,
    }


@router.post("/ingest/file", tags=["ingest"])
def ingest_file(
    request: Request,
    path: str = Query(..., description="log file name or full path"),
    user: CurrentUser = Depends(require_analyst),
    engine: AnalysisEngine = Depends(get_engine),
    db: Session = Depends(get_db),
):
    try:
        stats = engine.ingest_file(path)
    except FileNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error))
    persist.persist_snapshot(engine)
    _audit(db, request, user, "ingest.file", path=path,
           events_created=stats.events_created)
    return _ingest_result(stats)


@router.post("/ingest/journal", tags=["ingest"])
def ingest_journal(
    since: str = "-24h",
    unit: Optional[List[str]] = Query(None),
    _role=Depends(require_analyst),
    engine: AnalysisEngine = Depends(get_engine),
):
    try:
        stats = engine.ingest_journal(since=since, units=unit)
    except RuntimeError as error:
        raise HTTPException(status_code=400, detail=str(error))
    persist.persist_snapshot(engine)
    return {
        "lines_read": stats.lines_read,
        "events_created": stats.events_created,
        "coverage": stats.coverage,
    }


@router.post("/ingest/ssh", tags=["ingest"])
def ingest_ssh(
    host: str = Query(..., description="address of the machine to read"),
    user: Optional[str] = Query("kali"),
    port: int = 22,
    key_file: Optional[str] = None,
    since: str = "-24h",
    sudo: bool = False,
    unit: Optional[List[str]] = Query(None),
    _role=Depends(require_analyst),
    engine: AnalysisEngine = Depends(get_engine),
):
    """Read the systemd journal of another machine, for example the Kali VM."""
    try:
        stats = engine.ingest_ssh(
            host=host, user=user, port=port, key_file=key_file,
            since=since, units=unit, use_sudo=sudo,
        )
    except RuntimeError as error:
        raise HTTPException(status_code=400, detail=str(error))
    persist.persist_snapshot(engine)
    return {
        "lines_read": stats.lines_read,
        "events_created": stats.events_created,
        "lines_unmatched": stats.lines_unmatched,
        "coverage": stats.coverage,
    }


@router.post("/ssh/test", tags=["ingest"])
def test_ssh(
    host: str = Query(...),
    user: Optional[str] = Query("kali"),
    port: int = 22,
    key_file: Optional[str] = None,
    sudo: bool = False,
    _role=Depends(require_analyst),
    engine: AnalysisEngine = Depends(get_engine),
):
    return engine.check_ssh(
        host=host, user=user, port=port, key_file=key_file, use_sudo=sudo
    )


@router.post("/live/start", tags=["ingest"])
def start_live(
    file: Optional[str] = None,
    since: str = "-5m",
    unit: Optional[List[str]] = Query(None),
    host: Optional[str] = None,
    user: Optional[str] = None,
    port: int = 22,
    key_file: Optional[str] = None,
    sudo: bool = False,
    _role=Depends(require_analyst),
    engine: AnalysisEngine = Depends(get_engine),
):
    started = engine.start_live(
        file=file, since=since, units=unit,
        host=host, user=user, port=port, key_file=key_file, use_sudo=sudo,
    )
    return {"started": started, "source": engine.live_source,
            "error": engine.live_error}


@router.post("/live/stop", tags=["ingest"])
def stop_live(_role=Depends(require_analyst),
              engine: AnalysisEngine = Depends(get_engine)):
    return {"stopped": engine.stop_live()}


@router.post("/reset", tags=["system"])
def reset(request: Request, user: CurrentUser = Depends(require_analyst),
          engine: AnalysisEngine = Depends(get_engine),
          db: Session = Depends(get_db)):
    engine.reset()
    persist.clear_all()
    _audit(db, request, user, "engine.reset")
    return {"status": "cleared"}
