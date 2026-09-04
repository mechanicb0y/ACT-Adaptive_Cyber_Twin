#The ACT REST API.
#
#Every route here is three or four lines: read the query, call the
#AnalysisEngine, serialize. All the real work lives in app/api/engine.py, which
#has no web framework in it and is tested without starting a server.
#
#Run it with:
#    cd backend
#    python -m uvicorn app.api.main:app --reload
#
#Then open http://127.0.0.1:8000 for the dashboard
#and  http://127.0.0.1:8000/docs for the generated API documentation.

import asyncio
from pathlib import Path
from typing import List, Optional

from app.config import env as _env  # noqa: F401  (loads backend/.env on import)

from fastapi import FastAPI, HTTPException, Query, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from app.api.engine import AnalysisEngine
from app.api.serializers import (
    assessments_to_list,
    behaviors_to_list,
    events_to_list,
    response_to_dict,
)

FRONTEND_DIR = Path(__file__).resolve().parents[3] / "frontend"

app = FastAPI(
    title="ACT - Adaptive Cyber Twin",
    description="Linux security log ingestion, behavior correlation, risk scoring, MITRE ATT&CK mapping and attack graphs.",
    version="1.0.0",
)

#the dashboard may be opened straight from disk during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

#one engine for the whole process, the dashboard talks to this
engine = AnalysisEngine()


# ---------------------------------------------------------------- dashboard #


@app.get("/", include_in_schema=False)
def dashboard():

    index = FRONTEND_DIR / "index.html"

    if not index.exists():
        return JSONResponse(
            {"project": "ACT", "status": "running", "api": "/docs"}
        )

    return FileResponse(index)


@app.get("/api/health")
def health():
    return {"status": "ok", "events": len(engine.store.all())}


# ------------------------------------------------------------------ events #


@app.get("/api/events")
def get_events(
    user: Optional[str] = None,
    ip: Optional[str] = None,
    type: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=0, le=5000),
    offset: int = Query(0, ge=0),
):
    events, total = engine.events(
        user=user,
        ip_address=ip,
        event_type=type,
        search=search,
        limit=limit,
        offset=offset,
    )

    return {
        "total": total,
        "count": len(events),
        "offset": offset,
        "events": events_to_list(events),
    }


# --------------------------------------------------------------- behaviors #


@app.get("/api/behaviors")
def get_behaviors(
    min_risk: int = Query(0, ge=0, le=100),
    rule: Optional[str] = None,
    severity: Optional[str] = None,
    evidence: int = Query(20, ge=0, le=500),
):
    behaviors = engine.behaviors(min_risk=min_risk, rule=rule, severity=severity)

    return {
        "count": len(behaviors),
        "behaviors": behaviors_to_list(behaviors, evidence_limit=evidence),
    }


@app.get("/api/behaviors/{behavior_id}")
def get_behavior(behavior_id: str):

    for behavior in engine.behaviors():
        if behavior.id == behavior_id:
            return behaviors_to_list([behavior], evidence_limit=0)[0]

    raise HTTPException(status_code=404, detail="Behavior not found")


# ------------------------------------------------------------ attack graph #


@app.get("/api/attack-graph")
def get_attack_graph():
    return engine.attack_graph().to_dict()


# ------------------------------------------------------ the AI layer / twin #


@app.get("/api/intelligence")
def get_intelligence():
    """Prediction, decision, response and narrative for every attacker.

    ACT is always autonomous: once a VM is connected over SSH (``armed`` true),
    any blocking decision is executed immediately. ``ssh_target`` is the machine
    ACT will act on.
    """
    assessments = assessments_to_list(engine.assessments())   # triggers the refresh
    data = engine.response_mode()
    data["assessments"] = assessments
    return data


@app.post("/api/arm")
def arm(account_lock: bool = False):
    """Point ACT's responder at the known SSH machine (normally automatic)."""
    return engine.arm(allow_account_lock=account_lock)


@app.post("/api/disarm")
def disarm():
    """Emergency stand-down: forget the SSH target so nothing executes."""
    return engine.disarm()


@app.post("/api/respond")
def respond(actor: str = Query(..., description="the attacker's address")):
    """Carry out the recommended action for one attacker (executes only if armed)."""

    result = engine.respond(actor)

    if result is None:
        raise HTTPException(status_code=404, detail="No attack path for that actor")

    return response_to_dict(result)


# ----------------------------------------------------------------- reports #


@app.get("/api/report/{actor}")
def get_report(
    actor: str,
    format: str = Query("html", pattern="^(html|pdf)$"),
):
    """Analyst-ready incident report for one attacker.

    ``format=html`` returns a standalone page for preview; ``format=pdf``
    returns a downloadable PDF with the same content (MITRE ATT&CK techniques,
    kill-chain stages, event timeline, risk score, confidence, AI contribution
    and the action ACT took).
    """

    built = engine.report(actor, fmt=format)

    if built is None:
        raise HTTPException(status_code=404, detail="No attack path for that actor")

    content, media_type, filename = built
    disposition = "attachment" if format == "pdf" else "inline"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'{disposition}; filename="{filename}"'},
    )


# ---------------------------------------------------------- notifications #


@app.get("/api/notifications")
def notifications_status():
    """Whether critical-attack alerts (Telegram / Slack) are enabled and ready."""
    return engine.notifier.status()


@app.post("/api/notifications/config")
def notifications_config(
    enabled: Optional[bool] = None,
    platform: Optional[str] = Query(None, pattern="^(telegram|slack|both)$"),
    risk_threshold: Optional[int] = Query(None, ge=0, le=100),
):
    """Enable / disable alerting and choose the platform, at runtime.

    Tokens and the persistent defaults live in ``backend/.env`` and
    ``backend/config/detection.json``.
    """
    return engine.notifier.configure(
        enabled=enabled, platform=platform, risk_threshold=risk_threshold
    )


@app.post("/api/notifications/test")
def notifications_test():
    """Send a test alert on every configured transport, right now."""

    if not engine.notifier.configured:
        raise HTTPException(
            status_code=400,
            detail=("No transport configured. Set TELEGRAM_BOT_TOKEN + "
                    "TELEGRAM_CHAT_ID or SLACK_WEBHOOK_URL in backend/.env."),
        )

    results = engine.notifier.send_text(
        "✅ *ACT test alert* — notifications are wired up correctly."
    )
    return {"results": results}


# ------------------------------------------------------------------- stats #


@app.get("/api/stats")
def get_stats():
    return engine.stats()


@app.get("/api/logs")
def get_sample_logs():
    return {"logs": engine.available_logs()}


# ----------------------------------------------------------------- ingest #


@app.post("/api/ingest/file")
def ingest_file(path: str = Query(..., description="log file name or full path")):

    try:
        stats = engine.ingest_file(path)
    except FileNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error))

    return {
        "lines_read": stats.lines_read,
        "events_created": stats.events_created,
        "lines_unmatched": stats.lines_unmatched,
        "parse_errors": stats.parse_errors,
        "coverage": stats.coverage,
    }


@app.post("/api/ingest/journal")
def ingest_journal(
    since: str = "-24h",
    unit: Optional[List[str]] = Query(None),
):
    try:
        stats = engine.ingest_journal(since=since, units=unit)
    except RuntimeError as error:
        raise HTTPException(status_code=400, detail=str(error))

    return {
        "lines_read": stats.lines_read,
        "events_created": stats.events_created,
        "coverage": stats.coverage,
    }


@app.post("/api/ingest/ssh")
def ingest_ssh(
    host: str = Query(..., description="address of the machine to read, e.g. 192.168.86.130"),
    user: Optional[str] = Query("kali"),
    port: int = 22,
    key_file: Optional[str] = None,
    since: str = "-24h",
    sudo: bool = False,
    unit: Optional[List[str]] = Query(None),
):
    """Read the systemd journal of another machine, for example the Kali VM."""

    try:
        stats = engine.ingest_ssh(
            host=host, user=user, port=port, key_file=key_file,
            since=since, units=unit, use_sudo=sudo,
        )
    except RuntimeError as error:
        raise HTTPException(status_code=400, detail=str(error))

    return {
        "lines_read": stats.lines_read,
        "events_created": stats.events_created,
        "lines_unmatched": stats.lines_unmatched,
        "coverage": stats.coverage,
    }


@app.post("/api/ssh/test")
def test_ssh(
    host: str = Query(...),
    user: Optional[str] = Query("kali"),
    port: int = 22,
    key_file: Optional[str] = None,
    sudo: bool = False,
):
    """Check the connection to the VM and say exactly what is wrong if it fails."""

    return engine.check_ssh(
        host=host, user=user, port=port, key_file=key_file, use_sudo=sudo
    )


@app.post("/api/live/start")
def start_live(
    file: Optional[str] = None,
    since: str = "-5m",
    unit: Optional[List[str]] = Query(None),
    host: Optional[str] = None,
    user: Optional[str] = None,
    port: int = 22,
    key_file: Optional[str] = None,
    sudo: bool = False,
):
    started = engine.start_live(
        file=file, since=since, units=unit,
        host=host, user=user, port=port, key_file=key_file, use_sudo=sudo,
    )

    return {
        "started": started,
        "source": engine.live_source,
        "error": engine.live_error,
    }


@app.post("/api/live/stop")
def stop_live():
    return {"stopped": engine.stop_live()}


@app.post("/api/reset")
def reset():
    engine.reset()
    return {"status": "cleared"}


# ------------------------------------------------------------ live stream #


@app.websocket("/api/stream")
async def stream(websocket: WebSocket):
    """Pushes every new event as it is ingested.

    Deliberately a poll of the engine rather than a callback: the ingestion
    pipeline runs in its own thread, and reading a growing list from the event
    loop is far simpler to reason about than pushing across threads.
    """

    await websocket.accept()

    index = len(engine.store.all())

    try:
        await websocket.send_json({"type": "connected", "from_index": index})

        while True:
            index, new_events = engine.events_since(index)

            if new_events:
                await websocket.send_json(
                    {
                        "type": "events",
                        "events": events_to_list(new_events),
                        "total": index,
                    }
                )

            await asyncio.sleep(1)

    except WebSocketDisconnect:
        return
    except Exception:                                       # noqa: BLE001
        #a dead socket must never take the server down
        return
