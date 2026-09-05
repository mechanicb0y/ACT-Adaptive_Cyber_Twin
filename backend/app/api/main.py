"""The ACT REST API application.

Route handlers live in ``app/api/v1/`` (engine-backed) and ``app/auth/`` (auth).
This module only assembles them: the middleware stack, the versioned + legacy
mounts, the dashboard/login pages, the event-stream websocket, and startup.

Run it with:
    cd backend
    python -m uvicorn app.api.main:app --reload

Dashboard at http://127.0.0.1:8000/ , API docs at /docs .
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from app.config import env as _env  # noqa: F401  (loads backend/.env on import)

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

from app.api.cors import DynamicCORSMiddleware
from app.api.hosts import TrustedHostMiddleware
from app.api.https import ForceHTTPSMiddleware
from app.api.deps import get_engine
from app.api.serializers import events_to_list
from app.api.v1 import api_router
from app.api.ratelimit import RateLimitMiddleware
from app.auth import service as auth_service
from app.auth.middleware import AuthMiddleware, authenticate_websocket
from app.auth.router import router as auth_router
from app.core.logging import configure_logging
from app.core.metrics import MetricsMiddleware
from app.core.settings import get_settings
from app.core.tracing import configure_observability
from app.db.session import get_sessionmaker, init_db

log = logging.getLogger("app.api")

FRONTEND_DIR = Path(__file__).resolve().parents[3] / "frontend"


@asynccontextmanager
async def lifespan(app_: FastAPI):
    configure_logging()
    settings = get_settings()
    configure_observability(app_, settings)
    try:
        init_db()  # create_all for SQLite; a no-op once Alembic has run on PG
    except Exception:  # noqa: BLE001  (a broken DB must not stop the read-only demo)
        log.exception("database init failed; some endpoints will error until fixed")
    if settings.auth_enabled:
        try:
            with get_sessionmaker()() as session:
                auth_service.bootstrap_admin(session)
                session.commit()
        except Exception:  # noqa: BLE001
            log.exception("admin bootstrap failed")
    else:
        log.warning("ACT_AUTH_ENABLED=false - every request runs as admin")
    yield


app = FastAPI(
    title="ACT - Adaptive Cyber Twin",
    description="Linux security log ingestion, behavior correlation, risk scoring, "
                "MITRE ATT&CK mapping, attack graphs and autonomous response.",
    version="1.0.0",
    lifespan=lifespan,
)

# Middleware, added inner-first so the runtime order is:
#   CORS (answers preflight, decorates every response)
#   -> rate limiting -> request metrics -> authentication -> routes
# Every one of these reads get_settings() per request, so a redeploy or a test
# can change behaviour without rebuilding the app.
app.add_middleware(AuthMiddleware)
app.add_middleware(MetricsMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(DynamicCORSMiddleware)
app.add_middleware(ForceHTTPSMiddleware)
app.add_middleware(TrustedHostMiddleware)  # outermost: reject a forged Host first

# Auth endpoints and the engine API, each mounted twice: the canonical
# /api/v1/... and the unversioned /api/... alias kept for the dashboard and
# existing clients (hidden from the OpenAPI schema to avoid duplicate operations).
app.include_router(auth_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api", include_in_schema=False)
app.include_router(api_router, prefix="/api/v1")
app.include_router(api_router, prefix="/api", include_in_schema=False)


# ---------------------------------------------------------------- dashboard #


@app.get("/", include_in_schema=False)
def dashboard():
    index = FRONTEND_DIR / "index.html"
    if not index.exists():
        return JSONResponse({"project": "ACT", "status": "running", "api": "/docs"})
    return FileResponse(index)


@app.get("/login", include_in_schema=False)
def login_page():
    page = FRONTEND_DIR / "login.html"
    if not page.exists():
        return JSONResponse({"detail": "login page not found"}, status_code=404)
    return FileResponse(page)


@app.get("/logo.jpeg", include_in_schema=False)
def logo():
    logo_file = FRONTEND_DIR / "public" / "logo.jpeg"
    if not logo_file.exists():
        return JSONResponse({"detail": "logo not found"}, status_code=404)
    return FileResponse(logo_file)


# ------------------------------------------------------------ live stream #


@app.websocket("/api/stream")
@app.websocket("/api/v1/stream")
async def stream(websocket: WebSocket):
    """Pushes every new event as it is ingested.

    Auth: pass the access token as ``?token=`` (browsers cannot set an
    ``Authorization`` header on a WebSocket). Closed with code 4401 when the
    token is missing or invalid and auth is enabled.
    """
    if authenticate_websocket(websocket.query_params.get("token")) is None:
        await websocket.close(code=4401)
        return

    engine = get_engine()
    await websocket.accept()
    index = len(engine.store.all())

    try:
        await websocket.send_json({"type": "connected", "from_index": index})
        while True:
            index, new_events = engine.events_since(index)
            if new_events:
                await websocket.send_json({
                    "type": "events",
                    "events": events_to_list(new_events),
                    "total": index,
                })
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        return
    except Exception:                                       # noqa: BLE001
        # a dead socket must never take the server down
        return
