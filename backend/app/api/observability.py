"""``/api/health`` payload.

Deliberately cheap: it counts in-memory state and pings the database, but it
does not run the LLM or open an SSH connection. ``status`` is ``ok`` unless the
database is required (auth on) and unreachable.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from app.core.settings import get_settings
from app.db.session import check_connection

log = logging.getLogger("app.api.observability")

_STARTED = time.time()


def _last_attack(engine: Any) -> str | None:
    try:
        events = engine.store.all()
        if not events:
            return None
        return max(e.timestamp for e in events).isoformat(sep=" ", timespec="seconds")
    except Exception:  # noqa: BLE001
        return None


def _ollama(engine: Any) -> dict:
    try:
        analyst = engine.twin.analyst
        return {
            "provider": analyst.provider or "none",
            "available": bool(analyst.available),
            "narrator": analyst.narrator_name(),
        }
    except Exception:  # noqa: BLE001
        return {"provider": "unknown", "available": False, "narrator": None}


def build_health(engine: Any) -> dict:
    settings = get_settings()
    db = check_connection()

    paths = 0
    compromised = False
    try:
        graph = engine.attack_graph()
        paths = len(graph.paths)
        compromised = any(p.succeeded for p in graph.paths)
    except Exception:  # noqa: BLE001
        log.debug("attack graph unavailable for health", exc_info=True)

    healthy = db["connected"] or not settings.auth_enabled

    return {
        "status": "ok" if healthy else "degraded",
        "version": "1.0.0",
        "environment": settings.env,
        "uptime_seconds": round(time.time() - _STARTED, 1),
        "auth_enabled": settings.auth_enabled,
        "database": db,
        "ollama": _ollama(engine),
        "events": len(engine.store.all()),
        "active_attack_paths": paths,
        "compromised": compromised,
        "last_attack_time": _last_attack(engine),
    }
