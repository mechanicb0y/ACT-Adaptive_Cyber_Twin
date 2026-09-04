"""Health and metrics - the endpoints an orchestrator and Prometheus scrape.

Both are in the auth middleware's open list, so they need no bearer token.
``/metrics`` can still be gated with ``ACT_METRICS_TOKEN``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from app.api.deps import get_engine
from app.api.engine import AnalysisEngine
from app.api.observability import build_health
from app.core import metrics
from app.core.settings import get_settings

router = APIRouter(tags=["system"])


@router.get("/health")
def health(engine: AnalysisEngine = Depends(get_engine)):
    """Liveness + readiness: process, database, Ollama, last attack seen."""
    return build_health(engine)


@router.get("/metrics", include_in_schema=False)
def prometheus_metrics(request: Request, engine: AnalysisEngine = Depends(get_engine)):
    settings = get_settings()
    if not settings.metrics_enabled:
        raise HTTPException(status_code=404, detail="metrics are disabled")

    if settings.metrics_token:
        supplied = request.query_params.get("token")
        if not supplied:
            auth = request.headers.get("authorization", "")
            if auth.lower().startswith("bearer "):
                supplied = auth[7:].strip()
        if supplied != settings.metrics_token:
            raise HTTPException(status_code=401, detail="bad metrics token")

    body, content_type = metrics.render(engine)
    return Response(content=body, media_type=content_type)
