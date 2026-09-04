"""Optional distributed tracing (OpenTelemetry) and error reporting (Sentry).

Both are off unless configured *and* their packages are installed
(``backend/requirements-observability.txt``). Missing packages or missing
config -> a logged no-op. Nothing here is imported by the pipeline; only
``app/api/main.py`` calls :func:`configure_observability` at startup.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from app.core.settings import Settings, get_settings

log = logging.getLogger("app.core.tracing")

_STATE = {"otel": False, "sentry": False}


def observability_status() -> dict:
    return dict(_STATE)


# ------------------------------------------------------------------- Sentry #


def _setup_sentry(settings: Settings) -> None:
    if not settings.sentry_dsn:
        return
    try:
        import sentry_sdk
    except ImportError:
        log.warning("SENTRY_DSN is set but sentry-sdk is not installed "
                    "(pip install -r requirements-observability.txt)")
        return
    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.env,
        traces_sample_rate=settings.sentry_traces_sample_rate,
        release="act@1.0.0",
    )
    _STATE["sentry"] = True
    log.info("Sentry error reporting enabled", extra={"environment": settings.env})


# --------------------------------------------------------------- OpenTelemetry #


def _setup_otel(app: Any, settings: Settings) -> None:
    if not settings.otel_enabled:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import (
            BatchSpanProcessor,
            ConsoleSpanExporter,
        )
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    except ImportError:
        log.warning("ACT_OTEL_ENABLED is set but the OpenTelemetry packages are "
                    "not installed (pip install -r requirements-observability.txt)")
        return

    resource = Resource.create({"service.name": settings.otel_service_name,
                                "deployment.environment": settings.env})
    provider = TracerProvider(resource=resource)

    exporters = []
    if settings.otel_exporter_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
            exporters.append(OTLPSpanExporter(
                endpoint=settings.otel_exporter_endpoint.rstrip("/") + "/v1/traces"
            ))
        except ImportError:
            log.warning("OTLP HTTP exporter not installed; falling back")
    if settings.otel_console_export or not exporters:
        exporters.append(ConsoleSpanExporter())

    for exporter in exporters:
        provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    FastAPIInstrumentor.instrument_app(app, excluded_urls="/api/health,/api/metrics")

    try:
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        from app.db.session import get_engine as _get_db_engine
        SQLAlchemyInstrumentor().instrument(engine=_get_db_engine().sync_engine
                                            if hasattr(_get_db_engine(), "sync_engine")
                                            else _get_db_engine())
    except Exception:  # noqa: BLE001
        log.debug("SQLAlchemy instrumentation skipped", exc_info=True)

    _STATE["otel"] = True
    log.info("OpenTelemetry tracing enabled",
             extra={"service": settings.otel_service_name,
                    "endpoint": settings.otel_exporter_endpoint or "console"})


def configure_observability(app: Any, settings: Optional[Settings] = None) -> None:
    settings = settings or get_settings()
    try:
        _setup_sentry(settings)
    except Exception:  # noqa: BLE001
        log.exception("Sentry init failed")
    try:
        _setup_otel(app, settings)
    except Exception:  # noqa: BLE001
        log.exception("OpenTelemetry init failed")
