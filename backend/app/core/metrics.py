"""Prometheus metrics for the service.

Exposes counters/histograms via ``prometheus_client`` on the default registry.
The HTTP request counter + duration histogram are filled by
:class:`MetricsMiddleware`; the domain counters (attacks, alerts, blocks, logins)
are bumped from the code paths that own those events. Engine gauges (event count,
attack-path count, ...) are read straight off the live engine at scrape time by
:func:`render`.

For the literal "p50/p95/p99" ask, a small in-memory reservoir of recent request
durations is kept alongside the histogram and published as three gauges. Grafana
users should prefer ``histogram_quantile`` over the histogram itself.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from typing import Deque, Optional

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

log = logging.getLogger("app.core.metrics")

# --------------------------------------------------------------------- meters #

UP = Gauge("act_up", "1 while the ACT API process is serving")
UP.set(1)

HTTP_REQUESTS = Counter(
    "act_http_requests_total", "HTTP requests handled",
    ["method", "path", "status"],
)
HTTP_DURATION = Histogram(
    "act_http_request_duration_seconds", "HTTP request duration",
    ["method", "path"],
    buckets=(.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10),
)

ATTACKS_DETECTED = Counter(
    "act_attacks_detected_total", "Behaviours newly persisted as attacks",
)
ALERTS_SENT = Counter(
    "act_alerts_sent_total", "Critical-alert notifications attempted",
    ["platform", "result"],   # result: sent | failed
)
BLOCKS = Counter(
    "act_blocks_total", "Autonomous block responses by outcome",
    ["result"],               # result: success | failure
)
RESPONSES = Counter(
    "act_responses_total", "Response actions carried out",
    ["action", "status"],
)
LOGIN_ATTEMPTS = Counter(
    "act_login_attempts_total", "Authentication attempts",
    ["result"],               # result: success | failure
)

# engine gauges, refreshed at scrape time
G_EVENTS = Gauge("act_events", "Security events currently held by the engine")
G_BEHAVIORS = Gauge("act_behaviors", "Correlated behaviours currently detected")
G_ATTACK_PATHS = Gauge("act_active_attack_paths", "Attack paths in the current graph")
G_COMPROMISED = Gauge("act_attack_paths_compromised", "Attack paths that reached compromise")

P50 = Gauge("act_http_request_duration_p50_seconds", "Rolling p50 of request duration")
P95 = Gauge("act_http_request_duration_p95_seconds", "Rolling p95 of request duration")
P99 = Gauge("act_http_request_duration_p99_seconds", "Rolling p99 of request duration")

_DURATIONS: Deque[float] = deque(maxlen=2048)


# ---------------------------------------------------------------- recorders #


def record_attacks(n: int = 1) -> None:
    if n > 0:
        ATTACKS_DETECTED.inc(n)


def record_alert(platform: str, ok: bool) -> None:
    ALERTS_SENT.labels(platform=platform or "unknown",
                       result="sent" if ok else "failed").inc()


def record_block(ok: bool) -> None:
    BLOCKS.labels(result="success" if ok else "failure").inc()


def record_response(action: str, status: str) -> None:
    RESPONSES.labels(action=action or "unknown", status=status or "unknown").inc()


def record_login(ok: bool) -> None:
    LOGIN_ATTEMPTS.labels(result="success" if ok else "failure").inc()


def _quantile(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, int(round(q * (len(sorted_vals) - 1))))
    return sorted_vals[idx]


def _refresh_quantiles() -> None:
    snapshot = sorted(_DURATIONS)
    P50.set(_quantile(snapshot, 0.50))
    P95.set(_quantile(snapshot, 0.95))
    P99.set(_quantile(snapshot, 0.99))


# ---------------------------------------------------------------- middleware #


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            elapsed = time.perf_counter() - start
            route = request.scope.get("route")
            path = getattr(route, "path", None) or "__unmatched__"
            method = request.method
            HTTP_REQUESTS.labels(method=method, path=path,
                                 status=str(status_code)).inc()
            HTTP_DURATION.labels(method=method, path=path).observe(elapsed)
            _DURATIONS.append(elapsed)


# ------------------------------------------------------------------ render #


def render(engine: Optional[object] = None) -> tuple[bytes, str]:
    """Serialise the registry. Refreshes engine gauges + rolling quantiles first."""
    if engine is not None:
        try:
            G_EVENTS.set(len(engine.store.all()))
            behaviors = engine.behaviors()
            G_BEHAVIORS.set(len(behaviors))
            graph = engine.attack_graph()
            G_ATTACK_PATHS.set(len(graph.paths))
            G_COMPROMISED.set(sum(1 for p in graph.paths if p.succeeded))
        except Exception:  # noqa: BLE001  (metrics must never 500)
            log.debug("engine gauge refresh failed", exc_info=True)
    _refresh_quantiles()
    return generate_latest(), CONTENT_TYPE_LATEST
