"""In-process per-IP rate limiting.

A fixed-window counter per (client, bucket). Two buckets: ``auth`` for the
credential endpoints (login / refresh - a much lower ceiling to blunt password
spraying) and ``api`` for everything else. Non-``/api`` paths, websocket
upgrades, and ``OPTIONS`` are never limited.

In-process means each worker keeps its own counts - fine for ACT's normal
single-process deployment; behind several workers the effective limit multiplies
by the worker count. A shared store (Redis) would be a later change.
"""

from __future__ import annotations

import logging
import time
from threading import Lock
from typing import Dict, Tuple

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.settings import get_settings

log = logging.getLogger("app.api.ratelimit")

_WINDOW_SECONDS = 60
_AUTH_PATHS = ("/api/auth/login", "/api/auth/refresh",
               "/api/v1/auth/login", "/api/v1/auth/refresh")


class _Counter:
    __slots__ = ("count", "window_start")

    def __init__(self, now: float) -> None:
        self.count = 0
        self.window_start = now


class RateLimiter:
    """The counting core, without any framework - unit-testable on its own."""

    def __init__(self) -> None:
        self._cells: Dict[Tuple[str, str], _Counter] = {}
        self._lock = Lock()
        self._last_sweep = 0.0

    def hit(self, key: str, bucket: str, limit: int, now: float | None = None
            ) -> Tuple[bool, int, int]:
        """Return ``(allowed, remaining, retry_after_seconds)``."""
        now = time.monotonic() if now is None else now
        with self._lock:
            self._maybe_sweep(now)
            cell = self._cells.get((key, bucket))
            if cell is None or now - cell.window_start >= _WINDOW_SECONDS:
                cell = _Counter(now)
                self._cells[(key, bucket)] = cell
            cell.count += 1
            if cell.count > limit:
                retry = int(_WINDOW_SECONDS - (now - cell.window_start)) + 1
                return False, 0, max(retry, 1)
            return True, max(limit - cell.count, 0), 0

    def _maybe_sweep(self, now: float) -> None:
        if now - self._last_sweep < _WINDOW_SECONDS:
            return
        self._last_sweep = now
        stale = [k for k, c in self._cells.items()
                 if now - c.window_start >= _WINDOW_SECONDS * 2]
        for k in stale:
            del self._cells[k]

    def reset(self) -> None:
        with self._lock:
            self._cells.clear()
            self._last_sweep = 0.0


_LIMITER = RateLimiter()


def get_limiter() -> RateLimiter:
    return _LIMITER


def _client_key(request: Request, trust_forwarded: bool) -> str:
    if trust_forwarded:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        path = request.url.path

        if (not settings.rate_limit_enabled
                or request.method == "OPTIONS"
                or not path.startswith("/api/")):
            return await call_next(request)

        is_auth = path in _AUTH_PATHS
        bucket = "auth" if is_auth else "api"
        limit = (settings.rate_limit_auth_per_minute if is_auth
                 else settings.rate_limit_per_minute)
        key = _client_key(request, settings.trust_forwarded_for)

        allowed, remaining, retry_after = _LIMITER.hit(key, bucket, limit)
        if not allowed:
            log.warning("rate limit hit", extra={"client": key, "bucket": bucket,
                                                 "path": path})
            return JSONResponse(
                {"detail": "rate limit exceeded, slow down"},
                status_code=429,
                headers={"Retry-After": str(retry_after),
                         "X-RateLimit-Limit": str(limit),
                         "X-RateLimit-Remaining": "0"},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
