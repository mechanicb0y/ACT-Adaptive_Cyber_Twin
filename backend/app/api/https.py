"""Redirect plaintext HTTP to HTTPS when ``ACT_FORCE_HTTPS`` is on.

Reads the flag per request (like the other ACT middleware) so it can be toggled
without rebuilding the app. It honours ``X-Forwarded-Proto`` so it works behind
a TLS-terminating proxy or the nginx frontend container, and never redirects
``/api/health`` so a plain-HTTP liveness probe still succeeds.
"""

from __future__ import annotations

from starlette.datastructures import URL
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse

from app.core.settings import get_settings

_ALWAYS_PLAINTEXT_OK = ("/api/health", "/api/v1/health")


def _is_secure(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    forwarded = request.headers.get("x-forwarded-proto", "")
    return forwarded.split(",")[0].strip() == "https"


class ForceHTTPSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        if (not settings.force_https
                or _is_secure(request)
                or request.url.path in _ALWAYS_PLAINTEXT_OK):
            return await call_next(request)

        target: URL = request.url.replace(scheme="https")
        if target.port == 80:
            target = target.replace(port=443)
        return RedirectResponse(str(target), status_code=307)
