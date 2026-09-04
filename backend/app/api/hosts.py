"""Reject forged Host headers.

A poisoned ``Host`` is how password-reset links and OAuth redirect URIs get
pointed at an attacker's domain. ``ACT_ALLOWED_HOSTS`` is the allowlist
(comma-separated; ``*`` accepts anything, the dev default; a leading ``.``
allows subdomains). Read per request, like the other ACT middleware.

``/api/health`` is exempt so an orchestrator can probe it by raw IP.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from app.core.settings import get_settings

_EXEMPT = ("/api/health", "/api/v1/health")


def host_allowed(host: str, allowlist: list[str]) -> bool:
    if not allowlist or "*" in allowlist:
        return True
    hostname = host.split(":")[0].strip().lower()
    if not hostname:
        return False
    for pattern in allowlist:
        pattern = pattern.lower()
        if pattern.startswith("."):
            if hostname == pattern[1:] or hostname.endswith(pattern):
                return True
        elif hostname == pattern:
            return True
    return False


class TrustedHostMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        allowlist = get_settings().allowed_hosts_list
        if "*" in allowlist or not allowlist:
            return await call_next(request)
        if request.url.path in _EXEMPT:
            return await call_next(request)
        if not host_allowed(request.headers.get("host", ""), allowlist):
            return PlainTextResponse("invalid host header", status_code=400)
        return await call_next(request)
