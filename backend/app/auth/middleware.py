"""One place where every HTTP request is authenticated.

Runs for ``/api/*`` only. The dashboard shell, ``/login``, ``/docs`` and
``/openapi.json`` are served without a token (the browser then calls the API
with one). ``/api/auth/*`` and ``/api/health`` are always open.

WebSocket upgrades bypass ``BaseHTTPMiddleware``; ``/api/stream`` authenticates
itself from a ``?token=`` query parameter (see :func:`authenticate_websocket`).
"""

from __future__ import annotations

import logging
from typing import Iterable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from app.auth.dependencies import PROTOTYPE_ADMIN, CurrentUser
from app.auth.tokens import TokenError, decode_access_token
from app.core.settings import get_settings

log = logging.getLogger("app.auth.middleware")

# Open paths under /api. Everything else under /api needs a bearer token. The
# check runs on the version-normalised path, so /api/v1/health matches too.
OPEN_API_PREFIXES = ("/api/auth", "/api/health", "/api/metrics")


def _normalise(path: str) -> str:
    # collapse the optional version segment: /api/v1/foo -> /api/foo
    if path == "/api/v1":
        return "/api"
    if path.startswith("/api/v1/"):
        return "/api/" + path[len("/api/v1/"):]
    return path


def _is_open(path: str) -> bool:
    norm = _normalise(path)
    return any(norm == prefix or norm.startswith(prefix + "/")
               for prefix in OPEN_API_PREFIXES)


def _claims_to_user(token: str) -> CurrentUser:
    claims = decode_access_token(token)
    return CurrentUser(id=claims.user_id, username=claims.username, role=claims.role)


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip() or None
    return None


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, *, open_prefixes: Iterable[str] | None = None):
        super().__init__(app)
        self._open = tuple(open_prefixes) if open_prefixes else OPEN_API_PREFIXES

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        settings = get_settings()

        if not settings.auth_enabled:
            request.state.act_user = PROTOTYPE_ADMIN
            return await call_next(request)

        if request.method == "OPTIONS" or not path.startswith("/api/"):
            return await call_next(request)

        token = _bearer(request)

        if _is_open(path):
            # Still attach the user when a good token rides along (harmless).
            if token:
                try:
                    request.state.act_user = _claims_to_user(token)
                except TokenError:
                    pass
            return await call_next(request)

        if not token:
            return JSONResponse(
                {"detail": "not authenticated"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            request.state.act_user = _claims_to_user(token)
        except TokenError as exc:
            return JSONResponse(
                {"detail": str(exc)},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        return await call_next(request)


def authenticate_websocket(token: str | None) -> CurrentUser | None:
    """Resolve a websocket caller. ``None`` means reject (unless auth is off)."""
    settings = get_settings()
    if not settings.auth_enabled:
        return PROTOTYPE_ADMIN
    if not token:
        return None
    try:
        return _claims_to_user(token)
    except TokenError:
        return None
