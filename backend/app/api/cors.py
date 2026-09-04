"""CORS handled in-process, reading the allowlist per request.

Starlette's ``CORSMiddleware`` fixes its config at construction time, which the
rest of ACT's middleware does not - they all consult :func:`get_settings` on
every request so a redeploy (or a test) can change behaviour without rebuilding
the app. This does the same for CORS.

Rules:
* ``ACT_CORS_ORIGINS`` empty  -> the localhost dev origins in
  ``Settings.cors_origin_list``.
* contains ``*``              -> every origin is echoed back; credentialed
  requests are still refused (a wildcard + credentials is invalid).
* otherwise                   -> only listed origins get CORS headers.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

from app.core.settings import get_settings

_EXPOSE = "X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After"


def _allowed_origin(origin: str, allowlist: list[str]) -> str | None:
    if not origin:
        return None
    if "*" in allowlist:
        return origin
    return origin if origin in allowlist else None


class DynamicCORSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        origin = request.headers.get("origin", "")
        allow = _allowed_origin(origin, settings.cors_origin_list)
        credentials = settings.cors_allow_credentials and "*" not in settings.cors_origin_list

        # Preflight
        if request.method == "OPTIONS" and request.headers.get(
            "access-control-request-method"
        ):
            if allow is None:
                return PlainTextResponse("origin not allowed", status_code=400)
            headers = {
                "Access-Control-Allow-Origin": allow,
                "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
                "Access-Control-Allow-Headers": request.headers.get(
                    "access-control-request-headers", "*"
                ),
                "Access-Control-Max-Age": "600",
                "Vary": "Origin",
            }
            if credentials:
                headers["Access-Control-Allow-Credentials"] = "true"
            return Response(status_code=200, headers=headers)

        response = await call_next(request)

        if allow is not None:
            response.headers["Access-Control-Allow-Origin"] = allow
            response.headers["Access-Control-Expose-Headers"] = _EXPOSE
            existing_vary = response.headers.get("Vary")
            response.headers["Vary"] = (
                f"{existing_vary}, Origin" if existing_vary else "Origin"
            )
            if credentials:
                response.headers["Access-Control-Allow-Credentials"] = "true"
        return response
