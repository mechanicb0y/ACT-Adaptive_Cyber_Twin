"""Version 1 of the ACT HTTP API.

``api_router`` carries every ``/api`` route except the auth endpoints (those are
``app.auth.router``). ``main.py`` mounts it at ``/api/v1`` and, for backward
compatibility, also at ``/api`` (hidden from the schema).
"""

from fastapi import APIRouter

from app.api.v1 import routes, system

api_router = APIRouter()
api_router.include_router(system.router)
api_router.include_router(routes.router)

__all__ = ["api_router"]
