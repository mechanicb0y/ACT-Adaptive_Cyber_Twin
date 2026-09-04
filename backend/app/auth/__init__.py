"""Authentication and authorisation.

Local username/password accounts (bcrypt) with JWT sessions - a short-lived
access token plus a rotating, server-tracked refresh token. Role-based access
control with three roles: ``admin`` > ``analyst`` > ``viewer``.

OAuth2 (Google / GitHub) is scaffolded here but inert: the endpoints exist and
return a clear "not configured" response until a client id + secret are set.

Everything is gated by ``settings.auth_enabled``. With it off (the historical
single-user prototype, and the test suite's default) every request is treated as
an admin and no token is required.
"""

from app.auth.dependencies import (
    CurrentUser,
    get_current_user,
    require_role,
)
from app.auth.middleware import AuthMiddleware

__all__ = ["AuthMiddleware", "CurrentUser", "get_current_user", "require_role"]
