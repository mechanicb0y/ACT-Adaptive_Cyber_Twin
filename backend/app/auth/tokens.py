"""JWT access tokens and opaque refresh tokens.

Access token: a short-lived signed JWT (``type=access``) carrying the user id,
username and role. Stateless - verified by signature and expiry alone, so the
auth middleware never touches the database on the hot path.

Refresh token: a long random string handed to the client. Only its SHA-256
hash is stored (:class:`app.db.models.RefreshToken`), so a database leak does
not expose usable tokens. Rotated on every use.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import logging
import secrets
from dataclasses import dataclass
from typing import Any, Optional

import jwt

from app.core.settings import Settings, get_settings

log = logging.getLogger("app.auth.tokens")

_PROCESS_SECRET: Optional[str] = None


class TokenError(Exception):
    """Raised for any malformed, expired or wrong-type token."""


def _secret(settings: Settings) -> str:
    global _PROCESS_SECRET
    if settings.jwt_secret:
        return settings.jwt_secret
    if _PROCESS_SECRET is None:
        _PROCESS_SECRET = secrets.token_urlsafe(48)
        log.warning(
            "ACT_JWT_SECRET is not set - using a random per-process secret; "
            "sessions will not survive a restart and cannot be shared across "
            "workers. Set ACT_JWT_SECRET in production."
        )
    return _PROCESS_SECRET


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


@dataclass(frozen=True, slots=True)
class AccessClaims:
    sub: str          # user id, as a string
    username: str
    role: str
    exp: _dt.datetime
    iat: _dt.datetime

    @property
    def user_id(self) -> int:
        return int(self.sub)


def create_access_token(
    *, user_id: int, username: str, role: str,
    settings: Optional[Settings] = None,
) -> str:
    settings = settings or get_settings()
    issued = _now()
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "type": "access",
        "jti": secrets.token_urlsafe(8),  # unique even for two tokens in one second
        "iat": issued,
        "exp": issued + _dt.timedelta(minutes=settings.access_token_ttl_minutes),
    }
    return jwt.encode(payload, _secret(settings), algorithm=settings.jwt_algorithm)


def decode_access_token(
    token: str, *, settings: Optional[Settings] = None
) -> AccessClaims:
    settings = settings or get_settings()
    try:
        payload: dict[str, Any] = jwt.decode(
            token, _secret(settings), algorithms=[settings.jwt_algorithm]
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("invalid token") from exc

    if payload.get("type") != "access":
        raise TokenError("not an access token")
    try:
        return AccessClaims(
            sub=str(payload["sub"]),
            username=payload.get("username", ""),
            role=payload.get("role", "viewer"),
            exp=_dt.datetime.fromtimestamp(payload["exp"], tz=_dt.timezone.utc),
            iat=_dt.datetime.fromtimestamp(payload["iat"], tz=_dt.timezone.utc),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise TokenError("malformed claims") from exc


# ------------------------------------------------------------- refresh tokens #


def generate_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def refresh_token_expiry(
    *, remember_me: bool, settings: Optional[Settings] = None
) -> _dt.datetime:
    settings = settings or get_settings()
    days = (settings.refresh_token_remember_days if remember_me
            else settings.refresh_token_ttl_days)
    return _now() + _dt.timedelta(days=days)
