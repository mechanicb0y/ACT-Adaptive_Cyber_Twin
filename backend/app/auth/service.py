"""Auth operations against the database.

Every function takes an open :class:`~sqlalchemy.orm.Session` and leaves the
transaction to the caller (the router commits). Errors are raised as
:class:`AuthError` with an HTTP-ish ``status`` so the router can translate them
without importing FastAPI here.
"""

from __future__ import annotations

import datetime as _dt
import logging
import secrets
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth import tokens
from app.auth.passwords import hash_password, verify_password
from app.core.settings import Settings, get_settings
from app.db.models import OAuthHandoff, RefreshToken, Role, User

log = logging.getLogger("app.auth.service")

VALID_ROLES = {r.value for r in Role}


class AuthError(Exception):
    def __init__(self, message: str, *, status: int = 401) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _aware(value: _dt.datetime) -> _dt.datetime:
    # SQLite hands back naive datetimes; treat stored values as UTC.
    if value.tzinfo is None:
        return value.replace(tzinfo=_dt.timezone.utc)
    return value


# --------------------------------------------------------------- user lookup #


def get_user_by_username(session: Session, username: str) -> Optional[User]:
    return session.scalar(
        select(User).where(func.lower(User.username) == username.lower())
    )


def get_user_by_id(session: Session, user_id: int) -> Optional[User]:
    return session.get(User, user_id)


def user_count(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(User)) or 0


# ------------------------------------------------------------- authentication #


def authenticate(session: Session, username: str, password: str) -> User:
    user = get_user_by_username(session, username)
    # Verify even when the user is missing, to keep the timing uniform.
    reference = user.hashed_password if user else (
        "$2b$12$" + "." * 53  # structurally valid, never matches
    )
    ok = verify_password(password, reference)
    if not user or not ok:
        raise AuthError("invalid username or password")
    if not user.is_active:
        raise AuthError("account is disabled", status=403)
    return user


def touch_last_login(session: Session, user: User) -> None:
    user.last_login = _now()


# --------------------------------------------------------------- token issue #


def issue_tokens(
    session: Session,
    user: User,
    *,
    remember_me: bool = False,
    user_agent: Optional[str] = None,
    settings: Optional[Settings] = None,
) -> dict:
    settings = settings or get_settings()

    access = tokens.create_access_token(
        user_id=user.id, username=user.username, role=user.role, settings=settings
    )
    raw_refresh = tokens.generate_refresh_token()
    row = RefreshToken(
        user_id=user.id,
        token_hash=tokens.hash_refresh_token(raw_refresh),
        expires_at=tokens.refresh_token_expiry(
            remember_me=remember_me, settings=settings
        ),
        user_agent=(user_agent or "")[:256] or None,
        remember_me=remember_me,
    )
    session.add(row)

    return {
        "access_token": access,
        "refresh_token": raw_refresh,
        "expires_in": settings.access_token_ttl_minutes * 60,
        "role": user.role,
        "username": user.username,
    }


def _lookup_refresh(session: Session, raw_refresh: str) -> RefreshToken:
    row = session.scalar(
        select(RefreshToken).where(
            RefreshToken.token_hash == tokens.hash_refresh_token(raw_refresh)
        )
    )
    if row is None:
        raise AuthError("refresh token not recognised")
    return row


def rotate_refresh(
    session: Session,
    raw_refresh: str,
    *,
    user_agent: Optional[str] = None,
    settings: Optional[Settings] = None,
) -> dict:
    settings = settings or get_settings()
    row = _lookup_refresh(session, raw_refresh)

    if row.revoked_at is not None:
        # Token reuse after rotation - treat the whole chain as compromised.
        revoke_all_for_user(session, row.user_id)
        raise AuthError("refresh token already used; all sessions revoked",
                        status=401)
    if _aware(row.expires_at) <= _now():
        raise AuthError("refresh token expired")

    user = get_user_by_id(session, row.user_id)
    if user is None or not user.is_active:
        raise AuthError("account is disabled", status=403)

    row.revoked_at = _now()
    result = issue_tokens(
        session, user,
        remember_me=row.remember_me,
        user_agent=user_agent,
        settings=settings,
    )
    return result


def revoke_refresh(session: Session, raw_refresh: str) -> bool:
    row = session.scalar(
        select(RefreshToken).where(
            RefreshToken.token_hash == tokens.hash_refresh_token(raw_refresh)
        )
    )
    if row is None or row.revoked_at is not None:
        return False
    row.revoked_at = _now()
    return True


def revoke_all_for_user(session: Session, user_id: int) -> int:
    rows = session.scalars(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked_at.is_(None),
        )
    ).all()
    now = _now()
    for row in rows:
        row.revoked_at = now
    return len(rows)


def purge_expired_refresh_tokens(session: Session) -> int:
    rows = session.scalars(
        select(RefreshToken).where(RefreshToken.expires_at < _now())
    ).all()
    for row in rows:
        session.delete(row)
    return len(rows)


# ----------------------------------------------------------- user management #


def create_user(
    session: Session,
    *,
    username: str,
    password: Optional[str],
    email: Optional[str] = None,
    role: str = "viewer",
) -> User:
    if role not in VALID_ROLES:
        raise AuthError(f"unknown role {role!r}", status=422)
    if get_user_by_username(session, username):
        raise AuthError("username already taken", status=409)
    user = User(
        username=username,
        email=email,
        role=role,
        hashed_password=hash_password(password) if password else None,
    )
    session.add(user)
    session.flush()
    log.info("user created", extra={"username": username, "role": role})
    return user


def list_users(session: Session) -> list[User]:
    return list(session.scalars(select(User).order_by(User.id)).all())


def update_user(
    session: Session,
    user: User,
    *,
    password: Optional[str] = None,
    email: Optional[str] = None,
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
) -> User:
    if role is not None:
        if role not in VALID_ROLES:
            raise AuthError(f"unknown role {role!r}", status=422)
        user.role = role
    if email is not None:
        user.email = email or None
    if password is not None:
        user.hashed_password = hash_password(password)
        revoke_all_for_user(session, user.id)
    if is_active is not None:
        user.is_active = is_active
        if not is_active:
            revoke_all_for_user(session, user.id)
    return user


def change_password(
    session: Session, user: User, current_password: str, new_password: str
) -> None:
    if not verify_password(current_password, user.hashed_password):
        raise AuthError("current password is incorrect", status=400)
    user.hashed_password = hash_password(new_password)
    revoke_all_for_user(session, user.id)


def delete_user(session: Session, user: User) -> None:
    session.delete(user)


# ------------------------------------------------------------------ bootstrap #


def bootstrap_admin(
    session: Session, *, settings: Optional[Settings] = None
) -> Optional[str]:
    """Ensure at least one admin exists. Returns a generated password if it had
    to invent one, else ``None``."""
    settings = settings or get_settings()
    if user_count(session) > 0:
        return None

    generated: Optional[str] = None
    password = settings.bootstrap_admin_password
    if not password:
        password = secrets.token_urlsafe(15)
        generated = password

    create_user(
        session,
        username=settings.bootstrap_admin_username,
        password=password,
        role="admin",
    )
    if generated:
        log.warning(
            "created first admin %r with a generated password: %s  "
            "(set ACT_ADMIN_PASSWORD to control this; change it after first login)",
            settings.bootstrap_admin_username, generated,
        )
    else:
        log.info("created first admin %r from ACT_ADMIN_PASSWORD",
                 settings.bootstrap_admin_username)
    return generated


# ---------------------------------------------------------------------- oauth #


def create_oauth_handoff(
    session: Session, *, user_id: int, remember_me: bool, ttl_seconds: int = 120
) -> str:
    """Store a single-use code for the OAuth callback -> SPA hand-off. Returns
    the raw code (only its hash is persisted)."""
    # opportunistic cleanup: this table is transient by design
    for stale in session.scalars(
        select(OAuthHandoff).where(OAuthHandoff.expires_at < _now())
    ).all():
        session.delete(stale)

    raw = tokens.generate_refresh_token()
    session.add(OAuthHandoff(
        code_hash=tokens.hash_refresh_token(raw),
        user_id=user_id,
        remember_me=remember_me,
        expires_at=_now() + _dt.timedelta(seconds=ttl_seconds),
    ))
    return raw


def redeem_oauth_handoff(
    session: Session,
    raw_code: str,
    *,
    user_agent: Optional[str] = None,
    settings: Optional[Settings] = None,
) -> dict:
    row = session.scalar(
        select(OAuthHandoff).where(
            OAuthHandoff.code_hash == tokens.hash_refresh_token(raw_code)
        )
    )
    if row is None:
        raise AuthError("invalid sign-in hand-off")
    if row.consumed_at is not None:
        raise AuthError("sign-in hand-off already used")
    if _aware(row.expires_at) <= _now():
        raise AuthError("sign-in hand-off expired")

    row.consumed_at = _now()
    user = get_user_by_id(session, row.user_id)
    if user is None or not user.is_active:
        raise AuthError("account is disabled", status=403)

    touch_last_login(session, user)
    return issue_tokens(
        session, user, remember_me=row.remember_me,
        user_agent=user_agent, settings=settings,
    )


def upsert_oauth_user(
    session: Session,
    *,
    provider: str,
    subject: str,
    email: Optional[str],
    email_verified: bool,
    username_hint: str,
    default_role: str = "viewer",
) -> User:
    # Match strictly on the provider's stable subject id first.
    user = session.scalar(
        select(User).where(
            User.oauth_provider == provider, User.oauth_subject == subject
        )
    )
    if user:
        if email and email_verified and user.email != email:
            user.email = email
        return user

    # An unverified email must never be used to find or create an account -
    # otherwise anyone who can put a victim's address on a throwaway OAuth
    # account takes it over. Drop it and provision a fresh, email-less account.
    if email and not email_verified:
        email = None

    if email:
        existing = session.scalar(select(User).where(User.email == email))
        if existing:
            if existing.hashed_password:
                # A real credentialed account. Silent linking here is account
                # takeover; require the owner to prove the password first.
                raise AuthError(
                    "an account with this email already exists - sign in with "
                    "your password, then link this provider from your profile",
                    status=409,
                )
            if existing.oauth_provider and existing.oauth_provider != provider:
                raise AuthError(
                    "this email is already linked to a different sign-in provider",
                    status=409,
                )
            # Dormant, passwordless account (e.g. admin pre-provisioned it):
            # safe to attach this verified identity.
            existing.oauth_provider = provider
            existing.oauth_subject = subject
            return existing

    username = username_hint
    suffix = 1
    while get_user_by_username(session, username):
        suffix += 1
        username = f"{username_hint}{suffix}"

    user = User(
        username=username,
        email=email,
        role=default_role if default_role in VALID_ROLES else "viewer",
        oauth_provider=provider,
        oauth_subject=subject,
        hashed_password=None,
    )
    session.add(user)
    session.flush()
    log.info("oauth user provisioned",
             extra={"provider": provider, "username": username})
    return user
