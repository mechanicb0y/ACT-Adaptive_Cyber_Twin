"""``/api/auth/*`` - the only routes reachable without a bearer token.

Kept deliberately thin: parse the request, call :mod:`app.auth.service`, commit,
serialise. Rate limiting is applied globally in a later phase.
"""

from __future__ import annotations

import datetime as _dt
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.auth import oauth, service
from app.auth.dependencies import CurrentUser, get_current_user, require_admin
from app.auth.schemas import (
    LoginRequest,
    MessageResponse,
    PasswordChange,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    TokenResponse,
    UserCreate,
    UserOut,
    UserUpdate,
)
from app.auth.service import AuthError
from app.core.email import EmailSender
from app.core.settings import get_settings
from app.db.repository import record_audit
from app.db.session import get_db

log = logging.getLogger("app.auth.router")

# Mounted by main.py at both /api/auth and /api/v1/auth.
router = APIRouter(prefix="/auth", tags=["auth"])


def _client_ip(request: Request) -> Optional[str]:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


def _as_http(exc: AuthError) -> HTTPException:
    return HTTPException(status_code=exc.status, detail=exc.message)


# --------------------------------------------------------------- local login #


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = _client_ip(request)
    try:
        user = service.authenticate(db, body.username, body.password)
    except AuthError as exc:
        record_audit(db, action="login.failed", actor=body.username,
                     source_ip=ip, detail={"reason": exc.message})
        db.commit()
        raise _as_http(exc)

    service.touch_last_login(db, user)
    tokens = service.issue_tokens(
        db, user,
        remember_me=body.remember_me,
        user_agent=request.headers.get("user-agent"),
    )
    record_audit(db, action="login", actor=user.username, source_ip=ip,
                 detail={"remember_me": body.remember_me})
    db.commit()
    return TokenResponse(**tokens)


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    try:
        tokens = service.rotate_refresh(
            db, body.refresh_token,
            user_agent=request.headers.get("user-agent"),
        )
    except AuthError as exc:
        db.commit()  # persist any chain-revocation done inside rotate_refresh
        raise _as_http(exc)
    db.commit()
    return TokenResponse(**tokens)


@router.post("/logout", response_model=MessageResponse)
def logout(body: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    revoked = service.revoke_refresh(db, body.refresh_token)
    if revoked:
        record_audit(db, action="logout", source_ip=_client_ip(request))
    db.commit()
    return MessageResponse(detail="signed out" if revoked else "no active session")


# --------------------------------------------------------------- self-service #


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.auth_disabled:
        return UserOut(
            id=0, username="prototype", email=None, role="admin",
            is_active=True, oauth_provider=None,
            created_at=_dt.datetime.now(_dt.timezone.utc),
            last_login=None,
        )
    row = service.get_user_by_id(db, user.id)
    if row is None:
        raise HTTPException(status_code=404, detail="user not found")
    return UserOut.model_validate(row)


@router.post("/password-reset/request", response_model=MessageResponse,
             status_code=status.HTTP_202_ACCEPTED)
def password_reset_request(
    body: PasswordResetRequest, request: Request, db: Session = Depends(get_db)
):
    """Start a password reset. Always returns 202 with the same body, whether or
    not the email matches an account (no enumeration)."""
    settings = get_settings()
    same_answer = MessageResponse(
        detail="if that email has an account, a reset link is on its way"
    )

    issued = service.create_password_reset(
        db, body.email, requested_ip=_client_ip(request), settings=settings,
    )
    if issued is None:
        db.commit()
        return same_answer

    user, raw_token = issued

    # The link base is NEVER taken from the request (a forged Host header would
    # send the victim a link to the attacker's site). It comes only from
    # ACT_PUBLIC_BASE_URL; without that we fall back to the configured bind
    # address for local dev, and refuse outright in production.
    if settings.public_base_url:
        base = settings.public_base_url.rstrip("/")
    elif settings.is_production:
        log.error("password reset requested but ACT_PUBLIC_BASE_URL is not set; "
                  "not sending a link")
        record_audit(db, action="password.reset.request", actor=user.username,
                     source_ip=_client_ip(request),
                     detail={"emailed": False, "error": "no public base url"})
        db.commit()
        return same_answer
    else:
        base = f"http://{settings.host}:{settings.port}"

    reset_url = f"{base}/login?reset={raw_token}"

    sender = EmailSender.from_settings(settings)
    ok, error = sender.send_password_reset(
        user.email, username=user.username, reset_url=reset_url,
        ttl_minutes=settings.password_reset_ttl_minutes,
    )
    record_audit(db, action="password.reset.request", actor=user.username,
                 source_ip=_client_ip(request),
                 detail={"emailed": ok, "error": error})
    db.commit()

    if not ok and not settings.is_production:
        # dev convenience: no SMTP, so surface the (config-derived) link
        log.warning("password reset link for %s: %s", user.username, reset_url)
    return same_answer


@router.post("/password-reset/confirm", response_model=MessageResponse)
def password_reset_confirm(
    body: PasswordResetConfirm, request: Request, db: Session = Depends(get_db)
):
    try:
        user = service.redeem_password_reset(db, body.token, body.new_password)
    except AuthError as exc:
        db.commit()
        raise _as_http(exc)
    record_audit(db, action="password.reset.confirm", actor=user.username,
                 source_ip=_client_ip(request))
    db.commit()
    return MessageResponse(detail="password updated; sign in with your new password")


@router.post("/change-password", response_model=MessageResponse)
def change_password(
    body: PasswordChange,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user.auth_disabled:
        raise HTTPException(status_code=400,
                            detail="auth is disabled; nothing to change")
    row = service.get_user_by_id(db, user.id)
    if row is None:
        raise HTTPException(status_code=404, detail="user not found")
    try:
        service.change_password(db, row, body.current_password, body.new_password)
    except AuthError as exc:
        raise _as_http(exc)
    record_audit(db, action="password.change", actor=row.username,
                 source_ip=_client_ip(request))
    db.commit()
    return MessageResponse(detail="password changed; sign in again")


# ---------------------------------------------------------- user admin (RBAC) #


@router.get("/users", response_model=list[UserOut])
def list_users(_: CurrentUser = Depends(require_admin), db: Session = Depends(get_db)):
    return [UserOut.model_validate(u) for u in service.list_users(db)]


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreate,
    request: Request,
    admin: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        row = service.create_user(
            db, username=body.username, password=body.password,
            email=body.email, role=body.role,
        )
    except AuthError as exc:
        raise _as_http(exc)
    record_audit(db, action="user.create", actor=admin.username,
                 target=body.username, source_ip=_client_ip(request),
                 detail={"role": body.role})
    db.commit()
    return UserOut.model_validate(row)


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    body: UserUpdate,
    request: Request,
    admin: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    row = service.get_user_by_id(db, user_id)
    if row is None:
        raise HTTPException(status_code=404, detail="user not found")
    if row.id == admin.id and body.role is not None and body.role != "admin":
        raise HTTPException(status_code=400,
                            detail="you cannot demote your own account")
    try:
        service.update_user(
            db, row, password=body.password, email=body.email,
            role=body.role, is_active=body.is_active,
        )
    except AuthError as exc:
        raise _as_http(exc)
    record_audit(db, action="user.update", actor=admin.username,
                 target=row.username, source_ip=_client_ip(request),
                 detail=body.model_dump(exclude_none=True, exclude={"password"}))
    db.commit()
    return UserOut.model_validate(row)


@router.delete("/users/{user_id}", response_model=MessageResponse)
def delete_user(
    user_id: int,
    request: Request,
    admin: CurrentUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    row = service.get_user_by_id(db, user_id)
    if row is None:
        raise HTTPException(status_code=404, detail="user not found")
    if row.id == admin.id:
        raise HTTPException(status_code=400,
                            detail="you cannot delete your own account")
    username = row.username
    service.delete_user(db, row)
    record_audit(db, action="user.delete", actor=admin.username,
                 target=username, source_ip=_client_ip(request))
    db.commit()
    return MessageResponse(detail=f"deleted {username}")


# ---------------------------------------------------------------------- OAuth #


@router.get("/providers")
def providers():
    return {
        "local": {"enabled": True},
        "oauth": oauth.providers_status(),
    }


@router.get("/oauth/{provider}/login")
def oauth_login(provider: str, request: Request, remember_me: bool = False):
    if provider not in oauth.PROVIDERS:
        raise HTTPException(status_code=404, detail="unknown provider")
    if not oauth.is_configured(provider):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"{provider} OAuth is not configured on this server",
        )
    state = oauth.make_state(remember_me)
    url = oauth.authorize_url(
        provider, state=state,
        redirect=oauth.redirect_uri(provider, str(request.base_url)),
    )
    return RedirectResponse(url, status_code=307)


@router.get("/oauth/{provider}/callback")
async def oauth_callback(
    provider: str, request: Request,
    code: Optional[str] = None, state: Optional[str] = None,
    error: Optional[str] = None,
    db: Session = Depends(get_db),
):
    if provider not in oauth.PROVIDERS:
        raise HTTPException(status_code=404, detail="unknown provider")
    if error:
        return RedirectResponse(f"/login?oauth_error={error}", status_code=303)
    if not code or not state:
        raise HTTPException(status_code=400, detail="missing code or state")

    settings = get_settings()
    try:
        remember_me = oauth.read_state(state)
        identity = await oauth.exchange_code(
            provider, code=code,
            redirect=oauth.redirect_uri(provider, str(request.base_url)),
        )
        oauth.check_domain_allowed(identity.email)
    except oauth.OAuthError as exc:
        return RedirectResponse(f"/login?oauth_error={exc.message}",
                                status_code=303)

    try:
        user = service.upsert_oauth_user(
            db, provider=provider, subject=identity.subject,
            email=identity.email, email_verified=identity.email_verified,
            username_hint=identity.username_hint,
            default_role=settings.oauth_default_role,
        )
    except AuthError as exc:
        db.rollback()
        return RedirectResponse(f"/login?oauth_error={exc.message}",
                                status_code=303)
    if not user.is_active:
        return RedirectResponse("/login?oauth_error=account+disabled",
                                status_code=303)

    # Never put tokens in the redirect URL. Stash a one-time code, hand it to the
    # browser as an httpOnly cookie, and let the SPA trade it at /oauth/complete.
    code = service.create_oauth_handoff(
        db, user_id=user.id, remember_me=remember_me
    )
    record_audit(db, action="login.oauth", actor=user.username,
                 source_ip=_client_ip(request), detail={"provider": provider})
    db.commit()

    redirect = RedirectResponse("/login?oauth=ok", status_code=303)
    redirect.set_cookie(
        "act_oauth_handoff", code,
        max_age=120, httponly=True, samesite="lax",
        secure=get_settings().is_production, path="/",
    )
    return redirect


@router.post("/oauth/complete", response_model=TokenResponse)
def oauth_complete(
    request: Request, response: Response, db: Session = Depends(get_db)
):
    """Exchange the one-time OAuth hand-off cookie for a token pair."""
    code = request.cookies.get("act_oauth_handoff")
    response.delete_cookie("act_oauth_handoff", path="/")
    if not code:
        raise HTTPException(status_code=400, detail="no pending sign-in")
    try:
        tokens = service.redeem_oauth_handoff(
            db, code, user_agent=request.headers.get("user-agent"),
        )
    except AuthError as exc:
        db.commit()
        raise _as_http(exc)
    record_audit(db, action="login.oauth.complete", actor=tokens["username"],
                 source_ip=_client_ip(request))
    db.commit()
    return TokenResponse(**tokens)
