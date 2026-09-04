"""OAuth2 (Google / GitHub) - authorization-code flow, standard library + httpx.

Deliberately no Authlib: the flow is a redirect, a form POST to exchange the
code, and one userinfo request - all of which httpx (already a dependency) does
cleanly, and it keeps ACT's install free of a crypto build chain.

Inert until a provider's client id **and** secret are set. ``providers_status``
reports what is and is not configured; every endpoint degrades to a 501-style
"not configured" response otherwise.

The CSRF ``state`` is a short signed JWT (nonce + remember flag + expiry), so no
server-side session storage is needed for the round trip.
"""

from __future__ import annotations

import datetime as _dt
import logging
import secrets
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlencode

import httpx
import jwt

from app.auth.tokens import _secret  # module-internal, intentional reuse
from app.core.settings import Settings, get_settings

log = logging.getLogger("app.auth.oauth")

_HTTP_TIMEOUT = 10.0


@dataclass(frozen=True, slots=True)
class Provider:
    name: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scope: str
    emails_url: Optional[str] = None  # GitHub keeps emails on a separate route


PROVIDERS: dict[str, Provider] = {
    "google": Provider(
        name="google",
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
        scope="openid email profile",
    ),
    "github": Provider(
        name="github",
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        userinfo_url="https://api.github.com/user",
        scope="read:user user:email",
        emails_url="https://api.github.com/user/emails",
    ),
}


class OAuthError(Exception):
    def __init__(self, message: str, *, status: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


@dataclass(frozen=True, slots=True)
class OAuthIdentity:
    provider: str
    subject: str
    email: Optional[str]
    username_hint: str


def is_configured(provider: str, settings: Optional[Settings] = None) -> bool:
    settings = settings or get_settings()
    return provider in settings.oauth_providers


def providers_status(settings: Optional[Settings] = None) -> dict:
    settings = settings or get_settings()
    return {
        name: {"configured": name in settings.oauth_providers}
        for name in PROVIDERS
    }


def _client_creds(provider: str, settings: Settings) -> tuple[str, str]:
    try:
        return settings.oauth_providers[provider]
    except KeyError:
        raise OAuthError(f"{provider} OAuth is not configured", status=501)


def redirect_uri(provider: str, request_base_url: str,
                 settings: Optional[Settings] = None) -> str:
    settings = settings or get_settings()
    base = (settings.oauth_redirect_base_url or request_base_url).rstrip("/")
    return f"{base}/api/auth/oauth/{provider}/callback"


# ----------------------------------------------------------------- state token #


def make_state(remember_me: bool, settings: Optional[Settings] = None) -> str:
    settings = settings or get_settings()
    now = _dt.datetime.now(_dt.timezone.utc)
    payload = {
        "nonce": secrets.token_urlsafe(12),
        "remember_me": bool(remember_me),
        "type": "oauth_state",
        "iat": now,
        "exp": now + _dt.timedelta(minutes=10),
    }
    return jwt.encode(payload, _secret(settings), algorithm=settings.jwt_algorithm)


def read_state(state: str, settings: Optional[Settings] = None) -> bool:
    settings = settings or get_settings()
    try:
        payload = jwt.decode(state, _secret(settings),
                             algorithms=[settings.jwt_algorithm])
    except jwt.InvalidTokenError as exc:
        raise OAuthError("invalid or expired state") from exc
    if payload.get("type") != "oauth_state":
        raise OAuthError("invalid state")
    return bool(payload.get("remember_me"))


# --------------------------------------------------------------- flow helpers #


def authorize_url(provider: str, *, state: str, redirect: str,
                  settings: Optional[Settings] = None) -> str:
    settings = settings or get_settings()
    spec = PROVIDERS[provider]
    client_id, _ = _client_creds(provider, settings)
    params = {
        "client_id": client_id,
        "redirect_uri": redirect,
        "response_type": "code",
        "scope": spec.scope,
        "state": state,
    }
    if provider == "google":
        params["access_type"] = "online"
        params["prompt"] = "select_account"
    return f"{spec.authorize_url}?{urlencode(params)}"


async def exchange_code(
    provider: str, *, code: str, redirect: str,
    settings: Optional[Settings] = None,
) -> OAuthIdentity:
    settings = settings or get_settings()
    spec = PROVIDERS[provider]
    client_id, client_secret = _client_creds(provider, settings)

    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect,
        "grant_type": "authorization_code",
    }

    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        token_resp = await client.post(
            spec.token_url, data=data, headers={"Accept": "application/json"}
        )
        if token_resp.status_code >= 400:
            raise OAuthError(
                f"{provider} token exchange failed ({token_resp.status_code})"
            )
        access_token = token_resp.json().get("access_token")
        if not access_token:
            raise OAuthError(f"{provider} did not return an access token")

        auth_header = {"Authorization": f"Bearer {access_token}",
                       "Accept": "application/json"}
        info_resp = await client.get(spec.userinfo_url, headers=auth_header)
        if info_resp.status_code >= 400:
            raise OAuthError(f"{provider} userinfo failed "
                             f"({info_resp.status_code})")
        info = info_resp.json()

        email = None
        if provider == "google":
            subject = str(info.get("sub") or "")
            email = info.get("email")
            username_hint = (info.get("email") or "").split("@")[0] or "user"
        else:  # github
            subject = str(info.get("id") or "")
            email = info.get("email")
            username_hint = info.get("login") or "user"
            if not email and spec.emails_url:
                emails_resp = await client.get(spec.emails_url, headers=auth_header)
                if emails_resp.status_code < 400:
                    for entry in emails_resp.json():
                        if entry.get("primary") and entry.get("verified"):
                            email = entry.get("email")
                            break

    if not subject:
        raise OAuthError(f"{provider} did not return a stable user id")

    return OAuthIdentity(
        provider=provider,
        subject=subject,
        email=email.lower() if email else None,
        username_hint=username_hint,
    )


def check_domain_allowed(email: Optional[str],
                         settings: Optional[Settings] = None) -> None:
    settings = settings or get_settings()
    allowed = settings.oauth_allowed_domain_list
    if not allowed:
        return
    domain = (email or "").split("@")[-1].lower()
    if domain not in allowed:
        raise OAuthError(
            "your email domain is not allowed to sign in here", status=403
        )
