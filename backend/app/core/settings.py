"""Typed access to the environment.

One place that reads ``os.environ`` and hands back a frozen ``Settings`` object,
so the rest of the code never sees a raw ``os.getenv`` call or has to guess a
default. Values come from the real environment first and ``backend/.env`` second
(loaded by :mod:`app.config.env` on import).

Nothing here is required. Every field has a default that keeps ACT running as
the single-user prototype it has always been - SQLite in a local file, logging
to the console, SSL off. Set the matching variable to move a piece into
production. ``backend/.env.example`` documents the full list.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from functools import lru_cache
from pathlib import Path
from typing import Optional

from app.config import env as _env  # noqa: F401  (loads backend/.env on import)

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BACKEND_DIR / "data"


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def _str(name: str, default: str) -> str:
    raw = os.environ.get(name)
    return raw if raw is not None and raw.strip() != "" else default


def _opt(name: str) -> Optional[str]:
    raw = os.environ.get(name)
    return raw if raw is not None and raw.strip() != "" else None


def _default_database_url() -> str:
    """SQLite in ``backend/data/act.db`` unless ``DATABASE_URL`` overrides it."""
    explicit = _opt("DATABASE_URL")
    if explicit:
        return explicit
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{(DATA_DIR / 'act.db').as_posix()}"


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable snapshot of the environment. Build it with :func:`get_settings`."""

    # --- environment ---------------------------------------------------------
    env: str = field(default_factory=lambda: _str("ACT_ENV", "development"))

    # --- database ----------------------------------------------------------
    database_url: str = field(default_factory=_default_database_url)
    db_pool_size: int = field(default_factory=lambda: _int("ACT_DB_POOL_SIZE", 5))
    db_max_overflow: int = field(default_factory=lambda: _int("ACT_DB_MAX_OVERFLOW", 10))
    db_pool_recycle_seconds: int = field(
        default_factory=lambda: _int("ACT_DB_POOL_RECYCLE", 1800)
    )
    db_connect_retries: int = field(default_factory=lambda: _int("ACT_DB_CONNECT_RETRIES", 5))
    db_connect_retry_backoff: float = field(
        default_factory=lambda: float(_str("ACT_DB_CONNECT_RETRY_BACKOFF", "0.5"))
    )
    db_echo: bool = field(default_factory=lambda: _bool("ACT_DB_ECHO", False))

    # --- logging ---------------------------------------------------------
    log_level: str = field(default_factory=lambda: _str("ACT_LOG_LEVEL", "INFO").upper())
    log_format: str = field(default_factory=lambda: _str("ACT_LOG_FORMAT", "console").lower())
    log_file: Optional[str] = field(default_factory=lambda: _opt("ACT_LOG_FILE"))
    log_file_max_bytes: int = field(
        default_factory=lambda: _int("ACT_LOG_FILE_MAX_BYTES", 10 * 1024 * 1024)
    )
    log_file_backup_count: int = field(
        default_factory=lambda: _int("ACT_LOG_FILE_BACKUP_COUNT", 5)
    )

    # --- HTTP service --------------------------------------------------------
    host: str = field(default_factory=lambda: _str("ACT_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _int("ACT_PORT", 8000))

    # --- authentication ----------------------------------------------------
    # On by default: every /api route needs a bearer token except the auth
    # endpoints and /api/health. Set ACT_AUTH_ENABLED=false only for the old
    # single-user prototype mode (the test suite does this).
    auth_enabled: bool = field(default_factory=lambda: _bool("ACT_AUTH_ENABLED", True))
    jwt_secret: Optional[str] = field(default_factory=lambda: _opt("ACT_JWT_SECRET"))
    jwt_algorithm: str = field(default_factory=lambda: _str("ACT_JWT_ALGORITHM", "HS256"))
    access_token_ttl_minutes: int = field(
        default_factory=lambda: _int("ACT_ACCESS_TOKEN_TTL_MIN", 30)
    )
    refresh_token_ttl_days: int = field(
        default_factory=lambda: _int("ACT_REFRESH_TOKEN_TTL_DAYS", 7)
    )
    refresh_token_remember_days: int = field(
        default_factory=lambda: _int("ACT_REFRESH_TOKEN_REMEMBER_DAYS", 30)
    )
    # First-run admin. If the password is unset one is generated and logged once.
    bootstrap_admin_username: str = field(
        default_factory=lambda: _str("ACT_ADMIN_USERNAME", "admin")
    )
    bootstrap_admin_password: Optional[str] = field(
        default_factory=lambda: _opt("ACT_ADMIN_PASSWORD")
    )

    # --- OAuth2 (scaffold; inert unless a client id + secret are set) ------
    oauth_google_client_id: Optional[str] = field(
        default_factory=lambda: _opt("ACT_OAUTH_GOOGLE_CLIENT_ID")
    )
    oauth_google_client_secret: Optional[str] = field(
        default_factory=lambda: _opt("ACT_OAUTH_GOOGLE_CLIENT_SECRET")
    )
    oauth_github_client_id: Optional[str] = field(
        default_factory=lambda: _opt("ACT_OAUTH_GITHUB_CLIENT_ID")
    )
    oauth_github_client_secret: Optional[str] = field(
        default_factory=lambda: _opt("ACT_OAUTH_GITHUB_CLIENT_SECRET")
    )
    oauth_redirect_base_url: Optional[str] = field(
        default_factory=lambda: _opt("ACT_OAUTH_REDIRECT_BASE_URL")
    )
    # Comma-separated allowlist of email domains for first-time OAuth sign-ins.
    oauth_allowed_domains: str = field(
        default_factory=lambda: _str("ACT_OAUTH_ALLOWED_DOMAINS", "")
    )
    oauth_default_role: str = field(
        default_factory=lambda: _str("ACT_OAUTH_DEFAULT_ROLE", "viewer")
    )

    # --- SSL (wired up in a later phase; recorded here so one loader owns it) --
    ssl_enabled: bool = field(default_factory=lambda: _bool("ACT_SSL_ENABLED", False))
    ssl_cert: Optional[str] = field(default_factory=lambda: _opt("ACT_SSL_CERT"))
    ssl_key: Optional[str] = field(default_factory=lambda: _opt("ACT_SSL_KEY"))
    force_https: bool = field(default_factory=lambda: _bool("ACT_FORCE_HTTPS", False))

    # --- CORS ------------------------------------------------------------
    # Comma-separated origin allowlist. Empty -> localhost dev origins only.
    # "*" is honoured (with a warning) but disables credentialed requests.
    cors_origins: str = field(default_factory=lambda: _str("ACT_CORS_ORIGINS", ""))
    cors_allow_credentials: bool = field(
        default_factory=lambda: _bool("ACT_CORS_ALLOW_CREDENTIALS", False)
    )

    # --- rate limiting (in-process, per client IP) ---------------------------
    rate_limit_enabled: bool = field(
        default_factory=lambda: _bool("ACT_RATE_LIMIT_ENABLED", True)
    )
    rate_limit_per_minute: int = field(
        default_factory=lambda: _int("ACT_RATE_LIMIT_PER_MIN", 240)
    )
    # Tighter bucket for the credential endpoints (login / refresh).
    rate_limit_auth_per_minute: int = field(
        default_factory=lambda: _int("ACT_RATE_LIMIT_AUTH_PER_MIN", 12)
    )
    # Trust X-Forwarded-For (only behind a proxy you control).
    trust_forwarded_for: bool = field(
        default_factory=lambda: _bool("ACT_TRUST_FORWARDED_FOR", False)
    )

    # --- metrics -----------------------------------------------------------
    metrics_enabled: bool = field(
        default_factory=lambda: _bool("ACT_METRICS_ENABLED", True)
    )
    # If set, /api/metrics requires ?token=<this> (or a matching bearer).
    metrics_token: Optional[str] = field(default_factory=lambda: _opt("ACT_METRICS_TOKEN"))

    # --- persistence of pipeline output ----------------------------------
    persist_enabled: bool = field(
        default_factory=lambda: _bool("ACT_PERSIST_ENABLED", True)
    )

    @property
    def is_production(self) -> bool:
        return self.env.lower() in {"production", "prod"}

    @property
    def cors_origin_list(self) -> list[str]:
        raw = [o.strip() for o in self.cors_origins.split(",") if o.strip()]
        if raw:
            return raw
        # sensible default: the app talking to itself + file:// (null origin)
        return [
            "http://localhost:8000", "http://127.0.0.1:8000",
            "https://localhost:8000", "https://127.0.0.1:8000",
        ]

    @property
    def oauth_providers(self) -> dict[str, tuple[str, str]]:
        """``{provider: (client_id, client_secret)}`` for fully-configured ones."""
        out: dict[str, tuple[str, str]] = {}
        if self.oauth_google_client_id and self.oauth_google_client_secret:
            out["google"] = (self.oauth_google_client_id,
                             self.oauth_google_client_secret)
        if self.oauth_github_client_id and self.oauth_github_client_secret:
            out["github"] = (self.oauth_github_client_id,
                             self.oauth_github_client_secret)
        return out

    @property
    def oauth_allowed_domain_list(self) -> list[str]:
        return [d.strip().lower() for d in self.oauth_allowed_domains.split(",")
                if d.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    def redacted(self) -> dict:
        """Every field as a dict, with the database password masked."""
        out = {}
        for f in fields(self):
            out[f.name] = getattr(self, f.name)
        out["database_url"] = _mask_url_password(self.database_url)
        return out


def _mask_url_password(url: str) -> str:
    # postgresql://user:secret@host/db  ->  postgresql://user:***@host/db
    if "@" not in url or "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    creds, tail = rest.split("@", 1)
    if ":" in creds:
        user, _pw = creds.split(":", 1)
        creds = f"{user}:***"
    return f"{scheme}://{creds}@{tail}"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton. Call :func:`reload_settings` in tests."""
    return Settings()


def reload_settings() -> Settings:
    """Drop the cached snapshot and read the environment again (tests use this)."""
    get_settings.cache_clear()
    return get_settings()
