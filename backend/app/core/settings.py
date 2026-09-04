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

    # --- SSL (wired up in a later phase; recorded here so one loader owns it) --
    ssl_enabled: bool = field(default_factory=lambda: _bool("ACT_SSL_ENABLED", False))
    ssl_cert: Optional[str] = field(default_factory=lambda: _opt("ACT_SSL_CERT"))
    ssl_key: Optional[str] = field(default_factory=lambda: _opt("ACT_SSL_KEY"))
    force_https: bool = field(default_factory=lambda: _bool("ACT_FORCE_HTTPS", False))

    @property
    def is_production(self) -> bool:
        return self.env.lower() in {"production", "prod"}

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
