"""Engine, session factory, retry and health probe.

The engine is created lazily on first use and cached for the process. SQLite
(local dev / tests) and Postgres (production) need different pool settings, so
:func:`_engine_kwargs` branches on the URL. ``pool_pre_ping`` is always on, which
transparently recovers from a Postgres connection dropped by the server.

Connect-time retry (:func:`_connect_with_retry`) covers the real-world case of
the app container starting before the database container is accepting
connections - it retries ``OperationalError`` with capped exponential backoff
before giving up.
"""

from __future__ import annotations

import contextlib
import logging
import time
from typing import Iterator, Optional

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.settings import Settings, get_settings
from app.db.base import Base

log = logging.getLogger("app.db")

_engine: Optional[Engine] = None
_Session: Optional[sessionmaker] = None


def _engine_kwargs(settings: Settings) -> dict:
    url = settings.database_url
    kwargs: dict = {"echo": settings.db_echo, "future": True}

    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url or url in ("sqlite://",):
            # One shared connection so an in-memory DB survives between sessions.
            kwargs["poolclass"] = StaticPool
        return kwargs

    # Postgres / MySQL / etc.
    kwargs.update(
        pool_pre_ping=True,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_recycle=settings.db_pool_recycle_seconds,
    )
    return kwargs


def _connect_with_retry(engine: Engine, settings: Settings) -> None:
    attempts = max(1, settings.db_connect_retries)
    delay = max(0.0, settings.db_connect_retry_backoff)

    for attempt in range(1, attempts + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            if attempt > 1:
                log.info("database reachable", extra={"attempt": attempt})
            return
        except OperationalError as exc:
            if attempt == attempts:
                log.error(
                    "database unreachable after retries",
                    extra={"attempts": attempts},
                )
                raise
            wait = min(delay * (2 ** (attempt - 1)), 10.0)
            log.warning(
                "database not ready, retrying",
                extra={"attempt": attempt, "sleep_seconds": round(wait, 2),
                       "error": str(exc.orig) if exc.orig else str(exc)},
            )
            time.sleep(wait)


def get_engine(settings: Optional[Settings] = None) -> Engine:
    """Return the process-wide Engine, creating it (with retry) on first call."""
    global _engine, _Session
    if _engine is not None:
        return _engine

    settings = settings or get_settings()
    engine = create_engine(settings.database_url, **_engine_kwargs(settings))

    if settings.is_sqlite:
        _enable_sqlite_fk(engine)

    _connect_with_retry(engine, settings)

    _engine = engine
    _Session = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    log.info("database engine ready", extra={"dialect": engine.dialect.name})
    return _engine


def _enable_sqlite_fk(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def _fk_pragma(dbapi_connection, _record):  # noqa: ANN001
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


def get_sessionmaker(settings: Optional[Settings] = None) -> sessionmaker:
    if _Session is None:
        get_engine(settings)
    assert _Session is not None
    return _Session


@contextlib.contextmanager
def session_scope(settings: Optional[Settings] = None) -> Iterator[Session]:
    """Transactional block: commit on success, roll back on any exception."""
    factory = get_sessionmaker(settings)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency. Yields a session; caller controls commit/rollback."""
    factory = get_sessionmaker()
    session = factory()
    try:
        yield session
    finally:
        session.close()


def init_db(settings: Optional[Settings] = None) -> None:
    """Create every table. For SQLite and first-run local dev only - production
    schema changes go through Alembic (``alembic upgrade head``)."""
    from app.db import models  # noqa: F401  (register mappers)

    engine = get_engine(settings)
    Base.metadata.create_all(engine)
    log.info("schema ensured", extra={"tables": len(Base.metadata.tables)})


def check_connection(settings: Optional[Settings] = None) -> dict:
    """Health probe: ``{"connected": bool, "dialect": str, "error": str|None}``."""
    try:
        engine = get_engine(settings)
        started = time.perf_counter()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {
            "connected": True,
            "dialect": engine.dialect.name,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001  (health probe must never raise)
        return {"connected": False, "dialect": None, "latency_ms": None,
                "error": str(exc)}


def reset_engine() -> None:
    """Dispose the engine and drop the cache. Tests call this between DB configs."""
    global _engine, _Session
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _Session = None
