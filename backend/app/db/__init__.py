"""Persistence layer.

The detection pipeline still runs entirely in memory - ``EventStore`` and the
correlator are untouched. This package adds an *optional* durable store next to
it: SQLAlchemy models for users, ingested events, correlated behaviours, attack
paths, responses, reports, alerts, runtime config and the audit trail, plus an
engine with connection pooling and connect-time retry.

Public surface:

* :data:`Base`            - declarative base every model inherits from
* :func:`get_engine`      - process-wide Engine (pooled, retrying)
* :func:`session_scope`   - ``with session_scope() as s:`` transaction block
* :func:`get_db`          - FastAPI dependency yielding a session
* :func:`init_db`         - ``create_all`` for SQLite / local dev
* :func:`check_connection`- lightweight health probe
"""

from app.db.base import Base
from app.db.session import (
    check_connection,
    get_db,
    get_engine,
    get_sessionmaker,
    init_db,
    reset_engine,
    session_scope,
)

__all__ = [
    "Base",
    "check_connection",
    "get_db",
    "get_engine",
    "get_sessionmaker",
    "init_db",
    "reset_engine",
    "session_scope",
]
