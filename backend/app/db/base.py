"""Declarative base and the shared naming convention.

The naming convention matters: without it SQLite and Postgres invent different
names for indexes and constraints, and Alembic autogenerate produces churn on
every run. With it, ``alembic revision --autogenerate`` is stable across both.
"""

from __future__ import annotations

import datetime as _dt

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def utcnow() -> _dt.datetime:
    """Timezone-aware UTC now. Used as the default for every timestamp column."""
    return _dt.datetime.now(_dt.timezone.utc)


class TimestampMixin:
    """``created_at`` maintained automatically."""

    created_at: Mapped[_dt.datetime] = mapped_column(
        default=utcnow, nullable=False
    )
