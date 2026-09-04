"""SQLAlchemy ORM models - the durable mirror of the pipeline's dataclasses.

These are storage records, not domain objects. The detection code keeps working
with the plain dataclasses in :mod:`app.models`; a later phase adds thin
mappers (dataclass <-> row) at the API boundary. Keeping them separate means the
pipeline never grows a database import.

List/dict columns use the generic ``JSON`` type, which is a real ``jsonb`` on
Postgres and a text column on SQLite - identical Python API either way.
"""

from __future__ import annotations

import datetime as _dt
import enum
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, backref, mapped_column, relationship

from app.db.base import Base, utcnow


class Role(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


def _ts(**kw: Any) -> Mapped[_dt.datetime]:
    return mapped_column(DateTime(timezone=True), **kw)


# --------------------------------------------------------------------- users #


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[Optional[str]] = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[Optional[str]] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default=Role.viewer.value, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # OAuth2 link (null for local accounts). Scaffold for a later phase.
    oauth_provider: Mapped[Optional[str]] = mapped_column(String(32))
    oauth_subject: Mapped[Optional[str]] = mapped_column(String(255))

    created_at: Mapped[_dt.datetime] = _ts(default=utcnow, nullable=False)
    last_login: Mapped[Optional[_dt.datetime]] = _ts()

    __table_args__ = (
        UniqueConstraint("oauth_provider", "oauth_subject",
                         name="uq_users_oauth_identity"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<User {self.username!r} role={self.role}>"


class RefreshToken(Base):
    """Server-side record of an issued refresh token (rotation + revocation)."""

    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    issued_at: Mapped[_dt.datetime] = _ts(default=utcnow, nullable=False)
    expires_at: Mapped[_dt.datetime] = _ts(nullable=False)
    revoked_at: Mapped[Optional[_dt.datetime]] = _ts()
    user_agent: Mapped[Optional[str]] = mapped_column(String(256))
    remember_me: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    user: Mapped[User] = relationship(
        backref=backref("refresh_tokens", passive_deletes=True)
    )


class OAuthHandoff(Base):
    """One-time code bridging an OAuth callback redirect and the SPA.

    The callback cannot hand the SPA a token in the URL (it would land in
    browser history), so it stores this short-lived, single-use row and sets an
    httpOnly cookie holding the raw code. The SPA immediately trades it via
    ``POST /api/auth/oauth/complete``.
    """

    __tablename__ = "oauth_handoffs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    remember_me: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[_dt.datetime] = _ts(default=utcnow, nullable=False)
    expires_at: Mapped[_dt.datetime] = _ts(nullable=False)
    consumed_at: Mapped[Optional[_dt.datetime]] = _ts()

    user: Mapped[User] = relationship()


# ------------------------------------------------------------------- events #


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[_dt.datetime] = _ts(default=utcnow, nullable=False, index=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    user: Mapped[Optional[str]] = mapped_column(String(128), index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    raw_log: Mapped[Optional[str]] = mapped_column(Text)
    attack_id: Mapped[Optional[str]] = mapped_column(String(128), index=True)

    __table_args__ = (
        Index("ix_events_type_ts", "event_type", "timestamp"),
    )


# ---------------------------------------------------------------- behaviors #


class Behavior(Base):
    __tablename__ = "behaviors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_ids: Mapped[list[int]] = mapped_column(JSON, default=list)
    behavior_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    kill_chain_stage: Mapped[Optional[str]] = mapped_column(String(48))
    evidence: Mapped[list[Any]] = mapped_column(JSON, default=list)
    created_at: Mapped[_dt.datetime] = _ts(default=utcnow, nullable=False, index=True)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)


# --------------------------------------------------------------- attack paths #


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    attacker_ip: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    behavior_ids: Mapped[list[int]] = mapped_column(JSON, default=list)
    path_type: Mapped[Optional[str]] = mapped_column(String(64))
    stages: Mapped[list[Any]] = mapped_column(JSON, default=list)
    compromised: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[_dt.datetime] = _ts(default=utcnow, nullable=False, index=True)


# ----------------------------------------------------------------- responses #


class Response(Base):
    __tablename__ = "responses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    attacker_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action_type: Mapped[str] = mapped_column(String(48), nullable=False)
    command: Mapped[Optional[str]] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(24), default="pending", nullable=False, index=True)
    executed_at: Mapped[Optional[_dt.datetime]] = _ts()
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[_dt.datetime] = _ts(default=utcnow, nullable=False)


# ------------------------------------------------------------------- reports #


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    attack_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    report_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    format: Mapped[str] = mapped_column(String(8), default="html", nullable=False)
    generated_at: Mapped[_dt.datetime] = _ts(default=utcnow, nullable=False, index=True)


# -------------------------------------------------------------------- alerts #


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    behavior_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("behaviors.id", ondelete="SET NULL"), index=True
    )
    platform: Mapped[str] = mapped_column(String(32), default="telegram", nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="pending", nullable=False, index=True)
    sent_at: Mapped[Optional[_dt.datetime]] = _ts()
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    behavior: Mapped[Optional[Behavior]] = relationship()


# -------------------------------------------------------------------- config #


class Config(Base):
    __tablename__ = "config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    value: Mapped[Any] = mapped_column(JSON)
    updated_at: Mapped[_dt.datetime] = _ts(default=utcnow, onupdate=utcnow, nullable=False)


# ---------------------------------------------------------------- audit log #


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[_dt.datetime] = _ts(default=utcnow, nullable=False, index=True)
    actor: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target: Mapped[Optional[str]] = mapped_column(String(255))
    source_ip: Mapped[Optional[str]] = mapped_column(String(64))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


ALL_MODELS = [
    User, RefreshToken, OAuthHandoff, Event, Behavior, AttackPath,
    Response, Report, Alert, Config, AuditLog,
]
