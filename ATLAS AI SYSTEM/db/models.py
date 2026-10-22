"""SQLAlchemy ORM Models for Atlas AI Foundation & Governance."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    event,
)
from sqlalchemy.orm import Mapped, mapped_column

from db.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuditTamperError(PermissionError):
    """Raised when any code attempts to update or delete an append-only AuditLog record."""


class SystemState(Base):
    """Singleton persistent system state for Normal vs Safe Mode (Kill Switch)."""

    __tablename__ = "system_state"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default="global")
    mode: Mapped[str] = mapped_column(String(16), nullable=False, default="NORMAL")  # NORMAL | SAFE
    kill_switch_engaged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    kill_switch_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    kill_switch_actor: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    kill_switch_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    trading_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="PAPER")  # PAPER | CANARY | LIVE
    board_execution_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)  # Advisory mode by default
    active_charter_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class AgentRecord(Base):
    """Persistent registry state, autonomy level, and health metrics for each agent."""

    __tablename__ = "agent_registry"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    layer: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    phase: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PLANNED", index=True
    )  # ACTIVE | PAUSED | SAFE_MODE_HALTED | PLANNED | ERROR | SUSPENDED
    previous_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    autonomy_level: Mapped[str] = mapped_column(
        String(8), nullable=False, default="L0"
    )  # L0 | L1 | L2 | L3
    capabilities_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    permissions_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    health_status: Mapped[str] = mapped_column(String(32), nullable=False, default="healthy")
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    cost_today_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    custom_daily_cap_usd: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    success_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_flags_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class TaskRecord(Base):
    """DB-backed job queue record."""

    __tablename__ = "task_queue"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    tier: Mapped[str] = mapped_column(String(8), nullable=False, default="0")  # 0 | 1 | 1.5 | 2 | 3
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=5, index=True)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="QUEUED", index=True
    )  # QUEUED | RUNNING | WAITING_APPROVAL | COMPLETED | FAILED | CANCELLED
    payload_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    result_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_retries: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    llm_calls_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_llm_calls: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    estimated_cost_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    actual_cost_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    idempotency_key: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, unique=True)
    decision_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    scheduled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    __table_args__ = (
        Index("ix_task_queue_status_priority_sched", "status", "priority", "scheduled_at"),
    )


class AuditLog(Base):
    """Append-only, tamper-evident hash-chained audit log.

    Updates and deletes are unconditionally blocked via SQLAlchemy ORM listeners.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(128), nullable=False)
    tier: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    why: Mapped[str] = mapped_column(Text, nullable=False)
    details_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)


@event.listens_for(AuditLog, "before_update")
def _prevent_audit_update(_mapper, _connection, _target):
    raise AuditTamperError("SECURITY VIOLATION: AuditLog is append-only and cannot be modified.")


@event.listens_for(AuditLog, "before_delete")
def _prevent_audit_delete(_mapper, _connection, _target):
    raise AuditTamperError("SECURITY VIOLATION: AuditLog is append-only and cannot be deleted.")


class LLMCallLog(Base):
    """Granular log of every LLM call routed through ModelRouter for Cost Agent enforcement."""

    __tablename__ = "llm_call_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    call_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    agent_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    model: Mapped[str] = mapped_column(String(64), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(32), nullable=False, default="v1")
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    is_mock: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    decision_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    task_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="SUCCESS")


class RefreshTokenRecord(Base):
    """Revocable SHA-256 hashed refresh tokens for single-owner dashboard sessions."""

    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    owner_email: Mapped[str] = mapped_column(String(256), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class AuthLockoutRecord(Base):
    """Tracks authentication failures by source key (IP or identifier) for lockout enforcement."""

    __tablename__ = "auth_lockouts"

    actor_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_failed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class CharterVersionRecord(Base):
    """Versioned governance Charter with optimistic concurrency control."""

    __tablename__ = "charter_versions"

    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    version_tag: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    author: Mapped[str] = mapped_column(String(128), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    charter_json: Mapped[str] = mapped_column(Text, nullable=False)
    tier_1_5_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    approved_decision_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
