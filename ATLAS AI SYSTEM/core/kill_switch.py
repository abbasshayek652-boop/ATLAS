"""Independent Emergency Kill Switch & Safe Mode Control Plane.

Rule 7:
- One API call halts all active agents, cancels all pending/queued/running jobs,
  and sets the system to SAFE MODE (read-only).
- Operates directly on the durable database and registry without depending on Atlas CEO.
- Resuming from SAFE MODE requires Chairman authentication with fresh (<5 min) Step-Up
  verification and Tier 2 authorization.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.agent_contract import AgentOperationalStatus
from core.agent_registry import REGISTRY
from core.audit import append_audit_log
from core.events import EVENT_HUB
from db.models import AgentRecord, SystemState, TaskRecord


def ensure_system_state(session: Session) -> SystemState:
    """Get or initialize the singleton SystemState record."""
    state = session.get(SystemState, "global")
    if state is None:
        state = SystemState(
            id="global",
            mode="NORMAL",
            kill_switch_engaged=False,
            trading_mode="PAPER",
            board_execution_enabled=False,
            active_charter_version=1,
            started_at=datetime.now(timezone.utc),
        )
        session.add(state)
        session.flush()
    return state


def engage_kill_switch(
    session: Session,
    *,
    actor: str,
    reason: str = "Emergency kill switch triggered",
) -> Dict[str, Any]:
    """Halt all active agents, cancel pending tasks, and transition system to SAFE MODE."""
    state = ensure_system_state(session)
    REGISTRY.sync_to_db(session)
    now = datetime.now(timezone.utc)

    state.mode = "SAFE"
    state.kill_switch_engaged = True
    state.kill_switch_reason = reason
    state.kill_switch_actor = actor
    state.kill_switch_at = now
    state.updated_at = now

    # Cancel all QUEUED, RUNNING, or WAITING_APPROVAL tasks
    pending_tasks = session.scalars(
        select(TaskRecord).where(
            TaskRecord.status.in_(["QUEUED", "RUNNING", "WAITING_APPROVAL"])
        )
    ).all()
    cancelled_task_ids = []
    for task in pending_tasks:
        task.status = "CANCELLED"
        task.error_message = f"Cancelled by emergency kill switch ({actor}): {reason}"
        task.completed_at = now
        cancelled_task_ids.append(task.id)

    # Halt all non-planned agents
    agent_rows = session.scalars(select(AgentRecord)).all()
    halted_agents = []
    for rec in agent_rows:
        if rec.status in (
            AgentOperationalStatus.ACTIVE.value,
            AgentOperationalStatus.PAUSED.value,
        ):
            rec.previous_status = rec.status
            rec.status = AgentOperationalStatus.SAFE_MODE_HALTED.value
            rec.health_status = "degraded"
            halted_agents.append(rec.name)
            try:
                REGISTRY.get(rec.name).status = AgentOperationalStatus.SAFE_MODE_HALTED
            except KeyError:
                pass

    append_audit_log(
        session,
        actor=actor,
        action="system.kill_switch_engaged",
        target="system:global",
        tier="0",
        outcome="HALTED",
        why=reason,
        details={
            "cancelled_tasks_count": len(cancelled_task_ids),
            "halted_agents_count": len(halted_agents),
            "halted_agents": halted_agents,
        },
    )
    EVENT_HUB.publish_sync(
        "system.kill_switch_engaged",
        {
            "mode": "SAFE",
            "actor": actor,
            "reason": reason,
            "cancelled_tasks_count": len(cancelled_task_ids),
            "halted_agents_count": len(halted_agents),
        },
        severity="critical",
    )
    session.flush()

    return {
        "mode": "SAFE",
        "kill_switch_engaged": True,
        "actor": actor,
        "reason": reason,
        "engaged_at": now.isoformat(),
        "cancelled_tasks_count": len(cancelled_task_ids),
        "halted_agents_count": len(halted_agents),
    }


def resume_from_safe_mode(
    session: Session,
    *,
    actor: str,
    reason: str = "Chairman authorized resume from SAFE MODE",
) -> Dict[str, Any]:
    """Leave SAFE MODE and restore previously active agents (Tier 2 Chairman + Step-Up required)."""
    state = ensure_system_state(session)
    REGISTRY.sync_to_db(session)
    now = datetime.now(timezone.utc)

    state.mode = "NORMAL"
    state.kill_switch_engaged = False
    state.updated_at = now

    agent_rows = session.scalars(
        select(AgentRecord).where(
            AgentRecord.status == AgentOperationalStatus.SAFE_MODE_HALTED.value
        )
    ).all()
    restored_agents = []
    for rec in agent_rows:
        target_status = rec.previous_status or AgentOperationalStatus.ACTIVE.value
        if target_status == AgentOperationalStatus.SAFE_MODE_HALTED.value:
            target_status = AgentOperationalStatus.ACTIVE.value
        rec.status = target_status
        rec.health_status = "healthy" if target_status == AgentOperationalStatus.ACTIVE.value else "degraded"
        restored_agents.append(rec.name)
        try:
            REGISTRY.get(rec.name).status = AgentOperationalStatus(target_status)
        except (KeyError, ValueError):
            pass

    append_audit_log(
        session,
        actor=actor,
        action="system.resumed_from_safe_mode",
        target="system:global",
        tier="2",
        outcome="SUCCESS",
        why=reason,
        details={"restored_agents": restored_agents},
    )
    EVENT_HUB.publish_sync(
        "system.resumed",
        {
            "mode": "NORMAL",
            "actor": actor,
            "reason": reason,
            "restored_agents_count": len(restored_agents),
        },
        severity="info",
    )
    session.flush()

    return {
        "mode": "NORMAL",
        "kill_switch_engaged": False,
        "actor": actor,
        "reason": reason,
        "resumed_at": now.isoformat(),
        "restored_agents_count": len(restored_agents),
    }
