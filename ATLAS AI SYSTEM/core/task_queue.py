"""DB-Backed Job Queue with Priority Scheduling, Idempotency, Retry Backoff & Runaway Guards."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import asc, desc, select
from sqlalchemy.orm import Session

from core.agent_contract import TaskInput, TaskResult
from core.agent_registry import REGISTRY
from core.audit import append_audit_log
from core.config import load_settings
from core.events import EVENT_HUB
from db.models import SystemState, TaskRecord


class TaskQueueService:
    """Manages durable DB-backed task queuing, execution, retry backoff, and cancellation."""

    def enqueue_task(
        self,
        session: Session,
        *,
        agent_name: str,
        action: str,
        parameters: Optional[Dict[str, Any]] = None,
        priority: int = 5,
        tier: str = "0",
        created_by: str = "system",
        idempotency_key: Optional[str] = None,
        decision_id: Optional[str] = None,
        scheduled_at: Optional[datetime] = None,
        estimated_cost_usd: float = 0.0,
    ) -> Dict[str, Any]:
        """Enqueue a new task or return existing task if idempotency_key matches."""
        if idempotency_key:
            existing = session.scalar(
                select(TaskRecord).where(TaskRecord.idempotency_key == idempotency_key)
            )
            if existing:
                return self.serialize_task(existing)

        sys_state = session.get(SystemState, "global")
        if sys_state and sys_state.mode == "SAFE":
            append_audit_log(
                session,
                actor=created_by,
                action="task.enqueue_blocked_safe_mode",
                target=f"agent:{agent_name}",
                tier=tier,
                outcome="DENIED",
                why="Cannot enqueue new tasks while system is in SAFE MODE",
            )
            session.flush()
            raise PermissionError("System is in SAFE MODE (read-only). Task enqueue rejected.")

        # Validate agent exists in registry
        REGISTRY.get(agent_name)

        cfg = load_settings()
        task_id = f"tsk_{uuid.uuid4().hex[:16]}"
        now = datetime.now(timezone.utc)
        sched = scheduled_at or now

        record = TaskRecord(
            id=task_id,
            agent_name=agent_name,
            action=action,
            tier=str(tier),
            priority=max(1, min(int(priority), 10)),
            status="QUEUED",
            payload_json=json.dumps(parameters or {}, sort_keys=True, default=str),
            retry_count=0,
            max_retries=cfg.max_retries_per_task,
            llm_calls_count=0,
            max_llm_calls=cfg.max_llm_calls_per_task,
            estimated_cost_usd=float(estimated_cost_usd),
            actual_cost_usd=0.0,
            idempotency_key=idempotency_key,
            decision_id=decision_id,
            created_by=created_by,
            scheduled_at=sched,
            created_at=now,
        )
        session.add(record)

        append_audit_log(
            session,
            actor=created_by,
            action="task.enqueued",
            target=task_id,
            tier=str(tier),
            outcome="SUCCESS",
            why=f"Enqueued '{action}' for agent '{agent_name}' at priority {record.priority}",
            details={
                "agent_name": agent_name,
                "action": action,
                "priority": record.priority,
                "idempotency_key": idempotency_key,
            },
        )
        EVENT_HUB.publish_sync(
            "task.enqueued",
            {"task_id": task_id, "agent_name": agent_name, "action": action, "tier": str(tier)},
        )
        session.flush()
        return self.serialize_task(record)

    def execute_next_queued_task(self, session: Session) -> Optional[Dict[str, Any]]:
        """Claim and execute the highest-priority due QUEUED task with retry & backoff."""
        sys_state = session.get(SystemState, "global")
        if sys_state and sys_state.mode == "SAFE":
            return None

        now = datetime.now(timezone.utc)
        stmt = (
            select(TaskRecord)
            .where(TaskRecord.status == "QUEUED", TaskRecord.scheduled_at <= now)
            .order_by(asc(TaskRecord.priority), asc(TaskRecord.scheduled_at))
            .limit(1)
        )
        task_rec = session.scalar(stmt)
        if not task_rec:
            return None

        return self.run_task_by_id(session, task_rec.id)

    def run_task_by_id(self, session: Session, task_id: str) -> Dict[str, Any]:
        """Execute a specific task record, enforcing schema validation and retry/escalation."""
        task_rec = session.get(TaskRecord, task_id)
        if not task_rec:
            raise KeyError(f"Task '{task_id}' not found")

        now = datetime.now(timezone.utc)
        task_rec.status = "RUNNING"
        task_rec.started_at = now
        session.flush()

        task_input = TaskInput(
            task_id=task_rec.id,
            action=task_rec.action,
            parameters=json.loads(task_rec.payload_json or "{}"),
            requester=task_rec.created_by,
            decision_id=task_rec.decision_id,
            tier=task_rec.tier,
        )

        try:
            result: TaskResult = REGISTRY.execute_agent_task(
                session,
                task_rec.agent_name,
                task_input,
                actor="system:task_queue",
            )
            task_rec.status = "COMPLETED"
            task_rec.result_json = json.dumps(result.model_dump(), sort_keys=True, default=str)
            task_rec.actual_cost_usd = float(task_rec.actual_cost_usd or 0.0) + result.actual_cost_usd
            task_rec.completed_at = datetime.now(timezone.utc)
            task_rec.error_message = None

            EVENT_HUB.publish_sync(
                "task.completed",
                {"task_id": task_rec.id, "agent_name": task_rec.agent_name, "action": task_rec.action},
            )
            session.flush()
            return self.serialize_task(task_rec)

        except NotImplementedError as exc:
            # Planned/unimplemented agents fail immediately and explicitly (never silently stubbed)
            task_rec.status = "FAILED"
            task_rec.error_message = str(exc)
            task_rec.completed_at = datetime.now(timezone.utc)
            session.flush()
            raise

        except Exception as exc:
            task_rec.retry_count += 1
            task_rec.error_message = str(exc)

            if task_rec.retry_count < task_rec.max_retries:
                backoff_seconds = 2 ** task_rec.retry_count
                task_rec.status = "QUEUED"
                task_rec.scheduled_at = datetime.now(timezone.utc) + timedelta(seconds=backoff_seconds)
                append_audit_log(
                    session,
                    actor="system:task_queue",
                    action="task.retry_scheduled",
                    target=task_rec.id,
                    tier=task_rec.tier,
                    outcome="ALERT",
                    why=f"Task failed (attempt {task_rec.retry_count}/{task_rec.max_retries}): {exc}",
                    details={"backoff_seconds": backoff_seconds},
                )
            else:
                task_rec.status = "FAILED"
                task_rec.completed_at = datetime.now(timezone.utc)
                append_audit_log(
                    session,
                    actor="system:task_queue",
                    action="task.failed_escalated",
                    target=task_rec.id,
                    tier="2",
                    outcome="FAILED",
                    why=f"Task exhausted all {task_rec.max_retries} retries and was escalated: {exc}",
                    details={"agent_name": task_rec.agent_name, "action": task_rec.action},
                )
                EVENT_HUB.publish_sync(
                    "task.failed_escalated",
                    {
                        "task_id": task_rec.id,
                        "agent_name": task_rec.agent_name,
                        "error": str(exc),
                        "retries": task_rec.retry_count,
                    },
                    severity="error",
                )

            session.flush()
            return self.serialize_task(task_rec)

    def list_tasks(
        self,
        session: Session,
        *,
        status_filter: Optional[str] = None,
        agent_name: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        stmt = select(TaskRecord).order_by(desc(TaskRecord.created_at))
        if status_filter:
            stmt = stmt.where(TaskRecord.status == status_filter.upper())
        if agent_name:
            stmt = stmt.where(TaskRecord.agent_name == agent_name)
        stmt = stmt.limit(min(max(limit, 1), 500))
        rows = session.scalars(stmt).all()
        return [self.serialize_task(r) for r in rows]

    @staticmethod
    def serialize_task(r: TaskRecord) -> Dict[str, Any]:
        def _iso(dt: Optional[datetime]) -> Optional[str]:
            if not dt:
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()

        return {
            "id": r.id,
            "agent_name": r.agent_name,
            "action": r.action,
            "tier": r.tier,
            "priority": r.priority,
            "status": r.status,
            "parameters": json.loads(r.payload_json or "{}"),
            "result": json.loads(r.result_json) if r.result_json else None,
            "error_message": r.error_message,
            "retry_count": r.retry_count,
            "max_retries": r.max_retries,
            "llm_calls_count": r.llm_calls_count,
            "max_llm_calls": r.max_llm_calls,
            "estimated_cost_usd": r.estimated_cost_usd,
            "actual_cost_usd": r.actual_cost_usd,
            "idempotency_key": r.idempotency_key,
            "decision_id": r.decision_id,
            "created_by": r.created_by,
            "scheduled_at": _iso(r.scheduled_at),
            "started_at": _iso(r.started_at),
            "completed_at": _iso(r.completed_at),
            "created_at": _iso(r.created_at),
        }


TASK_QUEUE = TaskQueueService()
