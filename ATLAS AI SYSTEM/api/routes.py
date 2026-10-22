"""FastAPI /api/v1 Router for Atlas AI Control Plane."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.schemas import (
    AgentControlRequest,
    ApprovalActionRequest,
    CharterUpdateRequest,
    CreateTaskRequest,
    GoogleLoginRequest,
    KillSwitchRequest,
    LimitsUpdateRequest,
    RefreshTokenRequest,
    ResumeRequest,
    TokenBundleResponse,
)
from core.agent_contract import TaskInput
from core.agent_registry import REGISTRY
from core.audit import append_audit_log, list_audit_logs, verify_audit_chain
from core.charter import (
    ensure_active_charter,
    get_active_charter_view,
    list_charter_versions,
    update_charter_by_chairman,
)
from core.config import load_settings
from core.kill_switch import (
    engage_kill_switch,
    ensure_system_state,
    resume_from_safe_mode,
)
from core.model_router import ModelRouter
from core.security import (
    AuthPrincipal,
    get_current_principal,
    login_with_google_id_token,
    refresh_access_token,
    require_scope,
    revoke_refresh_token,
)
from core.task_queue import TASK_QUEUE
from db.database import get_db
from db.models import TaskRecord

router = APIRouter(prefix="/api/v1", tags=["v1"])


# --- Health & System Status ---


@router.get("/health", summary="System & dependency health check")
def health_check(session: Session = Depends(get_db)) -> Dict[str, Any]:
    state = ensure_system_state(session)
    REGISTRY.sync_to_db(session)
    ensure_active_charter(session)
    session.commit()

    audit_integrity = verify_audit_chain(session)
    model_router = ModelRouter()

    return {
        "status": "healthy" if audit_integrity["valid"] else "degraded",
        "mode": state.mode,
        "kill_switch_engaged": state.kill_switch_engaged,
        "database": "connected",
        "audit_chain_valid": audit_integrity["valid"],
        "audit_entries_checked": audit_integrity["checked_count"],
        "model_router": model_router.providers["gemini"].health(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/status", summary="Get system state, mode (NORMAL/SAFE), uptime, and summary counts")
def get_system_status(
    principal: AuthPrincipal = Depends(require_scope("read:status")),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    state = ensure_system_state(session)
    REGISTRY.sync_to_db(session)
    charter = ensure_active_charter(session)
    session.commit()

    now = datetime.now(timezone.utc)
    started = state.started_at
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    uptime_seconds = max(0, int((now - started).total_seconds()))

    agents = REGISTRY.get_agent_views(session)
    active_count = sum(1 for a in agents if a["status"] == "ACTIVE")
    planned_count = sum(1 for a in agents if a["status"] == "PLANNED")
    paused_count = sum(1 for a in agents if a["status"] == "PAUSED")
    halted_count = sum(1 for a in agents if a["status"] == "SAFE_MODE_HALTED")
    unhealthy_count = sum(1 for a in agents if a["health"] == "unhealthy")

    queued_tasks = session.scalar(
        select(func.count()).select_from(TaskRecord).where(TaskRecord.status == "QUEUED")
    ) or 0

    model_router = ModelRouter()
    spend = model_router.get_spend_summary(session)

    return {
        "mode": state.mode,
        "kill_switch_engaged": state.kill_switch_engaged,
        "kill_switch_reason": state.kill_switch_reason,
        "trading_mode": state.trading_mode,
        "board_mode": "EXECUTION_ENABLED" if state.board_execution_enabled else "ADVISORY",
        "active_charter_version": charter.version,
        "uptime_seconds": uptime_seconds,
        "agents_summary": {
            "total": len(agents),
            "active": active_count,
            "planned": planned_count,
            "paused": paused_count,
            "safe_mode_halted": halted_count,
            "unhealthy": unhealthy_count,
        },
        "queued_tasks_count": int(queued_tasks),
        "pending_approvals_count": 0,
        "cost_today_usd": spend["global_daily_spend_usd"],
        "daily_budget_usd": spend["global_daily_budget_usd"],
        "caller": principal.actor,
        "timestamp": now.isoformat(),
    }


# --- Authentication & Step-Up Verification ---


@router.post(
    "/auth/google",
    response_model=TokenBundleResponse,
    summary="Single-owner Google OAuth 2.0 login (OWNER_EMAIL allowlist)",
)
def auth_google_login(
    body: GoogleLoginRequest,
    request: Request,
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    client_ip = request.client.host if request.client else "unknown"
    return login_with_google_id_token(
        session,
        id_token_str=body.id_token,
        client_ip=client_ip,
        is_step_up_flow=False,
    )


@router.post(
    "/auth/step-up",
    response_model=TokenBundleResponse,
    summary="Step-up verification via fresh Google re-authentication (valid for 5 minutes)",
)
def auth_google_step_up(
    body: GoogleLoginRequest,
    request: Request,
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    client_ip = request.client.host if request.client else "unknown"
    return login_with_google_id_token(
        session,
        id_token_str=body.id_token,
        client_ip=client_ip,
        is_step_up_flow=True,
    )


@router.post(
    "/auth/refresh",
    response_model=TokenBundleResponse,
    summary="Rotate refresh token and issue a new short-lived access token",
)
def auth_refresh_token(
    body: RefreshTokenRequest,
    request: Request,
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    client_ip = request.client.host if request.client else "unknown"
    return refresh_access_token(
        session,
        raw_refresh_token=body.refresh_token,
        client_ip=client_ip,
    )


@router.post("/auth/revoke", summary="Revoke a refresh token")
def auth_revoke_token(
    body: RefreshTokenRequest,
    principal: AuthPrincipal = Depends(get_current_principal),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    revoke_refresh_token(
        session,
        raw_refresh_token=body.refresh_token,
        actor=principal.actor,
    )
    return {"revoked": True}


# --- Kill Switch & Safe Mode Resume ---


@router.post(
    "/kill-switch",
    summary="Emergency Kill Switch: halt all agents, cancel pending jobs, enter SAFE MODE",
)
def trigger_kill_switch(
    body: Optional[KillSwitchRequest] = None,
    principal: AuthPrincipal = Depends(require_scope("execute:kill_switch")),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    reason = body.reason if body else "Emergency kill switch triggered"
    result = engage_kill_switch(session, actor=principal.actor, reason=reason)
    session.commit()
    return result


@router.post(
    "/resume",
    summary="Leave SAFE MODE and restore halted agents (Chairman + 5-min Step-Up required)",
)
def trigger_resume(
    body: Optional[ResumeRequest] = None,
    principal: AuthPrincipal = Depends(require_scope("execute:resume", require_step_up=True)),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    reason = body.reason if body else "Chairman authorized resume from SAFE MODE"
    result = resume_from_safe_mode(session, actor=principal.actor, reason=reason)
    session.commit()
    return result


# --- Agents Registry & Controls ---


@router.get("/agents", summary="List all registered catalog agents with layer, status, health, autonomy, and cost")
def list_agents_endpoint(
    layer: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    principal: AuthPrincipal = Depends(require_scope("read:all")),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    agents = REGISTRY.get_agent_views(session)
    session.commit()
    if layer:
        agents = [a for a in agents if a["layer"].lower() == layer.lower()]
    if status_filter:
        agents = [a for a in agents if a["status"].upper() == status_filter.upper()]
    return {"count": len(agents), "agents": agents}


@router.post("/agents/{name}/pause", summary="Pause an active agent")
def pause_agent_endpoint(
    name: str,
    body: Optional[AgentControlRequest] = None,
    principal: AuthPrincipal = Depends(require_scope("write:agents")),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    try:
        res = REGISTRY.pause_agent(
            session,
            name,
            actor=principal.actor,
            reason=body.reason if body else "Manual pause via API",
        )
        session.commit()
        return res
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/agents/{name}/resume", summary="Resume a paused agent")
def resume_agent_endpoint(
    name: str,
    body: Optional[AgentControlRequest] = None,
    principal: AuthPrincipal = Depends(require_scope("write:agents")),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    try:
        res = REGISTRY.resume_agent(
            session,
            name,
            actor=principal.actor,
            reason=body.reason if body else "Manual resume via API",
        )
        session.commit()
        return res
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/agents/{name}/run", summary="Execute a governed task on an agent")
def run_agent_direct_endpoint(
    name: str,
    action: str = Query(..., min_length=1),
    principal: AuthPrincipal = Depends(require_scope("write:tasks")),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    task = TaskInput(
        task_id=f"tsk_{uuid.uuid4().hex[:12]}",
        action=action,
        parameters={},
        requester=principal.actor,
        tier="0",
    )
    try:
        result = REGISTRY.execute_agent_task(session, name, task, actor=principal.actor)
        session.commit()
        return result.model_dump()
    except KeyError as exc:
        session.commit()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except NotImplementedError as exc:
        session.commit()
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)) from exc
    except PermissionError as exc:
        session.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc


# --- Task Queue ---


@router.get("/tasks", summary="List tasks in the DB-backed job queue")
def get_tasks_endpoint(
    status_filter: Optional[str] = Query(default=None, alias="status"),
    agent_name: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    principal: AuthPrincipal = Depends(require_scope("read:status")),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    tasks = TASK_QUEUE.list_tasks(
        session,
        status_filter=status_filter,
        agent_name=agent_name,
        limit=limit,
    )
    return {"count": len(tasks), "tasks": tasks}


@router.post("/tasks", status_code=status.HTTP_201_CREATED, summary="Enqueue a task in the DB-backed job queue")
def create_task_endpoint(
    body: CreateTaskRequest,
    principal: AuthPrincipal = Depends(require_scope("create:low_tier_task")),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    # Machine token can ONLY create low-tier (Tier 0 or Tier 1) tasks
    if principal.principal_type == "machine" and body.tier not in ("0", "1"):
        append_audit_log(
            session,
            actor=principal.actor,
            action="task.machine_high_tier_denied",
            target=f"agent:{body.agent_name}",
            tier=body.tier,
            outcome="DENIED",
            why=f"Machine token is forbidden from creating Tier {body.tier} tasks",
        )
        session.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Machine token is scoped to low-tier (Tier 0/1) tasks only.",
        )

    try:
        task_dict = TASK_QUEUE.enqueue_task(
            session,
            agent_name=body.agent_name,
            action=body.action,
            parameters=body.parameters,
            priority=body.priority,
            tier=body.tier,
            created_by=principal.actor,
            idempotency_key=body.idempotency_key,
            estimated_cost_usd=body.estimated_cost_usd,
        )
        session.commit()
        return task_dict
    except KeyError as exc:
        session.commit()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        session.commit()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.post("/tasks/process-next", summary="Claim and execute the highest-priority queued task")
def process_next_task_endpoint(
    principal: AuthPrincipal = Depends(require_scope("write:tasks")),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    try:
        res = TASK_QUEUE.execute_next_queued_task(session)
        session.commit()
        return {"processed": res is not None, "task": res}
    except NotImplementedError as exc:
        session.commit()
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)) from exc


# --- Costs & Budgets ---


@router.get("/costs", summary="Get daily/monthly spend by agent, by provider, and vs budget caps")
def get_costs_endpoint(
    principal: AuthPrincipal = Depends(require_scope("read:all")),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    router_svc = ModelRouter()
    return router_svc.get_spend_summary(session)


# --- Audit Log ---


@router.get("/audit", summary="Read-only tamper-evident audit log with filtering and pagination")
def get_audit_endpoint(
    actor: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
    outcome: Optional[str] = Query(default=None),
    tier: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: AuthPrincipal = Depends(require_scope("read:all")),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    entries = list_audit_logs(
        session,
        actor=actor,
        action=action,
        outcome=outcome,
        tier=tier,
        limit=limit,
        offset=offset,
    )
    return {"count": len(entries), "limit": limit, "offset": offset, "entries": entries}


@router.get("/audit/verify", summary="Verify cryptographic SHA-256 hash chain integrity of the audit log")
def verify_audit_endpoint(
    principal: AuthPrincipal = Depends(require_scope("read:all")),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    return verify_audit_chain(session)


# --- Charter & Settings Limits (Chairman + Step-Up Required) ---


@router.get("/charter", summary="Get active Charter and version history")
def get_charter_endpoint(
    principal: AuthPrincipal = Depends(require_scope("read:all")),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    active = get_active_charter_view(session)
    history = list_charter_versions(session)
    session.commit()
    return {"active": active, "history": history}


@router.put(
    "/charter",
    summary="Update the governance Charter (Chairman + 5-min Step-Up + optimistic version check required)",
)
def update_charter_endpoint(
    body: CharterUpdateRequest,
    principal: AuthPrincipal = Depends(require_scope("write:charter", require_step_up=True)),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    try:
        updated = update_charter_by_chairman(
            session,
            actor=principal.actor,
            expected_version=body.expected_version,
            rationale=body.rationale,
            updated_charter=body.updated_charter,
            tier_1_5_enabled=body.tier_1_5_enabled,
            explicit_confirmation=body.explicit_confirmation,
        )
        session.commit()
        return updated
    except PermissionError as exc:
        session.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        session.commit()
        code = (
            status.HTTP_409_CONFLICT
            if "version conflict" in str(exc).lower()
            else status.HTTP_400_BAD_REQUEST
        )
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.put(
    "/settings/limits",
    summary="Update budget caps and escalation thresholds (Tier 2 Chairman + 5-min Step-Up required)",
)
def update_limits_endpoint(
    body: LimitsUpdateRequest,
    principal: AuthPrincipal = Depends(require_scope("write:limits", require_step_up=True)),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    budget_updates: Dict[str, Any] = {}
    for field_name in (
        "global_daily_budget_usd",
        "global_monthly_budget_usd",
        "per_agent_daily_share_cap",
        "board_daily_budget_usd",
        "tier2_action_cost_threshold_usd",
    ):
        val = getattr(body, field_name)
        if val is not None:
            budget_updates[field_name] = val

    try:
        updated = update_charter_by_chairman(
            session,
            actor=principal.actor,
            expected_version=body.expected_version,
            rationale=body.rationale,
            updated_charter={"budgets_and_limits": budget_updates},
            explicit_confirmation=body.explicit_confirmation,
        )
        session.commit()
        return updated
    except ValueError as exc:
        session.commit()
        code = (
            status.HTTP_409_CONFLICT
            if "version conflict" in str(exc).lower()
            else status.HTTP_400_BAD_REQUEST
        )
        raise HTTPException(status_code=code, detail=str(exc)) from exc


# --- Phase 1+ Endpoints (Auth-guarded now; raise NotImplementedError in Phase 0 per Checkpoint Rule 3) ---


@router.get("/decisions", summary="Query decision log with tier and status filters (Phase 1)")
def get_decisions_endpoint(
    tier: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    principal: AuthPrincipal = Depends(require_scope("read:all")),
) -> Dict[str, Any]:
    raise NotImplementedError(
        "Decision Engine endpoint GET /api/v1/decisions is scheduled for Phase 1. Listed in STATUS.md."
    )


@router.get("/approvals", summary="List Tier 2 approval inbox items (Phase 1)")
def get_approvals_endpoint(
    status_filter: str = Query(default="pending", alias="status"),
    principal: AuthPrincipal = Depends(require_scope("read:all")),
) -> Dict[str, Any]:
    raise NotImplementedError(
        "Approval Inbox endpoint GET /api/v1/approvals is scheduled for Phase 1. Listed in STATUS.md."
    )


@router.post("/approvals/{approval_id}/{decision_action}", summary="Approve, reject, or modify a Tier 2 decision (Phase 1)")
def resolve_approval_endpoint(
    approval_id: str,
    decision_action: str,
    body: Optional[ApprovalActionRequest] = None,
    principal: AuthPrincipal = Depends(require_scope("write:approvals")),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    cfg = load_settings()
    if body and body.touches_real_money and not principal.has_fresh_step_up(cfg.step_up_max_age_seconds):
        append_audit_log(
            session,
            actor=principal.actor,
            action="auth.step_up_required_real_money",
            target=f"approval:{approval_id}",
            tier="2",
            outcome="DENIED",
            why="Real-money approval requires fresh Google step-up verification within 5 minutes",
        )
        session.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Step-up verification required for real-money approvals.",
        )
    raise NotImplementedError(
        f"Approval workflow endpoint POST /api/v1/approvals/{approval_id}/{decision_action} is scheduled for Phase 1. Listed in STATUS.md."
    )


@router.get("/recommendations", summary="List recommendations from the Learning Layer (Phase 2)")
def get_recommendations_endpoint(
    principal: AuthPrincipal = Depends(require_scope("read:all")),
) -> Dict[str, Any]:
    raise NotImplementedError(
        "Recommendations endpoint GET /api/v1/recommendations is scheduled for Phase 2. Listed in STATUS.md."
    )


@router.get("/trading/mode", summary="Get current trading mode (PAPER/CANARY/LIVE) and risk status (Phase 4)")
def get_trading_mode_endpoint(
    principal: AuthPrincipal = Depends(require_scope("read:all")),
) -> Dict[str, Any]:
    raise NotImplementedError(
        "Trading mode endpoint GET /api/v1/trading/mode is scheduled for Phase 4. Listed in STATUS.md."
    )


@router.get("/trading/pnl", summary="Get paper/live trading P&L and open positions (Phase 4)")
def get_trading_pnl_endpoint(
    principal: AuthPrincipal = Depends(require_scope("read:all")),
) -> Dict[str, Any]:
    raise NotImplementedError(
        "Trading P&L endpoint GET /api/v1/trading/pnl is scheduled for Phase 4. Listed in STATUS.md."
    )


@router.get("/board/members", summary="List Board of Directors members and rubrics (Phase 1 Board Advisory)")
def get_board_members_endpoint(
    principal: AuthPrincipal = Depends(require_scope("read:all")),
) -> Dict[str, Any]:
    raise NotImplementedError(
        "Board of Directors endpoint GET /api/v1/board/members is scheduled for Phase 1 + Board Advisory pass. Listed in STATUS.md."
    )
