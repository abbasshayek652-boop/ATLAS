"""Versioned Governance Charter with Optimistic Concurrency Control & Step-Up Enforcement."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from core.audit import append_audit_log
from core.config import load_settings
from core.events import EVENT_HUB
from db.models import CharterVersionRecord, SystemState


def default_charter_document() -> Dict[str, Any]:
    """Return the initial conservative Charter configuration (Addendum A3 & A7)."""
    cfg = load_settings()
    return {
        "delegated_action_types": [
            "internal_report_generation",
            "sandbox_config_tuning",
            "paper_strategy_simulation",
            "schedule_low_cost_job",
        ],
        "exclusions_and_prohibited_actions": [
            "withdraw_or_transfer_to_new_address",
            "modify_keys_or_secrets",
            "disable_risk_security_compliance_or_audit",
            "delete_or_edit_audit_logs",
            "edit_production_code_or_own_prompts_without_approval",
            "enable_own_execution_mode",
            "raise_own_budget",
        ],
        "budgets_and_limits": {
            "global_daily_budget_usd": cfg.global_daily_budget_usd,
            "global_monthly_budget_usd": cfg.global_monthly_budget_usd,
            "per_agent_daily_share_cap": cfg.per_agent_daily_share_cap,
            "board_daily_budget_usd": cfg.board_daily_budget_usd,
            "tier2_action_cost_threshold_usd": cfg.tier2_action_cost_threshold_usd,
            "soft_alert_ratio": cfg.budget_soft_alert_ratio,
            "hard_stop_ratio": cfg.budget_hard_stop_ratio,
            "max_retries_per_task": cfg.max_retries_per_task,
            "max_llm_calls_per_task": cfg.max_llm_calls_per_task,
        },
        "voting_rules": {
            "total_voting_directors": 5,
            "has_devils_advocate": True,
            "quorum_required": 5,
            "majority_required": 4,
            "any_escalate_forces_tier2": True,
            "timeout_default": "REJECT",
            "approval_expiry_hours": 24,
        },
        "autonomy_rules": {
            "minimum_track_record_tasks": 25,
            "max_board_recommended_level": "L2",
            "l3_requires_explicit_chairman_approval": True,
        },
        "board_mode": {
            "advisory_only": True,
            "tier_1_5_enabled": False,
        },
    }


def ensure_active_charter(session: Session) -> CharterVersionRecord:
    """Seed version 1 of the Charter if none exists and return the active CharterVersionRecord."""
    active = session.scalar(
        select(CharterVersionRecord)
        .where(CharterVersionRecord.is_active.is_(True))
        .order_by(desc(CharterVersionRecord.version))
        .limit(1)
    )
    if active is not None:
        return active

    doc = default_charter_document()
    record = CharterVersionRecord(
        version=1,
        version_tag="v1.0.0",
        author="system:bootstrap",
        rationale="Initial strict conservative Charter (Phase 0 bootstrap, Board in Advisory Mode).",
        charter_json=json.dumps(doc, sort_keys=True),
        tier_1_5_enabled=False,
        is_active=True,
    )
    session.add(record)
    session.flush()
    return record


def get_active_charter_view(session: Session) -> Dict[str, Any]:
    rec = ensure_active_charter(session)
    created = rec.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return {
        "version": rec.version,
        "version_tag": rec.version_tag,
        "author": rec.author,
        "rationale": rec.rationale,
        "tier_1_5_enabled": rec.tier_1_5_enabled,
        "is_active": rec.is_active,
        "charter": json.loads(rec.charter_json),
        "created_at": created.isoformat(),
    }


def list_charter_versions(session: Session) -> List[Dict[str, Any]]:
    ensure_active_charter(session)
    rows = session.scalars(
        select(CharterVersionRecord).order_by(desc(CharterVersionRecord.version))
    ).all()
    results = []
    for r in rows:
        created = r.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        results.append(
            {
                "version": r.version,
                "version_tag": r.version_tag,
                "author": r.author,
                "rationale": r.rationale,
                "tier_1_5_enabled": r.tier_1_5_enabled,
                "is_active": r.is_active,
                "charter": json.loads(r.charter_json),
                "created_at": created.isoformat(),
            }
        )
    return results


def update_charter_by_chairman(
    session: Session,
    *,
    actor: str,
    expected_version: int,
    rationale: str,
    updated_charter: Dict[str, Any],
    tier_1_5_enabled: Optional[bool] = None,
    explicit_confirmation: bool = False,
) -> Dict[str, Any]:
    """Create a new Charter version (Chairman + Step-Up only; optimistic version check)."""
    if not actor.startswith("owner:"):
        append_audit_log(
            session,
            actor=actor,
            action="charter.unauthorized_modification_blocked",
            target="charter",
            tier="3",
            outcome="DENIED",
            why="Only the authenticated Chairman may modify the Charter; agents and Board cannot expand their own authority.",
        )
        session.flush()
        raise PermissionError("Only the authenticated Chairman may modify the Charter.")

    if not explicit_confirmation:
        raise ValueError("Explicit confirmation (explicit_confirmation=True) is required for Charter changes.")

    current = ensure_active_charter(session)
    if current.version != expected_version:
        append_audit_log(
            session,
            actor=actor,
            action="charter.version_conflict",
            target=f"charter:v{current.version}",
            tier="2",
            outcome="DENIED",
            why=f"Optimistic concurrency conflict: expected version {expected_version}, active is {current.version}",
        )
        session.flush()
        raise ValueError(
            f"Charter version conflict: expected version {expected_version}, but current active version is {current.version}."
        )

    current.is_active = False
    new_version = current.version + 1
    new_tier_1_5 = current.tier_1_5_enabled if tier_1_5_enabled is None else bool(tier_1_5_enabled)

    merged_doc = json.loads(current.charter_json)
    for k, v in updated_charter.items():
        if isinstance(v, dict) and isinstance(merged_doc.get(k), dict):
            merged_doc[k].update(v)
        else:
            merged_doc[k] = v

    merged_doc.setdefault("board_mode", {})["tier_1_5_enabled"] = new_tier_1_5
    merged_doc["board_mode"]["advisory_only"] = not new_tier_1_5

    new_record = CharterVersionRecord(
        version=new_version,
        version_tag=f"v{new_version}.0.0",
        author=actor,
        rationale=rationale,
        charter_json=json.dumps(merged_doc, sort_keys=True),
        tier_1_5_enabled=new_tier_1_5,
        is_active=True,
    )
    session.add(new_record)

    sys_state = session.get(SystemState, "global")
    if sys_state:
        sys_state.active_charter_version = new_version
        sys_state.board_execution_enabled = new_tier_1_5

    append_audit_log(
        session,
        actor=actor,
        action="charter.updated",
        target=f"charter:v{new_version}",
        tier="2",
        outcome="SUCCESS",
        why=rationale,
        details={
            "previous_version": current.version,
            "new_version": new_version,
            "tier_1_5_enabled": new_tier_1_5,
        },
    )
    EVENT_HUB.publish_sync(
        "charter.updated",
        {"version": new_version, "author": actor, "tier_1_5_enabled": new_tier_1_5},
    )
    session.flush()
    return get_active_charter_view(session)
