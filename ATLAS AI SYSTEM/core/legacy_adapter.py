"""LegacyAdapter Interface for Wrapping Untrusted External Scripts Behind the Agent Contract.

Per Addendum A5:
- Legacy code is untrusted and must run only through a LegacyAdapter.
- Enforces schema-validated TaskInput / TaskResult.
- Strips environment secrets and injects only explicitly allowlisted env vars.
- Prohibits direct live trading (enforces PAPER mode unless Tier 2 approved) and direct external publishing.
- Enforces strict execution timeouts, cost estimation, audit logging, and health checks.
"""

from __future__ import annotations

import os
from abc import abstractmethod
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from core.agent_contract import (
    AgentOperationalStatus,
    AutonomyLevel,
    BaseAgent,
    TaskInput,
    TaskResult,
)
from core.audit import append_audit_log


FORBIDDEN_DIRECT_PERMISSIONS = frozenset(
    {
        "trade:live_direct",
        "publish:external_direct",
        "withdraw:funds",
        "secrets:read_all",
    }
)


class LegacyAdapter(BaseAgent):
    """Base adapter wrapping an untrusted legacy script/module under the Atlas AI Agent Contract."""

    def __init__(
        self,
        *,
        name: str,
        display_name: str,
        layer: str,
        description: str,
        capabilities: List[str],
        permissions: List[str],
        allowed_env_keys: Optional[List[str]] = None,
        is_trading_adapter: bool = False,
        default_timeout_seconds: int = 30,
        version: str = "1.0.0",
        phase: int = 4,
        autonomy_level: AutonomyLevel = AutonomyLevel.L0,
        status: AgentOperationalStatus = AgentOperationalStatus.PLANNED,
    ) -> None:
        forbidden = set(permissions) & FORBIDDEN_DIRECT_PERMISSIONS
        if forbidden:
            raise PermissionError(
                f"LegacyAdapter '{name}' cannot declare forbidden direct permissions: {sorted(forbidden)}"
            )
        super().__init__(
            name=name,
            display_name=display_name,
            layer=layer,
            description=description,
            capabilities=capabilities,
            permissions=permissions,
            version=version,
            phase=phase,
            autonomy_level=autonomy_level,
            status=status,
        )
        self.allowed_env_keys = list(allowed_env_keys or [])
        self.is_trading_adapter = is_trading_adapter
        self.default_timeout_seconds = default_timeout_seconds

    def build_sanitized_env(self) -> Dict[str, str]:
        """Return a minimal environment dictionary containing ONLY explicitly granted secrets."""
        sanitized: Dict[str, str] = {
            "ATLAS_SANDBOX": "1",
            "ATLAS_TRADING_MODE": "PAPER" if self.is_trading_adapter else "NONE",
        }
        for key in self.allowed_env_keys:
            if key in os.environ:
                sanitized[key] = os.environ[key]
        return sanitized

    def enforce_legacy_safety_guards(self, task: TaskInput, current_trading_mode: str = "PAPER") -> None:
        """Enforce that legacy code cannot execute live trades or external publications directly."""
        if self.status == AgentOperationalStatus.PLANNED:
            raise NotImplementedError(
                f"LegacyAdapter '{self.name}' is in status=PLANNED and not yet wired to verified code."
            )
        self.validate_action_and_permissions(task)
        if self.is_trading_adapter and current_trading_mode != "PAPER":
            if "trade:live_approved" not in self.permissions:
                raise PermissionError(
                    f"Legacy trading adapter '{self.name}' is restricted to PAPER mode until "
                    "Tier 2 Chairman approval grants live/canary execution."
                )

    @abstractmethod
    def invoke_legacy_callable(
        self,
        validated_input: TaskInput,
        sanitized_env: Dict[str, str],
        timeout_seconds: int,
    ) -> Dict[str, Any]:
        """Subclasses implement the isolated call to the audited legacy module."""

    def run(self, task: TaskInput) -> TaskResult:
        """Standard contract run() delegating through legacy safety & environment isolation."""
        timeout = min(task.timeout_seconds, self.default_timeout_seconds)
        self.enforce_legacy_safety_guards(task, current_trading_mode="PAPER")
        sanitized_env = self.build_sanitized_env()
        raw_output = self.invoke_legacy_callable(task, sanitized_env, timeout)
        return TaskResult(
            task_id=task.task_id,
            agent_name=self.name,
            action=task.action,
            status="completed",
            output=raw_output if isinstance(raw_output, dict) else {"result": raw_output},
            confidence=float(raw_output.get("confidence", 0.8)) if isinstance(raw_output, dict) else 0.8,
            actual_cost_usd=self.estimate_cost(task),
            is_mock=False,
        )

    def run_with_audit(
        self,
        session: Session,
        task: TaskInput,
        *,
        current_trading_mode: str = "PAPER",
    ) -> TaskResult:
        """Validate, audit, execute within timeout/sandbox constraints, and validate output schema."""
        timeout = min(task.timeout_seconds, self.default_timeout_seconds)
        try:
            self.enforce_legacy_safety_guards(task, current_trading_mode=current_trading_mode)
            sanitized_env = self.build_sanitized_env()
            raw_output = self.invoke_legacy_callable(task, sanitized_env, timeout)
            result = TaskResult(
                task_id=task.task_id,
                agent_name=self.name,
                action=task.action,
                status="completed",
                output=raw_output if isinstance(raw_output, dict) else {"result": raw_output},
                confidence=float(raw_output.get("confidence", 0.8)) if isinstance(raw_output, dict) else 0.8,
                actual_cost_usd=self.estimate_cost(task),
                is_mock=False,
            )
            append_audit_log(
                session,
                actor=f"legacy_adapter:{self.name}",
                action=f"legacy.{task.action}",
                target=task.task_id,
                tier=task.tier,
                outcome="SUCCESS",
                why=f"LegacyAdapter executed '{task.action}' in {current_trading_mode} mode",
                details={"timeout_seconds": timeout},
            )
            return result
        except Exception as exc:
            append_audit_log(
                session,
                actor=f"legacy_adapter:{self.name}",
                action=f"legacy.{task.action}",
                target=task.task_id,
                tier=task.tier,
                outcome="FAILED",
                why=str(exc),
            )
            raise
