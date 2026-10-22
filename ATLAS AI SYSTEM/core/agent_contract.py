"""Standard Agent Contract for Atlas AI.

Every agent in the system must implement BaseAgent and communicate strictly via
schema-validated TaskInput / TaskResult Pydantic v2 models through the task queue.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class AutonomyLevel(str, Enum):
    """Agent capability levels (separate from operational status)."""

    L0 = "L0"  # Recommend only
    L1 = "L1"  # Execute permitted sandbox or paper operations
    L2 = "L2"  # Execute explicitly allowlisted actions within enforced limits
    L3 = "L3"  # Execute broader, explicitly human-approved scope with notification/monitoring


class AgentOperationalStatus(str, Enum):
    """Operational status of an agent."""

    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    SAFE_MODE_HALTED = "SAFE_MODE_HALTED"
    PLANNED = "PLANNED"
    ERROR = "ERROR"
    SUSPENDED = "SUSPENDED"


class TaskInput(BaseModel):
    """Schema-validated input passed to any agent's run() method."""

    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(..., min_length=1, description="Unique task identifier")
    action: str = Field(..., min_length=1, description="Requested capability/action name")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Action parameters")
    requester: str = Field(default="atlas", description="Originating principal or supervisor")
    decision_id: Optional[str] = Field(default=None, description="Associated Decision ID")
    tier: str = Field(default="0", description="Assigned decision tier (0, 1, 1.5, 2, 3)")
    timeout_seconds: int = Field(default=30, ge=1, le=600, description="Max execution timeout")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Tracing and governance metadata")


class TaskResult(BaseModel):
    """Schema-validated output returned by any agent's run() method."""

    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(..., min_length=1)
    agent_name: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)
    status: str = Field(..., pattern="^(completed|failed|recommendation_only)$")
    output: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    actual_cost_usd: float = Field(default=0.0, ge=0.0)
    is_mock: bool = Field(default=False)
    error: Optional[str] = Field(default=None)
    completed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class AgentHealthReport(BaseModel):
    """Standardized health check response for an agent."""

    model_config = ConfigDict(extra="forbid")

    agent_name: str
    layer: str
    status: str
    health: str  # healthy | degraded | unhealthy | planned
    autonomy_level: str
    version: str
    phase: int
    details: Dict[str, Any] = Field(default_factory=dict)
    checked_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class BaseAgent(ABC):
    """Abstract contract that every Atlas AI agent must implement."""

    name: str
    display_name: str
    layer: str
    description: str
    version: str = "1.0.0"
    phase: int = 0
    capabilities: List[str]
    permissions: List[str]
    autonomy_level: AutonomyLevel = AutonomyLevel.L0
    status: AgentOperationalStatus = AgentOperationalStatus.PLANNED

    def __init__(
        self,
        *,
        name: str,
        display_name: str,
        layer: str,
        description: str,
        capabilities: List[str],
        permissions: List[str],
        version: str = "1.0.0",
        phase: int = 0,
        autonomy_level: AutonomyLevel = AutonomyLevel.L0,
        status: AgentOperationalStatus = AgentOperationalStatus.PLANNED,
    ) -> None:
        self.name = name
        self.display_name = display_name
        self.layer = layer
        self.description = description
        self.capabilities = list(capabilities)
        self.permissions = list(permissions)
        self.version = version
        self.phase = phase
        self.autonomy_level = autonomy_level
        self.status = status

    def validate_action_and_permissions(self, task: TaskInput, required_permission: Optional[str] = None) -> None:
        """Enforce capability and explicit allowlist permission checks before execution."""
        if task.action not in self.capabilities:
            raise PermissionError(
                f"Agent '{self.name}' does not support capability '{task.action}'. "
                f"Supported: {self.capabilities}"
            )
        if required_permission and required_permission not in self.permissions:
            raise PermissionError(
                f"Agent '{self.name}' lacks explicit permission '{required_permission}'. "
                f"Granted allowlist: {self.permissions}"
            )

    @abstractmethod
    def run(self, task: TaskInput) -> TaskResult:
        """Execute the validated task and return a schema-validated TaskResult."""

    @abstractmethod
    def estimate_cost(self, task: TaskInput) -> float:
        """Return estimated USD cost for running the given task."""

    def health(self) -> Dict[str, Any]:
        """Return standardized health dictionary."""
        health_val = "planned" if self.status == AgentOperationalStatus.PLANNED else "healthy"
        if self.status in (AgentOperationalStatus.ERROR, AgentOperationalStatus.SUSPENDED):
            health_val = "unhealthy"
        elif self.status in (AgentOperationalStatus.PAUSED, AgentOperationalStatus.SAFE_MODE_HALTED):
            health_val = "degraded"

        report = AgentHealthReport(
            agent_name=self.name,
            layer=self.layer,
            status=self.status.value,
            health=health_val,
            autonomy_level=self.autonomy_level.value,
            version=self.version,
            phase=self.phase,
            details={"capabilities_count": len(self.capabilities)},
        )
        return report.model_dump()


class PlannedAgent(BaseAgent):
    """Contract-compliant placeholder for catalog agents scheduled for later phases.

    Calling run() on a PlannedAgent explicitly raises NotImplementedError as required
    by the engineering specification (no fake stub outputs).
    """

    def run(self, task: TaskInput) -> TaskResult:
        raise NotImplementedError(
            f"Agent '{self.name}' ({self.display_name}, Layer: {self.layer}, Phase {self.phase}) "
            f"is registered with status=PLANNED and autonomy_level={self.autonomy_level.value}. "
            f"Execution of action '{task.action}' is not yet implemented."
        )

    def estimate_cost(self, task: TaskInput) -> float:
        return 0.0
