"""Pydantic v2 Request and Response Schemas for Atlas AI /api/v1."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class GoogleLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id_token: str = Field(..., min_length=1, description="Google OAuth 2.0 ID token from Google Sign-In")


class RefreshTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(..., min_length=1, description="Issued refresh token to rotate or revoke")


class TokenBundleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    step_up_verified_until: Optional[str] = None


class KillSwitchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(
        default="Emergency kill switch activated",
        min_length=1,
        max_length=500,
    )


class ResumeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(
        default="Chairman authorized resume from SAFE MODE",
        min_length=1,
        max_length=500,
    )


class AgentControlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="Operator action", min_length=1, max_length=500)


class CreateTaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_name: str = Field(..., min_length=1, description="Target agent identifier in registry")
    action: str = Field(..., min_length=1, description="Agent capability to invoke")
    parameters: Dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=5, ge=1, le=10, description="1 (highest) to 10 (lowest)")
    tier: str = Field(default="0", pattern="^(0|1|1\\.5|2|3)$")
    idempotency_key: Optional[str] = Field(default=None, max_length=128)
    estimated_cost_usd: float = Field(default=0.0, ge=0.0)


class CharterUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(..., ge=1, description="Active Charter version for optimistic concurrency check")
    rationale: str = Field(..., min_length=3, max_length=1000)
    updated_charter: Dict[str, Any] = Field(..., description="Updated Charter sections")
    tier_1_5_enabled: Optional[bool] = Field(default=None)
    explicit_confirmation: bool = Field(
        default=False,
        description="Must be true to confirm Tier 2 Charter modification",
    )


class LimitsUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(..., ge=1)
    rationale: str = Field(default="Chairman updated budget and threshold limits", min_length=3)
    global_daily_budget_usd: Optional[float] = Field(default=None, gt=0)
    global_monthly_budget_usd: Optional[float] = Field(default=None, gt=0)
    per_agent_daily_share_cap: Optional[float] = Field(default=None, gt=0, le=1.0)
    board_daily_budget_usd: Optional[float] = Field(default=None, gt=0)
    tier2_action_cost_threshold_usd: Optional[float] = Field(default=None, ge=0)
    explicit_confirmation: bool = Field(default=True)


class ApprovalActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposal_version: int = Field(default=1, ge=1)
    comment: Optional[str] = Field(default=None, max_length=1000)
    modified_parameters: Optional[Dict[str, Any]] = Field(default=None)
    touches_real_money: bool = Field(default=False)
