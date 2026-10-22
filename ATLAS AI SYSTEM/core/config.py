"""Atlas AI Configuration & Environment Management."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import List


def _parse_bool(val: str | None, default: bool = False) -> bool:
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _parse_list(val: str | None, default: List[str] | None = None) -> List[str]:
    if not val:
        return list(default) if default else []
    return [item.strip() for item in val.split(",") if item.strip()]


@dataclass
class Settings:
    """Centralized, validated settings loaded from environment variables."""

    env: str = field(default_factory=lambda: os.getenv("ENV", "dev").strip().lower())
    app_name: str = "Atlas AI Control Plane"
    api_v1_prefix: str = "/api/v1"
    version: str = "0.1.0"

    # Database
    database_url: str = field(
        default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./atlas_ai.db")
    )

    # Single-Owner Google OAuth 2.0 & JWT Auth
    owner_email: str = field(
        default_factory=lambda: os.getenv("OWNER_EMAIL", "abbass@example.com").strip().lower()
    )
    google_client_id: str = field(
        default_factory=lambda: os.getenv("GOOGLE_CLIENT_ID", "atlas-google-client-id.apps.googleusercontent.com").strip()
    )
    jwt_signing_key: str = field(
        default_factory=lambda: os.getenv(
            "JWT_SIGNING_KEY", "dev-only-jwt-signing-secret-change-in-production-32b"
        )
    )
    access_token_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("ACCESS_TOKEN_TTL_SECONDS", "900"))
    )
    refresh_token_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("REFRESH_TOKEN_TTL_SECONDS", "604800"))
    )
    step_up_max_age_seconds: int = field(
        default_factory=lambda: int(os.getenv("STEP_UP_MAX_AGE_SECONDS", "300"))
    )

    # Scoped Machine Token (stored/compared hashed in constant time)
    machine_api_token_hash: str = field(default="")

    # Dev Mode Bypass (STRICTLY forbidden when ENV=prod)
    dev_owner_token: str = field(
        default_factory=lambda: os.getenv("DEV_OWNER_TOKEN", "").strip()
    )

    # Security / CORS / Rate Limiting
    cors_allowed_origins: List[str] = field(
        default_factory=lambda: _parse_list(
            os.getenv("CORS_ALLOWED_ORIGINS"),
            default=["http://localhost:3000", "http://localhost:5173", "https://aistudio.google.com"],
        )
    )
    enforce_https: bool = field(
        default_factory=lambda: _parse_bool(
            os.getenv("ENFORCE_HTTPS"),
            default=os.getenv("ENV", "dev").strip().lower() in ("prod", "production"),
        )
    )
    rate_limit_login_per_minute: int = field(
        default_factory=lambda: int(os.getenv("RATE_LIMIT_LOGIN_PER_MINUTE", "10"))
    )
    rate_limit_write_per_minute: int = field(
        default_factory=lambda: int(os.getenv("RATE_LIMIT_WRITE_PER_MINUTE", "60"))
    )
    auth_lockout_threshold: int = field(
        default_factory=lambda: int(os.getenv("AUTH_LOCKOUT_THRESHOLD", "5"))
    )
    auth_lockout_window_seconds: int = field(
        default_factory=lambda: int(os.getenv("AUTH_LOCKOUT_WINDOW_SECONDS", "900"))
    )

    # LLM / Model Router
    gemini_api_key: str = field(
        default_factory=lambda: os.getenv("GEMINI_API_KEY", "").strip()
    )
    model_router_config_path: str = field(
        default_factory=lambda: os.getenv("MODEL_ROUTER_CONFIG_PATH", "core/model_router.yaml")
    )

    # Strict Conservative Budgets (Addendum A3 defaults)
    global_daily_budget_usd: float = field(
        default_factory=lambda: float(os.getenv("GLOBAL_DAILY_BUDGET_USD", "5.0"))
    )
    global_monthly_budget_usd: float = field(
        default_factory=lambda: float(os.getenv("GLOBAL_MONTHLY_BUDGET_USD", "100.0"))
    )
    per_agent_daily_share_cap: float = field(
        default_factory=lambda: float(os.getenv("PER_AGENT_DAILY_SHARE_CAP", "0.30"))
    )
    budget_soft_alert_ratio: float = field(
        default_factory=lambda: float(os.getenv("BUDGET_SOFT_ALERT_RATIO", "0.80"))
    )
    budget_hard_stop_ratio: float = field(
        default_factory=lambda: float(os.getenv("BUDGET_HARD_STOP_RATIO", "1.00"))
    )
    tier2_action_cost_threshold_usd: float = field(
        default_factory=lambda: float(os.getenv("TIER2_ACTION_COST_THRESHOLD_USD", "1.0"))
    )
    board_daily_budget_usd: float = field(
        default_factory=lambda: float(os.getenv("BOARD_DAILY_BUDGET_USD", "1.0"))
    )

    # Runaway Guards
    max_retries_per_task: int = field(
        default_factory=lambda: int(os.getenv("MAX_RETRIES_PER_TASK", "3"))
    )
    max_llm_calls_per_task: int = field(
        default_factory=lambda: int(os.getenv("MAX_LLM_CALLS_PER_TASK", "10"))
    )

    # Telegram Notifications & Low-Risk Approval Threshold
    telegram_bot_token: str = field(
        default_factory=lambda: os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    )
    telegram_owner_chat_id: str = field(
        default_factory=lambda: os.getenv("TELEGRAM_OWNER_CHAT_ID", "").strip()
    )
    telegram_low_risk_max_cost_usd: float = field(
        default_factory=lambda: float(os.getenv("TELEGRAM_LOW_RISK_MAX_COST_USD", "0.50"))
    )

    # n8n Webhook Integration
    n8n_webhook_base_url: str = field(
        default_factory=lambda: os.getenv("N8N_WEBHOOK_BASE_URL", "").strip()
    )
    n8n_webhook_secret: str = field(
        default_factory=lambda: os.getenv("N8N_WEBHOOK_SECRET", "").strip()
    )

    def __post_init__(self) -> None:
        raw_machine_token = os.getenv("MACHINE_API_TOKEN", "").strip()
        raw_machine_hash = os.getenv("MACHINE_API_TOKEN_HASH", "").strip()
        if raw_machine_hash:
            self.machine_api_token_hash = raw_machine_hash.lower()
        elif raw_machine_token:
            self.machine_api_token_hash = hashlib.sha256(
                raw_machine_token.encode("utf-8")
            ).hexdigest()

        self.validate_security_constraints()

    @property
    def is_prod(self) -> bool:
        return self.env in ("prod", "production")

    @property
    def is_dev_or_test(self) -> bool:
        return self.env in ("dev", "development", "test", "testing")

    def validate_security_constraints(self) -> None:
        """Fail startup immediately if production security constraints are violated."""
        if self.is_prod:
            if self.dev_owner_token:
                raise RuntimeError(
                    "CRITICAL SECURITY ERROR: DEV_OWNER_TOKEN is set while ENV=prod. "
                    "Dev authentication bypass is strictly prohibited in production."
                )
            if (
                not self.jwt_signing_key
                or self.jwt_signing_key == "dev-only-jwt-signing-secret-change-in-production-32b"
            ):
                raise RuntimeError(
                    "CRITICAL SECURITY ERROR: A strong JWT_SIGNING_KEY must be set in production."
                )
            if not self.owner_email or self.owner_email == "abbass@example.com":
                raise RuntimeError(
                    "CRITICAL SECURITY ERROR: OWNER_EMAIL must be configured in production."
                )


def load_settings() -> Settings:
    """Create a fresh Settings instance from current environment variables."""
    return Settings()
