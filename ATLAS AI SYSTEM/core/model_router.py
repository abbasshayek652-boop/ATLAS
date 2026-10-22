"""Provider-Agnostic Model Router with Gemini Adapter, Cost Enforcement & Fail-Closed Security.

Implements Addendum A3 & A4:
- Per-agent model assignments loaded from core/model_router.yaml (never hardcoded).
- Provider adapter interface (BaseLLMProvider: generate, estimate_cost, health, verify_models).
- GeminiProvider using google-genai Interactions API (client.interactions.create).
- Startup model verification against live Gemini API with warning logs.
- Deterministic MockLLMProvider allowed ONLY in ENV=dev or ENV=test; mock outputs are
  tagged mock=True and can NEVER trigger Tier 1 / Tier 1.5 execution.
- Fail-closed in ENV=prod when GEMINI_API_KEY is unset (raises ProviderUnavailableError).
- Retry with backoff -> configured fallback model -> fail task & alert (never falls back to mock in prod).
- Pre-call Cost Agent budget check (global daily/monthly, Board daily, 30% per-agent cap,
  80% soft alert, 100% hard stop, and per-task max LLM calls runaway guard).
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
import yaml
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.agent_contract import AgentOperationalStatus
from core.audit import append_audit_log
from core.config import Settings, load_settings
from core.events import EVENT_HUB
from db.models import AgentRecord, LLMCallLog, TaskRecord

logger = logging.getLogger("atlas.model_router")


class ProviderUnavailableError(RuntimeError):
    """Raised when the configured LLM provider is unavailable (fails closed in prod)."""


class BudgetCapExceededError(PermissionError):
    """Raised before an LLM call is sent if any global, Board, or per-agent cap is reached."""


class RunawayTaskError(RuntimeError):
    """Raised when a task exceeds the maximum permitted LLM calls or retries."""


class ModelAssignment(BaseModel):
    """Per-agent model configuration entry loaded from model_router.yaml."""

    model_config = ConfigDict(extra="ignore")

    provider: str = Field(..., min_length=1)
    model: str = Field(..., min_length=1)
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4096, ge=1)
    fallback: Optional[str] = Field(default=None)
    prompt_version: str = Field(default="v1.0")


class LLMResponse(BaseModel):
    """Standardized response returned by ModelRouter.generate()."""

    model_config = ConfigDict(extra="forbid")

    call_id: str
    agent_name: str
    provider: str
    model: str
    prompt_version: str
    text: str
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cost_usd: float = Field(default=0.0, ge=0.0)
    latency_ms: float = Field(default=0.0, ge=0.0)
    mock: bool = Field(default=False)
    used_fallback: bool = Field(default=False)
    decision_id: Optional[str] = None
    task_id: Optional[str] = None

    @property
    def can_trigger_execution(self) -> bool:
        """Mock outputs (mock=True) can NEVER trigger Tier 1 or Tier 1.5 execution."""
        return not self.mock


def assert_can_execute_from_llm(response: LLMResponse) -> None:
    """Enforce that mock LLM responses never authorize Tier 1 or Tier 1.5 execution."""
    if response.mock:
        raise PermissionError(
            "SECURITY BLOCK: LLM output is tagged mock=True and cannot authorize Tier 1 or Tier 1.5 execution."
        )


class BaseLLMProvider(ABC):
    """Pluggable LLM Provider Adapter Interface."""

    provider_name: str

    @abstractmethod
    def generate(
        self,
        *,
        model: str,
        prompt: str,
        system_instruction: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> Dict[str, Any]:
        """Execute model generation and return {'text', 'input_tokens', 'output_tokens'}."""

    @abstractmethod
    def estimate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Estimate USD cost for the given model and token counts."""

    @abstractmethod
    def health(self) -> Dict[str, Any]:
        """Return provider health status."""

    def verify_models(self, configured_models: List[str]) -> Dict[str, Any]:
        """Verify configured model identifiers against the upstream provider API."""
        return {"verified": True, "missing_models": []}


class GeminiProvider(BaseLLMProvider):
    """Google Gemini Provider using the official google-genai Interactions API."""

    provider_name = "gemini"

    def __init__(
        self,
        api_key: str,
        pricing_table: Dict[str, Dict[str, float]],
    ) -> None:
        self.api_key = api_key
        self.pricing_table = pricing_table

    def estimate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        rates = self.pricing_table.get(model) or {"input": 0.00015, "output": 0.00060}
        cost = (input_tokens / 1000.0) * float(rates.get("input", 0.00015)) + (
            output_tokens / 1000.0
        ) * float(rates.get("output", 0.00060))
        return round(cost, 8)

    def generate(
        self,
        *,
        model: str,
        prompt: str,
        system_instruction: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> Dict[str, Any]:
        if not self.api_key:
            raise ProviderUnavailableError("GEMINI_API_KEY is not configured.")

        # Prefer google-genai >= 2.30.1 Interactions API (client.interactions.create)
        try:
            from google import genai  # type: ignore

            client = genai.Client(api_key=self.api_key)
            kwargs: Dict[str, Any] = {
                "model": model,
                "input": prompt,
            }
            if system_instruction:
                kwargs["system_instruction"] = system_instruction

            interaction = client.interactions.create(**kwargs)
            output_text = getattr(interaction, "output_text", None)
            if not output_text and getattr(interaction, "steps", None):
                last_step = interaction.steps[-1]
                if getattr(last_step, "content", None):
                    output_text = getattr(last_step.content[0], "text", "")
            usage = getattr(interaction, "usage", None)
            in_tok = int(getattr(usage, "input_tokens", 0) or max(1, len(prompt) // 4))
            out_tok = int(getattr(usage, "output_tokens", 0) or max(1, len(output_text or "") // 4))
            return {
                "text": output_text or "",
                "input_tokens": in_tok,
                "output_tokens": out_tok,
            }
        except ImportError:
            # REST Interactions API fallback (/v1beta/interactions with Api-Revision: 2026-05-20)
            url = "https://generativelanguage.googleapis.com/v1beta/interactions"
            headers = {
                "Content-Type": "application/json",
                "x-goog-api-key": self.api_key,
                "Api-Revision": "2026-05-20",
            }
            body: Dict[str, Any] = {
                "model": model,
                "input": prompt,
            }
            if system_instruction:
                body["system_instruction"] = system_instruction

            resp = requests.post(url, headers=headers, json=body, timeout=30)
            if resp.status_code >= 400:
                raise ProviderUnavailableError(
                    f"Gemini Interactions API error (HTTP {resp.status_code}): {resp.text[:200]}"
                )
            data = resp.json()
            text = data.get("output_text", "")
            if not text and data.get("steps"):
                for step in reversed(data["steps"]):
                    if step.get("type") == "model_output" and step.get("content"):
                        text = step["content"][0].get("text", "")
                        break
            usage = data.get("usage", {})
            in_tok = int(usage.get("input_tokens", max(1, len(prompt) // 4)))
            out_tok = int(usage.get("output_tokens", max(1, len(text) // 4)))
            return {
                "text": text,
                "input_tokens": in_tok,
                "output_tokens": out_tok,
            }
        except Exception as exc:
            raise ProviderUnavailableError(f"Gemini generation failed for model '{model}': {exc}") from exc

    def verify_models(self, configured_models: List[str]) -> Dict[str, Any]:
        """Check configured Gemini models against the live API at startup and log warnings."""
        if not self.api_key:
            logger.warning(
                "GEMINI_API_KEY is not set; skipping live Gemini model verification at startup."
            )
            return {
                "verified": False,
                "reason": "no_api_key",
                "configured_models": configured_models,
                "missing_models": [],
            }
        try:
            resp = requests.get(
                "https://generativelanguage.googleapis.com/v1beta/models",
                headers={"x-goog-api-key": self.api_key},
                timeout=10,
            )
            if resp.status_code != 200:
                logger.warning(
                    "Could not verify Gemini models against live API (HTTP %s).", resp.status_code
                )
                return {
                    "verified": False,
                    "reason": f"http_{resp.status_code}",
                    "configured_models": configured_models,
                    "missing_models": [],
                }
            payload = resp.json()
            available = {
                m.get("name", "").replace("models/", "") for m in payload.get("models", [])
            }
            missing = [m for m in configured_models if m not in available]
            if missing:
                logger.warning(
                    "Configured Gemini models not found in live catalog: %s", missing
                )
            return {
                "verified": len(missing) == 0,
                "configured_models": configured_models,
                "missing_models": missing,
            }
        except Exception as exc:
            logger.warning("Live Gemini model verification failed at startup: %s", exc)
            return {
                "verified": False,
                "reason": str(exc),
                "configured_models": configured_models,
                "missing_models": [],
            }

    def health(self) -> Dict[str, Any]:
        return {
            "provider": "gemini",
            "configured": bool(self.api_key),
            "status": "healthy" if self.api_key else "unconfigured",
        }


class MockLLMProvider(BaseLLMProvider):
    """Deterministic offline mock provider strictly restricted to ENV=dev and ENV=test."""

    provider_name = "mock"

    def __init__(self, pricing_table: Dict[str, Dict[str, float]]) -> None:
        self.pricing_table = pricing_table

    def estimate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        rates = self.pricing_table.get(model) or {"input": 0.00015, "output": 0.00060}
        return round(
            (input_tokens / 1000.0) * float(rates.get("input", 0.00015))
            + (output_tokens / 1000.0) * float(rates.get("output", 0.00060)),
            8,
        )

    def generate(
        self,
        *,
        model: str,
        prompt: str,
        system_instruction: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> Dict[str, Any]:
        in_tok = max(8, len(prompt) // 4)
        summary = prompt.strip().splitlines()[0][:120] if prompt.strip() else "empty"
        text = f"[MOCK:{model}] Deterministic advisory response for: {summary}"
        out_tok = max(8, len(text) // 4)
        return {
            "text": text,
            "input_tokens": in_tok,
            "output_tokens": out_tok,
        }

    def health(self) -> Dict[str, Any]:
        return {"provider": "mock", "configured": True, "status": "dev_test_only"}


class OpenAIProviderPlaceholder(BaseLLMProvider):
    """Pluggable interface slot for OpenAI (not implemented in Phase 0 per Addendum A4)."""

    provider_name = "openai"

    def generate(self, **kwargs: Any) -> Dict[str, Any]:
        raise NotImplementedError("OpenAIProvider is not yet implemented. Listed in STATUS.md.")

    def estimate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        raise NotImplementedError("OpenAIProvider is not yet implemented.")

    def health(self) -> Dict[str, Any]:
        return {"provider": "openai", "status": "not_implemented"}


class AnthropicProviderPlaceholder(BaseLLMProvider):
    """Pluggable interface slot for Anthropic (not implemented in Phase 0 per Addendum A4)."""

    provider_name = "anthropic"

    def generate(self, **kwargs: Any) -> Dict[str, Any]:
        raise NotImplementedError("AnthropicProvider is not yet implemented. Listed in STATUS.md.")

    def estimate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        raise NotImplementedError("AnthropicProvider is not yet implemented.")

    def health(self) -> Dict[str, Any]:
        return {"provider": "anthropic", "status": "not_implemented"}


class ModelRouter:
    """Central LLM router enforcing per-agent YAML config, cost caps, fallback, and audit logging."""

    def __init__(
        self,
        config_path: Optional[str] = None,
        settings: Optional[Settings] = None,
    ) -> None:
        self.settings = settings or load_settings()
        path_str = config_path or self.settings.model_router_config_path
        self.config_path = Path(path_str)
        if not self.config_path.is_absolute():
            repo_root = Path(__file__).resolve().parent.parent
            self.config_path = repo_root / path_str

        self._raw_config: Dict[str, Any] = {}
        self.pricing_table: Dict[str, Dict[str, float]] = {}
        self.default_assignment: ModelAssignment
        self.agent_assignments: Dict[str, ModelAssignment] = {}
        self._load_yaml_config()

        self.providers: Dict[str, BaseLLMProvider] = {
            "gemini": GeminiProvider(self.settings.gemini_api_key, self.pricing_table),
            "mock": MockLLMProvider(self.pricing_table),
            "openai": OpenAIProviderPlaceholder(),
            "anthropic": AnthropicProviderPlaceholder(),
        }

    def _load_yaml_config(self) -> None:
        if not self.config_path.exists():
            raise FileNotFoundError(f"Model router config not found at {self.config_path}")
        with open(self.config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        self._raw_config = data
        self.pricing_table = data.get("pricing_per_1k_tokens_usd", {})
        defaults_dict = data.get("defaults") or {
            "provider": "gemini",
            "model": "gemini-3.8-flash",
            "temperature": 0.2,
            "max_tokens": 4096,
            "fallback": "gemini-3.5-flash-lite",
            "prompt_version": "v1.0",
        }
        self.default_assignment = ModelAssignment.model_validate(defaults_dict)
        agents_dict = data.get("agents", {})
        self.agent_assignments = {
            name: ModelAssignment.model_validate(cfg) for name, cfg in agents_dict.items()
        }

    def get_assignment(self, agent_name: str) -> ModelAssignment:
        """Return the configured ModelAssignment for an agent, or the default assignment."""
        return self.agent_assignments.get(agent_name, self.default_assignment)

    def configured_models(self) -> List[str]:
        models = {self.default_assignment.model}
        if self.default_assignment.fallback:
            models.add(self.default_assignment.fallback)
        for assign in self.agent_assignments.values():
            models.add(assign.model)
            if assign.fallback:
                models.add(assign.fallback)
        return sorted(models)

    def verify_startup_models(self) -> Dict[str, Any]:
        """Verify configured Gemini models against live API at startup."""
        gemini = self.providers["gemini"]
        return gemini.verify_models(self.configured_models())

    def get_spend_summary(self, session: Session) -> Dict[str, Any]:
        """Calculate real-time spend today, this month, by agent, and by provider."""
        now = datetime.now(timezone.utc)
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        rows = session.scalars(
            select(LLMCallLog).where(LLMCallLog.timestamp >= start_of_month)
        ).all()

        daily_total = 0.0
        monthly_total = 0.0
        board_daily_total = 0.0
        by_agent_daily: Dict[str, float] = {}
        by_provider_daily: Dict[str, float] = {}

        for r in rows:
            if r.status != "SUCCESS":
                continue
            cost = float(r.cost_usd or 0.0)
            monthly_total += cost
            ts = r.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= start_of_day:
                daily_total += cost
                by_agent_daily[r.agent_name] = by_agent_daily.get(r.agent_name, 0.0) + cost
                by_provider_daily[r.provider] = by_provider_daily.get(r.provider, 0.0) + cost
                if r.agent_name.startswith("director_"):
                    board_daily_total += cost

        cfg = self.settings
        per_agent_default_cap = round(cfg.global_daily_budget_usd * cfg.per_agent_daily_share_cap, 4)

        return {
            "global_daily_spend_usd": round(daily_total, 6),
            "global_daily_budget_usd": cfg.global_daily_budget_usd,
            "global_daily_utilization": round(
                daily_total / cfg.global_daily_budget_usd if cfg.global_daily_budget_usd > 0 else 0.0,
                4,
            ),
            "global_monthly_spend_usd": round(monthly_total, 6),
            "global_monthly_budget_usd": cfg.global_monthly_budget_usd,
            "board_daily_spend_usd": round(board_daily_total, 6),
            "board_daily_budget_usd": cfg.board_daily_budget_usd,
            "per_agent_default_daily_cap_usd": per_agent_default_cap,
            "soft_alert_ratio": cfg.budget_soft_alert_ratio,
            "hard_stop_ratio": cfg.budget_hard_stop_ratio,
            "by_agent_daily_usd": {k: round(v, 6) for k, v in sorted(by_agent_daily.items())},
            "by_provider_daily_usd": {k: round(v, 6) for k, v in sorted(by_provider_daily.items())},
        }

    def _enforce_pre_call_budgets_and_guards(
        self,
        session: Session,
        *,
        agent_name: str,
        estimated_call_cost_usd: float,
        task_id: Optional[str] = None,
    ) -> None:
        """Enforce runaway guards, 80% soft alerts, and 100% hard-stop budget caps before sending LLM call."""
        cfg = self.settings

        # 1. Runaway guard: check task max_llm_calls
        if task_id:
            task_rec = session.get(TaskRecord, task_id)
            if task_rec:
                limit = task_rec.max_llm_calls or cfg.max_llm_calls_per_task
                if task_rec.llm_calls_count >= limit:
                    task_rec.status = "FAILED"
                    task_rec.error_message = f"Runaway guard triggered: exceeded max_llm_calls ({limit})"
                    append_audit_log(
                        session,
                        actor=f"agent:{agent_name}",
                        action="cost.runaway_guard_triggered",
                        target=f"task:{task_id}",
                        outcome="HALTED",
                        why=f"Task '{task_id}' exceeded max LLM calls limit ({limit})",
                    )
                    EVENT_HUB.publish_sync(
                        "cost.runaway_guard",
                        {"agent_name": agent_name, "task_id": task_id, "max_llm_calls": limit},
                        severity="critical",
                    )
                    session.flush()
                    raise RunawayTaskError(
                        f"Task '{task_id}' exceeded maximum LLM call limit ({limit})."
                    )

        summary = self.get_spend_summary(session)
        projected_daily = summary["global_daily_spend_usd"] + estimated_call_cost_usd
        projected_monthly = summary["global_monthly_spend_usd"] + estimated_call_cost_usd
        agent_daily = summary["by_agent_daily_usd"].get(agent_name, 0.0) + estimated_call_cost_usd

        agent_rec = session.get(AgentRecord, agent_name)
        agent_cap = (
            float(agent_rec.custom_daily_cap_usd)
            if (agent_rec and agent_rec.custom_daily_cap_usd is not None)
            else round(cfg.global_daily_budget_usd * cfg.per_agent_daily_share_cap, 6)
        )

        # Check 100% Hard Stops (Global Daily, Global Monthly, Board Daily, Per-Agent 30% Cap)
        hard_stop_reason: Optional[str] = None
        if projected_daily > cfg.global_daily_budget_usd * cfg.budget_hard_stop_ratio:
            hard_stop_reason = (
                f"Global daily budget cap (${cfg.global_daily_budget_usd:.2f}) reached "
                f"(projected: ${projected_daily:.4f})"
            )
        elif projected_monthly > cfg.global_monthly_budget_usd * cfg.budget_hard_stop_ratio:
            hard_stop_reason = (
                f"Global monthly budget cap (${cfg.global_monthly_budget_usd:.2f}) reached "
                f"(projected: ${projected_monthly:.4f})"
            )
        elif agent_name.startswith("director_") and (
            summary["board_daily_spend_usd"] + estimated_call_cost_usd
            > cfg.board_daily_budget_usd * cfg.budget_hard_stop_ratio
        ):
            hard_stop_reason = (
                f"Board daily budget cap (${cfg.board_daily_budget_usd:.2f}) reached "
                f"(projected: ${summary['board_daily_spend_usd'] + estimated_call_cost_usd:.4f})"
            )
        elif agent_daily > agent_cap * cfg.budget_hard_stop_ratio:
            hard_stop_reason = (
                f"Agent '{agent_name}' exceeded its daily cap (${agent_cap:.2f}, 30% of global daily budget; "
                f"projected: ${agent_daily:.4f})"
            )

        if hard_stop_reason:
            if agent_rec and agent_rec.status == AgentOperationalStatus.ACTIVE.value:
                agent_rec.previous_status = agent_rec.status
                agent_rec.status = AgentOperationalStatus.PAUSED.value
                agent_rec.health_status = "degraded"
            append_audit_log(
                session,
                actor="agent:cost",
                action="cost.hard_stop_enforced",
                target=f"agent:{agent_name}",
                tier="2",
                outcome="HALTED",
                why=hard_stop_reason,
                details={
                    "agent_name": agent_name,
                    "estimated_call_cost_usd": estimated_call_cost_usd,
                    "tier2_escalation": "Request Chairman approval to raise budget cap",
                },
            )
            EVENT_HUB.publish_sync(
                "cost.hard_stop",
                {"agent_name": agent_name, "reason": hard_stop_reason, "tier": "2"},
                severity="critical",
            )
            session.flush()
            raise BudgetCapExceededError(hard_stop_reason)

        # Check 80% Soft Alerts
        soft_alerts: List[str] = []
        if projected_daily >= cfg.global_daily_budget_usd * cfg.budget_soft_alert_ratio:
            soft_alerts.append(
                f"Global daily spend at {(projected_daily / cfg.global_daily_budget_usd) * 100:.1f}% of ${cfg.global_daily_budget_usd:.2f}"
            )
        if agent_daily >= agent_cap * cfg.budget_soft_alert_ratio:
            soft_alerts.append(
                f"Agent '{agent_name}' spend at {(agent_daily / agent_cap) * 100:.1f}% of ${agent_cap:.2f} cap"
            )
        if soft_alerts:
            append_audit_log(
                session,
                actor="agent:cost",
                action="cost.soft_alert_80pct",
                target=f"agent:{agent_name}",
                outcome="ALERT",
                why="; ".join(soft_alerts),
            )
            EVENT_HUB.publish_sync(
                "cost.soft_alert",
                {"agent_name": agent_name, "alerts": soft_alerts},
                severity="warning",
            )

    def generate(
        self,
        session: Session,
        *,
        agent_name: str,
        prompt: str,
        system_instruction: Optional[str] = None,
        decision_id: Optional[str] = None,
        task_id: Optional[str] = None,
        allow_mock_in_dev: bool = True,
        max_retries: int = 2,
    ) -> LLMResponse:
        """Route an LLM request for `agent_name` with budget checks, retry/fallback, and logging."""
        assignment = self.get_assignment(agent_name)
        provider_name = assignment.provider.lower()
        provider = self.providers.get(provider_name)
        if not provider:
            raise ProviderUnavailableError(f"Unknown LLM provider '{provider_name}'")

        est_in_tokens = max(8, len(prompt) // 4)
        est_out_tokens = min(assignment.max_tokens, 512)
        est_cost = (
            provider.estimate_cost(assignment.model, est_in_tokens, est_out_tokens)
            if provider_name in ("gemini", "mock")
            else 0.001
        )

        # 1. Pre-call budget cap & runaway guard check (blocks before sending call)
        self._enforce_pre_call_budgets_and_guards(
            session,
            agent_name=agent_name,
            estimated_call_cost_usd=est_cost,
            task_id=task_id,
        )

        # 2. Check provider key availability & production fail-closed rule
        use_mock = False
        if provider_name == "mock":
            if self.settings.is_prod:
                append_audit_log(
                    session,
                    actor="system:model_router",
                    action="llm.mock_blocked_in_prod",
                    target=f"agent:{agent_name}",
                    outcome="DENIED",
                    why="Mock provider is strictly forbidden when ENV=prod",
                )
                session.flush()
                raise ProviderUnavailableError("Mock provider is forbidden in production.")
            use_mock = True
        elif provider_name == "gemini" and not self.settings.gemini_api_key:
            if self.settings.is_prod or not allow_mock_in_dev or not self.settings.is_dev_or_test:
                append_audit_log(
                    session,
                    actor="system:model_router",
                    action="llm.provider_unavailable",
                    target=f"agent:{agent_name}",
                    outcome="FAILED",
                    why="GEMINI_API_KEY is unset; failing closed without mock fallback.",
                )
                EVENT_HUB.publish_sync(
                    "llm.provider_unavailable",
                    {"agent_name": agent_name, "provider": "gemini"},
                    severity="critical",
                )
                session.flush()
                raise ProviderUnavailableError(
                    "GEMINI_API_KEY is unset; ModelRouter failed closed."
                )
            use_mock = True

        active_provider: BaseLLMProvider = self.providers["mock"] if use_mock else provider
        models_to_try = [assignment.model]
        if assignment.fallback and assignment.fallback != assignment.model:
            models_to_try.append(assignment.fallback)

        start_time = time.perf_counter()
        last_error: Optional[Exception] = None
        used_fallback = False
        chosen_model = assignment.model
        raw_result: Optional[Dict[str, Any]] = None

        for model_idx, candidate_model in enumerate(models_to_try):
            chosen_model = candidate_model
            used_fallback = model_idx > 0
            for attempt in range(max_retries):
                try:
                    raw_result = active_provider.generate(
                        model=candidate_model,
                        prompt=prompt,
                        system_instruction=system_instruction,
                        temperature=assignment.temperature,
                        max_tokens=assignment.max_tokens,
                    )
                    break
                except Exception as exc:
                    last_error = exc
                    if attempt + 1 < max_retries:
                        time.sleep(0.05 * (2**attempt))
            if raw_result is not None:
                break

        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        call_id = f"llm_{uuid.uuid4().hex[:16]}"

        if raw_result is None:
            # Log failed call and alert (NEVER fall back to mock in production)
            failed_log = LLMCallLog(
                call_id=call_id,
                timestamp=datetime.now(timezone.utc),
                agent_name=agent_name,
                provider=active_provider.provider_name,
                model=chosen_model,
                prompt_version=assignment.prompt_version,
                input_tokens=0,
                output_tokens=0,
                cost_usd=0.0,
                latency_ms=latency_ms,
                is_mock=use_mock,
                decision_id=decision_id,
                task_id=task_id,
                status="FAILED",
            )
            session.add(failed_log)
            append_audit_log(
                session,
                actor=f"agent:{agent_name}",
                action="llm.call_failed",
                target=chosen_model,
                outcome="FAILED",
                why=f"All retries and fallback models exhausted: {last_error}",
                details={"call_id": call_id, "decision_id": decision_id, "task_id": task_id},
            )
            EVENT_HUB.publish_sync(
                "llm.call_failed",
                {"agent_name": agent_name, "model": chosen_model, "error": str(last_error)},
                severity="error",
            )
            session.flush()
            raise ProviderUnavailableError(
                f"LLM generation failed for agent '{agent_name}' after retries and fallback: {last_error}"
            )

        in_tokens = int(raw_result["input_tokens"])
        out_tokens = int(raw_result["output_tokens"])
        actual_cost = active_provider.estimate_cost(chosen_model, in_tokens, out_tokens)

        call_log = LLMCallLog(
            call_id=call_id,
            timestamp=datetime.now(timezone.utc),
            agent_name=agent_name,
            provider=active_provider.provider_name,
            model=chosen_model,
            prompt_version=assignment.prompt_version,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            cost_usd=actual_cost,
            latency_ms=latency_ms,
            is_mock=use_mock,
            decision_id=decision_id,
            task_id=task_id,
            status="SUCCESS",
        )
        session.add(call_log)

        if task_id:
            task_rec = session.get(TaskRecord, task_id)
            if task_rec:
                task_rec.llm_calls_count += 1
                task_rec.actual_cost_usd = float(task_rec.actual_cost_usd or 0.0) + actual_cost

        agent_rec = session.get(AgentRecord, agent_name)
        if agent_rec:
            agent_rec.cost_today_usd = float(agent_rec.cost_today_usd or 0.0) + actual_cost

        session.flush()

        return LLMResponse(
            call_id=call_id,
            agent_name=agent_name,
            provider=active_provider.provider_name,
            model=chosen_model,
            prompt_version=assignment.prompt_version,
            text=str(raw_result["text"]),
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            cost_usd=actual_cost,
            latency_ms=latency_ms,
            mock=use_mock,
            used_fallback=used_fallback,
            decision_id=decision_id,
            task_id=task_id,
        )
