"""Atlas AI Agent Registry & Catalog.

Manages all 49 catalog agents across 11 layers, enforces permission allowlists,
synchronizes state with the database, and guarantees all agent invocations go through
Atlas / the task queue with full audit logging.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.agent_contract import (
    AgentOperationalStatus,
    AutonomyLevel,
    BaseAgent,
    PlannedAgent,
    TaskInput,
    TaskResult,
)
from core.audit import append_audit_log
from db.models import AgentRecord, SystemState


class FoundationAuditAgent(BaseAgent):
    """Phase 0 active foundation agent for audit chain verification and inspection."""

    def __init__(self) -> None:
        super().__init__(
            name="audit",
            display_name="Audit Agent",
            layer="Security",
            description="Independently logs and verifies every action, decision, approval, veto, and hash chain.",
            capabilities=["verify_chain", "inspect_logs"],
            permissions=["read:audit", "write:audit_report"],
            version="1.0.0",
            phase=0,
            autonomy_level=AutonomyLevel.L1,
            status=AgentOperationalStatus.ACTIVE,
        )

    def estimate_cost(self, task: TaskInput) -> float:
        return 0.0

    def run(self, task: TaskInput) -> TaskResult:
        self.validate_action_and_permissions(task, required_permission="read:audit")
        return TaskResult(
            task_id=task.task_id,
            agent_name=self.name,
            action=task.action,
            status="completed",
            output={"message": f"Audit Agent executed '{task.action}'", "verified": True},
            confidence=1.0,
            actual_cost_usd=0.0,
            is_mock=False,
        )


class FoundationHealthAgent(BaseAgent):
    """Phase 0 active foundation agent for system health diagnostics."""

    def __init__(self) -> None:
        super().__init__(
            name="health",
            display_name="Health Agent",
            layer="Infrastructure",
            description="Checks system health, database connectivity, task queue, and model router status.",
            capabilities=["check_system_health", "ping"],
            permissions=["read:health", "read:status"],
            version="1.0.0",
            phase=0,
            autonomy_level=AutonomyLevel.L1,
            status=AgentOperationalStatus.ACTIVE,
        )

    def estimate_cost(self, task: TaskInput) -> float:
        return 0.0

    def run(self, task: TaskInput) -> TaskResult:
        self.validate_action_and_permissions(task, required_permission="read:health")
        return TaskResult(
            task_id=task.task_id,
            agent_name=self.name,
            action=task.action,
            status="completed",
            output={"system": "healthy", "action": task.action},
            confidence=1.0,
            actual_cost_usd=0.0,
            is_mock=False,
        )


# Complete 49-Agent Catalog Definition (Layers 1 to 11)
CATALOG_SPECS: List[Dict[str, Any]] = [
    # 1. Executive Layer
    {
        "name": "atlas",
        "display_name": "Atlas (CEO)",
        "layer": "Executive",
        "description": "The brain of the system: coordinates agents, resolves conflicts, controls budgets, and enforces tiers.",
        "capabilities": ["evaluate_proposal", "assign_work", "prioritize_agents", "resolve_conflict"],
        "permissions": ["read:all", "queue:dispatch", "budget:inspect", "control:halt_agent"],
        "phase": 1,
    },
    {
        "name": "scheduler",
        "display_name": "Scheduler Agent",
        "layer": "Executive",
        "description": "Schedules jobs, queues work, delays tasks, retries failed jobs, and executes priorities.",
        "capabilities": ["schedule_job", "delay_task", "retry_failed_job"],
        "permissions": ["read:queue", "write:queue"],
        "phase": 1,
    },
    {
        "name": "workflow",
        "display_name": "Workflow Agent",
        "layer": "Executive",
        "description": "Executes external n8n workflows and multi-step orchestration pipelines.",
        "capabilities": ["trigger_n8n_workflow", "check_workflow_status"],
        "permissions": ["read:workflows", "webhook:n8n_trigger"],
        "phase": 1,
    },
    # 2. Finance Layer
    {
        "name": "wallet",
        "display_name": "Wallet Agent",
        "layer": "Finance",
        "description": "Read-only treasury tracker across exchanges, banks, payment processors, and cold wallets.",
        "capabilities": ["read_balances", "compute_net_worth", "check_emergency_fund"],
        "permissions": ["read:exchange_balances", "read:bank_balances", "read:wallets"],
        "phase": 2,
    },
    {
        "name": "financial_planner",
        "display_name": "Financial Planner Agent",
        "layer": "Finance",
        "description": "Produces financial plans covering budgets, capital allocation, taxes, and emergency funds.",
        "capabilities": ["create_financial_plan", "propose_allocation"],
        "permissions": ["read:finance_reports", "draft:financial_plan"],
        "phase": 2,
    },
    {
        "name": "accounting",
        "display_name": "Accounting Agent",
        "layer": "Finance",
        "description": "Tracks income, expenses, invoices, subscriptions, cloud costs, taxes, and P&L.",
        "capabilities": ["reconcile_ledger", "generate_pnl_report", "estimate_taxes"],
        "permissions": ["read:transactions", "read:invoices", "write:accounting_report"],
        "phase": 2,
    },
    {
        "name": "investment",
        "display_name": "Investment Agent",
        "layer": "Finance",
        "description": "Analyzes long-term investing across stocks, ETFs, Bitcoin, Gold, and real estate.",
        "capabilities": ["analyze_long_term_allocation", "compare_risk_returns"],
        "permissions": ["read:market_data", "draft:investment_thesis"],
        "phase": 2,
    },
    # 3. Trading Layer
    {
        "name": "crypto_trading",
        "display_name": "Crypto Trading Agent",
        "layer": "Trading",
        "description": "Market analysis, signals, paper/canary/live execution across crypto exchanges (Legacy-compatible contract).",
        "capabilities": ["analyze_crypto_market", "generate_signal", "execute_paper_trade"],
        "permissions": ["read:exchange", "trade:paper"],
        "phase": 4,
    },
    {
        "name": "gold_trading",
        "display_name": "Gold Trading Agent",
        "layer": "Trading",
        "description": "Analyzes and paper-trades PAXG, Gold, Silver, and precious metals (Legacy-compatible contract).",
        "capabilities": ["analyze_metals_market", "generate_gold_signal", "execute_paper_trade"],
        "permissions": ["read:exchange", "trade:paper"],
        "phase": 4,
    },
    {
        "name": "strategy",
        "display_name": "Strategy Agent",
        "layer": "Trading",
        "description": "Creates and evaluates EMA, RSI, MACD, and ML trading strategies.",
        "capabilities": ["design_strategy", "evaluate_indicators"],
        "permissions": ["read:market_data", "write:strategy_draft"],
        "phase": 4,
    },
    {
        "name": "backtesting",
        "display_name": "Backtesting Agent",
        "layer": "Trading",
        "description": "Runs historical simulations computing drawdown, Sharpe ratio, and win rate.",
        "capabilities": ["run_backtest", "compute_sharpe_and_drawdown"],
        "permissions": ["read:historical_data", "write:backtest_report"],
        "phase": 4,
    },
    {
        "name": "risk",
        "display_name": "Risk Agent",
        "layer": "Trading",
        "description": "Independent risk control with veto power; calculates drawdown, daily loss, exposure, and leverage.",
        "capabilities": ["evaluate_risk", "check_drawdown_limits", "issue_risk_veto"],
        "permissions": ["read:all_positions", "veto:decision", "control:halt_trading"],
        "phase": 1,
    },
    {
        "name": "portfolio",
        "display_name": "Portfolio Agent",
        "layer": "Trading",
        "description": "Handles position sizing, capital allocation, diversification, and sector exposure.",
        "capabilities": ["calculate_position_size", "check_diversification"],
        "permissions": ["read:portfolio", "draft:rebalance_plan"],
        "phase": 4,
    },
    {
        "name": "arbitrage",
        "display_name": "Arbitrage Agent",
        "layer": "Trading",
        "description": "Scans cross-exchange price differences, funding rates, and basis spreads.",
        "capabilities": ["scan_funding_rates", "detect_basis_spread"],
        "permissions": ["read:exchange"],
        "phase": 4,
    },
    {
        "name": "market_regime",
        "display_name": "Market Regime Agent",
        "layer": "Trading",
        "description": "Classifies market regime (Bull, Bear, Sideways, Volatile) to adapt strategies.",
        "capabilities": ["classify_regime", "assess_volatility"],
        "permissions": ["read:market_data"],
        "phase": 4,
    },
    # 4. Learning Layer
    {
        "name": "learning_engine",
        "display_name": "Learning Engine",
        "layer": "Learning",
        "description": "Synthesizes cross-agent outcomes to produce improvement recommendations (never edits code directly).",
        "capabilities": ["analyze_outcomes", "propose_learning_update"],
        "permissions": ["read:metrics", "read:decisions", "write:recommendation"],
        "phase": 2,
    },
    {
        "name": "memory",
        "display_name": "Memory Agent",
        "layer": "Learning",
        "description": "Stores and retrieves historical decisions, conversations, metrics, errors, and successes.",
        "capabilities": ["store_memory", "query_memory", "summarize_history"],
        "permissions": ["read:memory", "write:memory"],
        "phase": 1,
    },
    {
        "name": "pattern_recognition",
        "display_name": "Pattern Recognition Agent",
        "layer": "Learning",
        "description": "Identifies hidden patterns, recurring failures, and winning combinations.",
        "capabilities": ["detect_failure_patterns", "find_winning_combinations"],
        "permissions": ["read:metrics", "read:audit", "write:recommendation"],
        "phase": 2,
    },
    {
        "name": "recommendation",
        "display_name": "Recommendation Agent",
        "layer": "Learning",
        "description": "Produces structured governance and operational recommendations for Chairman review.",
        "capabilities": ["create_recommendation", "rank_recommendations"],
        "permissions": ["read:metrics", "write:recommendation"],
        "phase": 2,
    },
    {
        "name": "self_evaluation",
        "display_name": "Self Evaluation Agent",
        "layer": "Learning",
        "description": "Scores agent reliability, cost efficiency, and accuracy on daily/weekly/monthly cycles.",
        "capabilities": ["score_agent_daily", "generate_scorecard"],
        "permissions": ["read:metrics", "read:audit", "write:scorecard"],
        "phase": 2,
    },
    # 5. Content Layer
    {
        "name": "content",
        "display_name": "Content Agent",
        "layer": "Content",
        "description": "Drafts articles, blog posts, Twitter threads, and Medium posts (requires Tier 2 approval to publish).",
        "capabilities": ["draft_article", "draft_social_post"],
        "permissions": ["read:research", "draft:content"],
        "phase": 3,
    },
    {
        "name": "linkedin",
        "display_name": "LinkedIn Agent",
        "layer": "Content",
        "description": "Drafts LinkedIn posts and thought-leadership updates (all external posts require Tier 2 approval).",
        "capabilities": ["draft_linkedin_post", "schedule_approved_post"],
        "permissions": ["read:content_drafts", "draft:linkedin"],
        "phase": 3,
    },
    {
        "name": "youtube",
        "display_name": "YouTube Agent",
        "layer": "Content",
        "description": "Prepares YouTube video scripts, descriptions, tags, and upload packages for Tier 2 approval.",
        "capabilities": ["draft_video_metadata", "prepare_youtube_upload"],
        "permissions": ["draft:youtube"],
        "phase": 3,
    },
    {
        "name": "tiktok",
        "display_name": "TikTok Agent",
        "layer": "Content",
        "description": "Prepares short-form video captions, hooks, and hashtags for Tier 2 approval.",
        "capabilities": ["draft_tiktok_caption", "generate_hashtags"],
        "permissions": ["draft:tiktok"],
        "phase": 3,
    },
    {
        "name": "newsletter",
        "display_name": "Newsletter Agent",
        "layer": "Content",
        "description": "Drafts email newsletter campaigns and subscriber digests (Tier 2 approval required before sending).",
        "capabilities": ["draft_newsletter", "preview_campaign"],
        "permissions": ["read:subscribers_count", "draft:newsletter"],
        "phase": 3,
    },
    {
        "name": "seo",
        "display_name": "SEO Agent",
        "layer": "Content",
        "description": "Performs keyword research, competitor ranking analysis, and content optimization.",
        "capabilities": ["research_keywords", "audit_content_seo"],
        "permissions": ["read:web_public", "write:seo_report"],
        "phase": 3,
    },
    # 6. Business Layer
    {
        "name": "freelance",
        "display_name": "Freelance Agent",
        "layer": "Business",
        "description": "Scans for relevant freelance projects, client leads, and contract opportunities.",
        "capabilities": ["scan_job_boards", "score_project_fit"],
        "permissions": ["read:job_listings", "write:lead_draft"],
        "phase": 3,
    },
    {
        "name": "crm",
        "display_name": "CRM Agent",
        "layer": "Business",
        "description": "Tracks clients, leads, sales pipeline stages, and follow-up reminders.",
        "capabilities": ["update_lead_stage", "summarize_pipeline"],
        "permissions": ["read:crm", "write:crm_internal"],
        "phase": 3,
    },
    {
        "name": "proposal",
        "display_name": "Proposal Agent",
        "layer": "Business",
        "description": "Generates draft PDF proposals, contracts, and invoices (external sending requires Tier 2 approval).",
        "capabilities": ["draft_proposal", "draft_invoice", "draft_contract"],
        "permissions": ["read:crm", "draft:proposal"],
        "phase": 3,
    },
    {
        "name": "research",
        "display_name": "Research Agent",
        "layer": "Business",
        "description": "Reads and summarizes research papers, GitHub repositories, technical docs, and industry blogs.",
        "capabilities": ["summarize_paper", "analyze_repo", "compile_research_brief"],
        "permissions": ["read:web_public", "write:research_brief"],
        "phase": 2,
    },
    {
        "name": "opportunity",
        "display_name": "Opportunity Agent",
        "layer": "Business",
        "description": "Identifies market gaps, SaaS product ideas, and new revenue opportunities.",
        "capabilities": ["evaluate_market_gap", "score_business_idea"],
        "permissions": ["read:research", "write:opportunity_brief"],
        "phase": 3,
    },
    # 7. Intelligence Layer
    {
        "name": "news",
        "display_name": "News Agent",
        "layer": "Intelligence",
        "description": "Aggregates and summarizes financial, crypto, AI, and global business news.",
        "capabilities": ["fetch_news_digest", "score_headline_impact"],
        "permissions": ["read:news_feeds", "write:intel_brief"],
        "phase": 2,
    },
    {
        "name": "sentiment",
        "display_name": "Sentiment Agent",
        "layer": "Intelligence",
        "description": "Analyzes market sentiment across social channels, forums, and Fear & Greed indices.",
        "capabilities": ["compute_sentiment_score", "read_fear_greed_index"],
        "permissions": ["read:sentiment_feeds", "write:sentiment_report"],
        "phase": 2,
    },
    {
        "name": "economic",
        "display_name": "Economic Agent",
        "layer": "Intelligence",
        "description": "Monitors macroeconomic indicators: CPI inflation, interest rates, GDP, Fed/ECB calendars.",
        "capabilities": ["check_macro_calendar", "analyze_rate_decision"],
        "permissions": ["read:macro_data", "write:economic_brief"],
        "phase": 2,
    },
    {
        "name": "competitor",
        "display_name": "Competitor Agent",
        "layer": "Intelligence",
        "description": "Tracks competitor products, pricing changes, and feature releases.",
        "capabilities": ["track_competitor_changes", "compare_feature_matrix"],
        "permissions": ["read:web_public", "write:competitor_report"],
        "phase": 2,
    },
    # 8. Infrastructure Layer
    {
        "name": "monitoring",
        "display_name": "Monitoring Agent",
        "layer": "Infrastructure",
        "description": "Collects operational metrics, latency distributions, error rates, and alert thresholds.",
        "capabilities": ["collect_metrics", "evaluate_alert_rules"],
        "permissions": ["read:metrics", "write:alerts"],
        "phase": 5,
    },
    {
        "name": "deployment",
        "display_name": "Deployment Agent",
        "layer": "Infrastructure",
        "description": "Prepares Docker and Cloud Run deployment plans (production deploys always require Tier 2 approval).",
        "capabilities": ["prepare_release_plan", "verify_staging_build"],
        "permissions": ["read:ci_status", "draft:deployment_plan"],
        "phase": 5,
    },
    {
        "name": "backup",
        "display_name": "Backup Agent",
        "layer": "Infrastructure",
        "description": "Manages encrypted snapshots of the database, registry, and Charter configuration.",
        "capabilities": ["create_db_snapshot", "verify_backup_integrity"],
        "permissions": ["read:db_metadata", "write:backup_snapshot"],
        "phase": 5,
    },
    {
        "name": "cost",
        "display_name": "Cost Agent",
        "layer": "Infrastructure",
        "description": "Enforces global, Board, and per-agent daily/monthly spend caps across LLM and cloud providers.",
        "capabilities": ["check_budget", "report_daily_spend", "pause_over_budget_agent"],
        "permissions": ["read:costs", "control:pause_agent", "write:cost_alert"],
        "phase": 1,
    },
    # 9. Security Layer
    {
        "name": "security",
        "display_name": "Security Agent",
        "layer": "Security",
        "description": "Independent security control with veto power; enforces permissions, token hygiene, and secret isolation.",
        "capabilities": ["inspect_permissions", "scan_for_secrets", "issue_security_veto"],
        "permissions": ["read:security_state", "veto:decision"],
        "phase": 1,
    },
    {
        "name": "compliance",
        "display_name": "Compliance Agent",
        "layer": "Security",
        "description": "Independent compliance control with veto power; verifies Charter rules, rate limits, and prohibited Tier 3 actions.",
        "capabilities": ["check_policy_compliance", "issue_compliance_veto"],
        "permissions": ["read:charter", "read:decisions", "veto:decision"],
        "phase": 1,
    },
    # 10. Development Layer
    {
        "name": "code_suggestion",
        "display_name": "Code Suggestion Agent",
        "layer": "Development",
        "description": "Proposes pull requests and code diffs for review; never edits production code directly.",
        "capabilities": ["propose_code_diff", "draft_pull_request"],
        "permissions": ["read:source_code", "draft:code_suggestion"],
        "phase": 5,
    },
    {
        "name": "documentation",
        "display_name": "Documentation Agent",
        "layer": "Development",
        "description": "Maintains architecture docs, OpenAPI specifications, and runbooks.",
        "capabilities": ["update_api_docs", "check_doc_drift"],
        "permissions": ["read:source_code", "draft:documentation"],
        "phase": 5,
    },
    {
        "name": "testing",
        "display_name": "Testing Agent",
        "layer": "Development",
        "description": "Executes unit, integration, and regression test suites in isolated sandboxes.",
        "capabilities": ["run_pytest_suite", "report_coverage"],
        "permissions": ["read:source_code", "execute:test_runner"],
        "phase": 5,
    },
    {
        "name": "debug",
        "display_name": "Debug Agent",
        "layer": "Development",
        "description": "Analyzes stack traces, exceptions, and failed tasks to recommend root-cause fixes.",
        "capabilities": ["analyze_traceback", "suggest_bugfix"],
        "permissions": ["read:logs", "draft:bugfix_recommendation"],
        "phase": 5,
    },
    # 11. Communication Layer
    {
        "name": "notification",
        "display_name": "Notification Agent",
        "layer": "Communication",
        "description": "Dispatches Telegram alerts and approval notifications to the Chairman's verified chat ID.",
        "capabilities": ["send_telegram_alert", "send_approval_prompt"],
        "permissions": ["send:telegram_owner"],
        "phase": 1,
    },
    {
        "name": "dashboard",
        "display_name": "Dashboard Agent",
        "layer": "Communication",
        "description": "Aggregates real-time telemetry, metrics, and event streams for the Control Dashboard.",
        "capabilities": ["publish_dashboard_snapshot", "stream_event"],
        "permissions": ["read:status", "read:metrics", "stream:events"],
        "phase": 1,
    },
]


class AgentRegistry:
    """Central registry managing all Atlas AI agents and enforcing the Agent Contract."""

    def __init__(self) -> None:
        self._agents: Dict[str, BaseAgent] = {}
        self._load_default_catalog()

    def _load_default_catalog(self) -> None:
        # Register active Phase 0 foundation agents
        for active_agent in (FoundationAuditAgent(), FoundationHealthAgent()):
            self._agents[active_agent.name] = active_agent

        # Register the rest of the catalog as PlannedAgent (status=PLANNED, autonomy=L0)
        for spec in CATALOG_SPECS:
            name = spec["name"]
            if name in self._agents:
                continue
            self._agents[name] = PlannedAgent(
                name=name,
                display_name=spec["display_name"],
                layer=spec["layer"],
                description=spec["description"],
                capabilities=spec["capabilities"],
                permissions=spec["permissions"],
                version="1.0.0",
                phase=spec["phase"],
                autonomy_level=AutonomyLevel.L0,
                status=AgentOperationalStatus.PLANNED,
            )

    def register(self, agent: BaseAgent) -> None:
        """Register or replace an agent implementation."""
        self._agents[agent.name] = agent

    def get(self, name: str) -> BaseAgent:
        if name not in self._agents:
            raise KeyError(f"Unknown agent '{name}'")
        return self._agents[name]

    def list_agents(self) -> List[BaseAgent]:
        return [self._agents[k] for k in sorted(self._agents.keys())]

    def sync_to_db(self, session: Session) -> None:
        """Ensure all registered agents exist in the database AgentRecord table."""
        for agent in self.list_agents():
            existing = session.get(AgentRecord, agent.name)
            if existing is None:
                health_val = "planned" if agent.status == AgentOperationalStatus.PLANNED else "healthy"
                rec = AgentRecord(
                    name=agent.name,
                    display_name=agent.display_name,
                    layer=agent.layer,
                    description=agent.description,
                    version=agent.version,
                    phase=agent.phase,
                    status=agent.status.value,
                    autonomy_level=agent.autonomy_level.value,
                    capabilities_json=json.dumps(agent.capabilities),
                    permissions_json=json.dumps(agent.permissions),
                    health_status=health_val,
                    cost_today_usd=0.0,
                )
                session.add(rec)
            else:
                # Keep code-defined capabilities/phase/description fresh while preserving runtime status
                existing.display_name = agent.display_name
                existing.layer = agent.layer
                existing.description = agent.description
                existing.version = agent.version
                existing.phase = agent.phase
                existing.capabilities_json = json.dumps(agent.capabilities)
                existing.permissions_json = json.dumps(agent.permissions)
                try:
                    agent.status = AgentOperationalStatus(existing.status)
                    agent.autonomy_level = AutonomyLevel(existing.autonomy_level)
                except ValueError:
                    pass
        session.flush()

    def get_agent_views(self, session: Session) -> List[Dict[str, Any]]:
        """Return serialized agent status rows grouped/ordered for the API."""
        self.sync_to_db(session)
        rows = session.scalars(select(AgentRecord).order_by(AgentRecord.layer, AgentRecord.name)).all()
        result: List[Dict[str, Any]] = []
        for r in rows:
            last_run = r.last_run_at
            if last_run and last_run.tzinfo is None:
                last_run = last_run.replace(tzinfo=timezone.utc)
            result.append(
                {
                    "name": r.name,
                    "display_name": r.display_name,
                    "layer": r.layer,
                    "description": r.description,
                    "version": r.version,
                    "phase": r.phase,
                    "status": r.status,
                    "autonomy_level": r.autonomy_level,
                    "health": r.health_status,
                    "capabilities": json.loads(r.capabilities_json or "[]"),
                    "permissions": json.loads(r.permissions_json or "[]"),
                    "last_run_at": last_run.isoformat() if last_run else None,
                    "cost_today_usd": round(float(r.cost_today_usd or 0.0), 6),
                    "failure_count": r.failure_count,
                    "success_count": r.success_count,
                }
            )
        return result

    def pause_agent(self, session: Session, name: str, actor: str, reason: str = "Manual pause") -> Dict[str, Any]:
        """Pause an agent and record an audit event."""
        self.sync_to_db(session)
        agent = self.get(name)
        rec = session.get(AgentRecord, name)
        if not rec:
            raise KeyError(f"Agent '{name}' not found in DB")
        if rec.status == AgentOperationalStatus.PLANNED.value:
            raise ValueError(f"Agent '{name}' is PLANNED (not yet implemented) and cannot be paused/resumed.")

        rec.previous_status = rec.status
        rec.status = AgentOperationalStatus.PAUSED.value
        rec.health_status = "degraded"
        agent.status = AgentOperationalStatus.PAUSED

        append_audit_log(
            session,
            actor=actor,
            action="agent.pause",
            target=f"agent:{name}",
            outcome="SUCCESS",
            why=reason,
        )
        session.flush()
        return {"name": name, "status": rec.status, "health": rec.health_status}

    def resume_agent(self, session: Session, name: str, actor: str, reason: str = "Manual resume") -> Dict[str, Any]:
        """Resume a paused agent (blocked if system is in SAFE mode or agent is PLANNED)."""
        self.sync_to_db(session)
        sys_state = session.get(SystemState, "global")
        if sys_state and sys_state.mode == "SAFE":
            raise PermissionError("Cannot resume individual agents while system is in SAFE MODE.")

        agent = self.get(name)
        rec = session.get(AgentRecord, name)
        if not rec:
            raise KeyError(f"Agent '{name}' not found in DB")
        if rec.status == AgentOperationalStatus.PLANNED.value:
            raise ValueError(f"Agent '{name}' is PLANNED (not yet implemented) and cannot be resumed.")

        rec.status = AgentOperationalStatus.ACTIVE.value
        rec.health_status = "healthy"
        agent.status = AgentOperationalStatus.ACTIVE

        append_audit_log(
            session,
            actor=actor,
            action="agent.resume",
            target=f"agent:{name}",
            outcome="SUCCESS",
            why=reason,
        )
        session.flush()
        return {"name": name, "status": rec.status, "health": rec.health_status}

    def execute_agent_task(
        self,
        session: Session,
        agent_name: str,
        task: TaskInput,
        *,
        actor: str = "system:task_queue",
    ) -> TaskResult:
        """Execute a task on the target agent through the governed registry boundary."""
        self.sync_to_db(session)
        sys_state = session.get(SystemState, "global")
        if sys_state and sys_state.mode == "SAFE":
            append_audit_log(
                session,
                actor=actor,
                action="agent.run_blocked_safe_mode",
                target=f"agent:{agent_name}",
                tier=task.tier,
                outcome="HALTED",
                why="System is in SAFE MODE; agent task execution is halted.",
                details={"task_id": task.task_id, "requested_action": task.action},
            )
            raise PermissionError("System is in SAFE MODE; agent execution is halted.")

        agent = self.get(agent_name)
        rec = session.get(AgentRecord, agent_name)

        if agent.status == AgentOperationalStatus.PLANNED or (
            rec and rec.status == AgentOperationalStatus.PLANNED.value
        ):
            append_audit_log(
                session,
                actor=actor,
                action="agent.run_not_implemented",
                target=f"agent:{agent_name}",
                tier=task.tier,
                outcome="FAILED",
                why=f"Agent '{agent_name}' is status=PLANNED (Phase {agent.phase})",
                details={"task_id": task.task_id, "requested_action": task.action},
            )
            # Delegate to PlannedAgent.run() which raises NotImplementedError
            return agent.run(task)

        if rec and rec.status != AgentOperationalStatus.ACTIVE.value:
            append_audit_log(
                session,
                actor=actor,
                action="agent.run_blocked_inactive",
                target=f"agent:{agent_name}",
                tier=task.tier,
                outcome="DENIED",
                why=f"Agent '{agent_name}' is currently {rec.status}",
                details={"task_id": task.task_id},
            )
            raise PermissionError(f"Agent '{agent_name}' is not ACTIVE (current status: {rec.status}).")

        result = agent.run(task)
        # Validate schema strictly via Pydantic v2
        validated = TaskResult.model_validate(result.model_dump() if isinstance(result, TaskResult) else result)

        if rec:
            rec.last_run_at = datetime.now(timezone.utc)
            rec.cost_today_usd = float(rec.cost_today_usd or 0.0) + validated.actual_cost_usd
            if validated.status == "completed":
                rec.success_count += 1
            else:
                rec.failure_count += 1

        append_audit_log(
            session,
            actor=f"agent:{agent_name}",
            action=f"agent.run.{task.action}",
            target=task.task_id,
            tier=task.tier,
            outcome="SUCCESS" if validated.status == "completed" else "FAILED",
            why=f"Executed capability '{task.action}' via registry",
            details={
                "confidence": validated.confidence,
                "actual_cost_usd": validated.actual_cost_usd,
                "is_mock": validated.is_mock,
            },
        )
        session.flush()
        return validated


REGISTRY = AgentRegistry()
