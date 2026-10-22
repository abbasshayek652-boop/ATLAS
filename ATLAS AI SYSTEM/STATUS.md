# Atlas AI System Status (`STATUS.md`)

**Current Checkpoint**: Phase 0 Foundation Complete (Waiting for Chairman `"continue"` before starting Phase 1 + Board Advisory).

---

## 1. What Works (Phase 0 Foundation)

- **Repository & Monorepo Structure**: `/core`, `/agents`, `/api`, `/db`, `/tests`, `/docs`, `/legacy`.
- **Database & Schema (`/db`)**:
  - SQLAlchemy 2.0 ORM supporting SQLite locally and PostgreSQL (Neon) in production.
  - Durable tables: `system_state`, `agent_registry`, `task_queue`, `audit_log`, `llm_call_log`, `refresh_tokens`, `auth_lockouts`, `charter_versions`.
- **Authentication, Authorization & Step-Up Security (`core/security.py`)**:
  - Single-owner Google OAuth 2.0 ID token verification (`OWNER_EMAIL` allowlist, audience, expiry, `email_verified=true`).
  - Short-lived Access JWT (15 min) + revocable SHA-256-hashed Refresh Token (7 days).
  - 5-minute Step-Up verification (`step_up_at` claim) enforced on resuming from SAFE mode, editing the Charter, and changing budget/threshold limits.
  - Scoped Machine Token (`MACHINE_API_TOKEN`, constant-time hash comparison) restricted strictly to `read:status`, `read:health`, `create:low_tier_task` (Tier 0/1), and `execute:kill_switch`.
  - Dev-only bypass (`DEV_OWNER_TOKEN`) strictly blocked when `ENV=prod` (fails startup immediately).
  - Sliding-window rate limiting and brute-force lockout (`AuthLockoutRecord`).
- **Agent Contract, Registry & LegacyAdapter (`core/agent_contract.py`, `core/agent_registry.py`, `core/legacy_adapter.py`)**:
  - All 49 catalog agents across 11 layers registered with capabilities, explicit permission allowlists, autonomy level (`L0`–`L3`), operational status, and target phase.
  - Active Phase 0 foundation agents: `audit` (Security Layer) and `health` (Infrastructure Layer).
  - `LegacyAdapter` interface with secret isolation (`build_sanitized_env`), forbidden direct permissions guard, and PAPER-mode trading lock.
- **DB-Backed Task Queue (`core/task_queue.py`)**:
  - Priority scheduling, idempotency keys (`idempotency_key`), schema validation (`TaskInput` / `TaskResult`), exponential retry backoff (`max_retries=3`), and Tier 2 failure escalation.
- **Model Router & Cost Enforcement (`core/model_router.py`, `core/model_router.yaml`)**:
  - Per-agent YAML configuration (`gemini-3.8-flash`, `gemini-4-argon`, `gemini-3.5-flash-lite` fallback, temperatures `0.2` / `0.4` / `0.6` / `0.7`).
  - Pre-call Cost Agent budget checks ($5/day global, $100/month global, $1/day Board, 30% single-agent daily share cap, 80% soft alert, 100% hard stop that pauses the agent, max 10 LLM calls per task runaway guard).
  - Fail-closed behavior in `ENV=prod` when `GEMINI_API_KEY` is unset (`ProviderUnavailableError`).
  - Deterministic `MockLLMProvider` restricted to `ENV=dev`/`ENV=test`, tagged `mock=True`, blocked from triggering Tier 1 / Tier 1.5 execution.
- **Tamper-Evident Append-Only Audit Log (`core/audit.py`)**:
  - SHA-256 cryptographic hash chain (`prev_hash` -> `entry_hash`), automatic secret redaction, ORM `before_update`/`before_delete` tamper guards (`AuditTamperError`), and `/api/v1/audit/verify` verification endpoint.
- **Emergency Kill Switch (`core/kill_switch.py`)**:
  - `POST /api/v1/kill-switch` halts all active agents, cancels pending jobs, enters `SAFE` mode, logs to `audit_log`, and broadcasts via WebSocket `/events` independently of Atlas CEO.
- **Documentation & Deployment**:
  - `docs/openapi.json`, `docs/API.md`, `docs/ARCHITECTURE.md`, `docs/AGENT_CONTRACT.md`, `docs/DECISION_POLICY.md`, `Dockerfile`, `.github/workflows/ci.yml`, `.github/workflows/deploy-cloudrun.yml`, `cloudbuild.yaml`.

---

## 2. Not implemented (Raises `NotImplementedError`)

Every item below explicitly raises `NotImplementedError` (or returns HTTP `501 Not Implemented` on REST routes) and has zero fake stub behavior:

1. **LLM Provider Adapters (`core/model_router.py`)**:
   - `OpenAIProviderPlaceholder.generate()` / `estimate_cost()` — raises `NotImplementedError` (scheduled for future multi-provider expansion).
   - `AnthropicProviderPlaceholder.generate()` / `estimate_cost()` — raises `NotImplementedError` (scheduled for future multi-provider expansion).
2. **Phase 1+ REST API Endpoints (`api/routes.py`)**:
   - `GET /api/v1/decisions` — Decision Engine log query (scheduled for Phase 1).
   - `GET /api/v1/approvals` — Tier 2 Approval Inbox listing (scheduled for Phase 1).
   - `POST /api/v1/approvals/{approval_id}/{decision_action}` — Tier 2 Approve / Reject / Modify workflow (scheduled for Phase 1; auth & step-up guards active now).
   - `GET /api/v1/board/members` — Board of Directors Advisory Mode endpoints (scheduled for Phase 1 + Board Advisory).
   - `GET /api/v1/recommendations` — Learning Layer recommendations (scheduled for Phase 2).
   - `GET /api/v1/trading/mode` and `GET /api/v1/trading/pnl` — Trading mode & P&L endpoints (scheduled for Phase 4).
3. **Planned Catalog Agents (`status=PLANNED`, `autonomy_level=L0` in `core/agent_registry.py`)**:
   - Calling `run()` on any of the 47 `PLANNED` agents raises `NotImplementedError`:
     - **Phase 1 Agents (to be activated in Phase 1)**: `atlas`, `scheduler`, `workflow`, `memory`, `cost`, `security`, `compliance`, `risk`, `notification`, `dashboard`.
     - **Phase 2 Agents (Finance & Intelligence & Learning)**: `wallet`, `financial_planner`, `accounting`, `investment`, `learning_engine` (pre-existing catalog spec, `PLANNED` L0), `pattern_recognition`, `recommendation`, `self_evaluation`, `research`, `news`, `sentiment`, `economic`, `competitor`.
     - **Phase 3 Agents (Content & Business)**: `content`, `linkedin` (pre-existing catalog spec, `PLANNED` L0), `youtube`, `tiktok`, `newsletter`, `seo`, `freelance`, `crm`, `proposal`, `opportunity`.
     - **Phase 4 Agents (Trading — PAPER mode)**: `crypto_trading` (pre-existing catalog spec, `PLANNED` L0), `gold_trading` (pre-existing catalog spec, `PLANNED` L0), `strategy`, `backtesting`, `portfolio`, `arbitrage`, `market_regime`.
     - **Phase 5 Agents (Infrastructure & Development)**: `monitoring`, `deployment`, `backup`, `code_suggestion`, `documentation`, `testing`, `debug`.
4. **Legacy Code Wiring (`core/legacy_adapter.py`)**:
   - `LegacyAdapter` base contract is implemented and tested, but no legacy scripts are wired in `/legacy` yet (`status=PLANNED` raises `NotImplementedError`).

---

## 3. What Is Next (Phase 1 + Board of Directors Advisory Mode)

Upon receiving `"continue"` from the Chairman:
1. Activate **Atlas (CEO)**, **Decision Engine** (deterministic Tiers `0`, `1`, `1.5`, `2`, `3` + approval inbox with expiry), **Scheduler**, **Workflow Agent** (n8n webhook integration), **Memory Agent**, **Notification Agent** (Telegram owner-only chat ID + low-risk approval threshold), **Dashboard Agent**, **Cost Agent**, **Security Agent**, **Compliance Agent**, and **Risk Agent** (independent vetoes).
2. Implement the **Board of Directors (6 Directors in Advisory Mode)**:
   - `Capital Director`, `Strategy Director`, `Technology Director`, `Operations Director`, `Growth Director`, and `Devil's Advocate`.
   - Enforce backend blind voting, Devil's Advocate mandatory pre-tally challenge, deterministic quorum/majority/escalation calculation, and full audit logging with `tier_1_5_enabled = False` (no execution authority).
3. Update `docs/openapi.json` and `docs/API.md` with all Phase 1 + Board endpoints and run the end-to-end demo scenario.
