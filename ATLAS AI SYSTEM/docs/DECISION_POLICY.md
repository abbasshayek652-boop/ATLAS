# Atlas AI Decision Policy, Budgets & Governance Charter

## 1. Decision Tiers & Deterministic Precedence

Every proposed action is evaluated deterministically before any LLM reasoning is consulted. An LLM may recommend **raising** a decision tier, but may **never lower** a tier determined by policy.

Classification runs in strict order (most restrictive rule wins):

1. **TIER 3 — FORBIDDEN FOR AGENTS**:
   - Withdrawals or transfers to new addresses
   - Modifying API keys, tokens, or secrets
   - Disabling or bypassing Risk, Security, Compliance, or Audit agents
   - Editing or deleting audit logs
   - Editing production code or own prompts without approval
   - Enabling the Board's own execution mode or raising its own budget
2. **TIER 2 — HUMAN (CHAIRMAN) APPROVAL REQUIRED**:
   - Moving or committing real money, or any spend `> $1.00` per action (`TIER2_ACTION_COST_THRESHOLD_USD`)
   - Enabling `CANARY` or `LIVE` trading
   - Publishing or sending anything externally in the Chairman's name (LinkedIn posts, articles, emails, proposals, invoices, contracts)
   - Production deployments, new permissions/integrations, Charter modifications, or changing risk/budget limits
   - Low-confidence proposals (`confidence < 0.70`)
   - Disagreement/conflict between two or more agents
   - Any active veto from Risk, Security, or Compliance
   - Any escalation vote from a Board Director
3. **TIER 1.5 — BOARD OF DIRECTORS (DISABLED BY DEFAULT / ADVISORY MODE)**:
   - Applies only when a proposal does not trigger Tier 2/3, falls within the active Charter's delegated authority, and `tier_1_5_enabled` is explicitly enabled by the Chairman.
   - In Phase 0 & Phase 1, the Board runs strictly in **Advisory Mode** (`tier_1_5_enabled = False`): blind votes and Devil's Advocate challenges are logged to the audit trail without granting execution authority.
4. **TIER 1 — AUTO + NOTIFY**:
   - Reversible, low-cost actions within budget (scheduling, task retries, paper trades, sandbox config).
5. **TIER 0 — AUTO**:
   - Read-only queries, analysis, internal reports, drafts, and housekeeping.

## 2. Independent Controls & Veto Power

- **Risk Agent**, **Security Agent**, and **Compliance Agent** operate independently of Atlas and the Board of Directors.
- Any one of these three controls can veto a proposal. Neither Atlas nor a unanimous Board vote can override or clear a veto; only the Chairman can resolve a veto where policy permits.
- **Audit Agent** maintains the hash-chained `audit_log` and cannot be instructed to suppress findings.
- If a mandatory control is unavailable, the system **fails closed**.

## 3. Strict Conservative Budget Policy (`core/model_router.py` & `core/charter.py`)

| Limit | Default Value | Enforcement |
|---|---|---|
| Global Daily API Budget | `$5.00 / day` | Hard stop at 100%, soft alert at 80% (`$4.00`) |
| Global Monthly API Budget | `$100.00 / month` | Hard stop at 100%, soft alert at 80% (`$80.00`) |
| Single-Agent Daily Cap | `30%` of global daily (`$1.50 / day`) | Pauses agent at 100%, requires Tier 2 approval to raise |
| Board Daily Budget (Advisory) | `$1.00 / day` | Hard stop at 100% before director LLM call is sent |
| Tier 2 Action Spend Threshold | `> $1.00 / action` | Forces Tier 2 Chairman Approval |
| Max Retries per Task | `3` | Marks task `FAILED` and escalates on exhaustion |
| Max LLM Calls per Task | `10` | Runaway guard halts task and emits critical alert |
