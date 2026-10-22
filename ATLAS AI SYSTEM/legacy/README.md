# Atlas AI Legacy Code Quarantine (`/legacy`)

This folder is reserved for importing existing scripts or modules (such as legacy Crypto Trading, Gold Trading, Learning Engine, or LinkedIn automation scripts) before they are audited and wrapped behind the standard Atlas AI Agent Contract.

## Mandatory Security & Governance Rules

1. **Untrusted by Default**: All code placed in `/legacy` is treated as untrusted external code. No service, route, or agent may import or execute files from `/legacy` directly.
2. **Must Run Only Through `LegacyAdapter`**: Any legacy module must be wrapped via [`core/legacy_adapter.py`](../core/legacy_adapter.py), which enforces:
   - Pydantic v2 `TaskInput` and `TaskResult` schema validation.
   - Explicit capability and permission allowlist verification.
   - Execution timeouts and cost estimation.
   - Append-only audit logging (`AuditLog`) for every invocation and failure.
   - Standardized `health()` reporting.
3. **Strict Secret Isolation**: Legacy code has **zero access** to process-wide environment variables or secrets (`JWT_SIGNING_KEY`, `DATABASE_URL`, `GEMINI_API_KEY`, etc.) except the specific read-only keys explicitly listed in its `LegacyAdapter.allowed_env_keys`.
4. **No Direct External Side Effects**:
   - Legacy code may **never** execute live trades or publish external content (LinkedIn posts, emails, proposals) directly.
   - All external publications must produce drafts routed through the Decision Engine and Tier 2 Chairman Approval Inbox.
5. **Trading Adapters Are PAPER Mode Only**:
   - All trading adapters (`crypto_trading`, `gold_trading`) run strictly in `PAPER` mode by default.
   - Transitioning to `CANARY` or `LIVE` mode requires backtest + paper-trade evidence and an explicit Tier 2 approval from the Chairman.

## Pre-Wiring Security Audit Checklist

Before any code added to `/legacy` is wired into a `LegacyAdapter`:
1. Enumerate all imported dependencies and verify each is a real, published package on PyPI.
2. Scan for hardcoded API keys, tokens, credentials, or wallet addresses and remove them.
3. Identify all direct network, webhook, or exchange API calls and route them through governed adapters.
4. Identify any code that bypasses the Atlas AI Decision Engine, Risk Agent, or Cost Agent caps.
5. Produce a written security & contract compliance report for Chairman sign-off before activation.
