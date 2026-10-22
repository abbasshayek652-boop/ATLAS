# Atlas AI Agent Contract & Legacy Adapter Specification

## 1. Mandatory Agent Contract (`core/agent_contract.py`)

Every agent in Atlas AI must inherit from `BaseAgent` and implement:

| Attribute / Method | Type | Requirement |
|---|---|---|
| `name` | `str` | Unique snake_case identifier (e.g., `atlas`, `crypto_trading`, `audit`). |
| `display_name` | `str` | Human-readable agent title. |
| `layer` | `str` | Operational layer (`Executive`, `Finance`, `Trading`, `Learning`, `Content`, `Business`, `Intelligence`, `Infrastructure`, `Security`, `Development`, `Communication`). |
| `description` | `str` | Clear summary of responsibilities and boundaries. |
| `version` | `str` | Semantic version string (`1.0.0`). |
| `phase` | `int` | Rollout phase (`0` through `6`). |
| `capabilities` | `list[str]` | Explicit list of actions the agent can perform. |
| `permissions` | `list[str]` | Explicit allowlist of permissions (e.g., `["read:exchange", "trade:paper"]`). |
| `autonomy_level` | `AutonomyLevel` | Capability level (`L0`, `L1`, `L2`, `L3`), stored separately from operational `status`. |
| `status` | `AgentOperationalStatus` | `ACTIVE`, `PAUSED`, `SAFE_MODE_HALTED`, `PLANNED`, `ERROR`, or `SUSPENDED`. |
| `run(task: TaskInput) -> TaskResult` | Method | Executes the task and returns a Pydantic v2 schema-validated `TaskResult`. |
| `estimate_cost(task: TaskInput) -> float` | Method | Returns the estimated USD cost before execution. |
| `health() -> dict` | Method | Returns a standardized `AgentHealthReport` payload. |

## 2. Autonomy Levels vs Operational Status

Capability level (`autonomy_level`) and operational state (`status`) are strictly orthogonal:

- **`L0`**: Recommend only.
- **`L1`**: Execute permitted sandbox or paper operations.
- **`L2`**: Execute explicitly allowlisted actions within enforced limits.
- **`L3`**: Execute a broader, explicitly Chairman-approved scope with notification and monitoring.

An autonomy level **never** bypasses action-specific permissions, Decision Engine tier classification, or independent Risk/Security/Compliance vetoes.

## 3. Planned Agents & No-Fake-Stubs Policy

Agents scheduled for future phases (including the 4 catalog agents noted as pre-existing: `crypto_trading`, `gold_trading`, `learning_engine`, and `linkedin`) are registered in `core/agent_registry.py` with:
- `status = PLANNED`
- `autonomy_level = L0`
- Declared `layer`, `description`, `capabilities`, `permissions` allowlist, and target `phase`

Calling `run()` on any `PLANNED` agent raises `NotImplementedError` (HTTP `501 Not Implemented` via REST API) and records an entry in `audit_log`. No fake stub outputs are ever returned.

## 4. LegacyAdapter Specification (`core/legacy_adapter.py`)

When existing scripts or modules are added to `/legacy`, they must **never** be imported or executed directly by routes or other agents. They must be wrapped behind `LegacyAdapter` (`core/legacy_adapter.py`), which enforces:

1. **Schema Validation**: All inputs are validated as `TaskInput` and outputs as `TaskResult`.
2. **Forbidden Direct Permissions**: `LegacyAdapter` rejects declaration of `trade:live_direct`, `publish:external_direct`, `withdraw:funds`, or `secrets:read_all`.
3. **Secret Isolation (`build_sanitized_env`)**: Legacy scripts receive only `ATLAS_SANDBOX=1`, `ATLAS_TRADING_MODE=PAPER`, and the specific environment variable keys listed in `allowed_env_keys`.
4. **PAPER-Mode Trading Lock**: Trading adapters (`is_trading_adapter=True`) are locked to `PAPER` mode unless `trade:live_approved` is granted through a Tier 2 Chairman approval.
5. **Timeouts & Audit**: Every invocation runs under `min(task.timeout_seconds, default_timeout_seconds)` and logs start/completion/failure to the hash-chained `AuditLog`.
