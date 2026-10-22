# Atlas AI Control Plane REST & WebSocket API Reference (`/api/v1`)

Machine-readable OpenAPI 3.1 schema: [`docs/openapi.json`](./openapi.json)

## 1. Authentication & Security Model

All API endpoints (except `GET /health`, `GET /api/v1/health`, and `POST /api/v1/auth/*`) require an HTTP header:

```http
Authorization: Bearer <token>
```

### 1.1 Single-Owner Google OAuth 2.0 Flow (Dashboard)
1. **Google Sign-In**: The React dashboard obtains a Google OAuth 2.0 ID token and sends it to `POST /api/v1/auth/google`.
2. **Backend Verification**: The backend verifies the Google signature, `aud == GOOGLE_CLIENT_ID`, expiry, `email_verified == true`, and checks `email == OWNER_EMAIL` in constant time. Any non-owner Google account is rejected with `403 Forbidden` and logged in `audit_log`.
3. **Session Tokens**: Returns an HS256-signed **Access JWT** (`expires_in: 900` seconds / 15 minutes) and a revocable SHA-256-hashed **Refresh Token** (7 days).
4. **Token Rotation**: Call `POST /api/v1/auth/refresh` with `{ "refresh_token": "rt_..." }` to rotate the refresh token and obtain a new 15-minute access token.

### 1.2 5-Minute Step-Up Verification (`require_step_up=True`)
High-consequence Chairman operations require a fresh Google authentication within the last **5 minutes** (`300` seconds), verified via the `step_up_at` claim in the Access JWT. Call `POST /api/v1/auth/step-up` with a fresh Google `id_token` before invoking:
- `POST /api/v1/resume` (Leaving SAFE MODE)
- `PUT /api/v1/charter` (Editing the Governance Charter)
- `PUT /api/v1/settings/limits` (Updating budget/escalation limits)
- Approving real-money Tier 2 requests or L3 autonomy promotions

### 1.3 Scoped Machine Token (`MACHINE_API_TOKEN`)
For n8n workflows, health checks, and emergency automation:
- **Allowed Scopes**: `read:status`, `read:health`, `create:low_tier_task` (Tier `0` and `1` only), and `execute:kill_switch` (`POST /api/v1/kill-switch`).
- **Strictly Forbidden (`403 Forbidden`)**: Approving/rejecting decisions, resuming from SAFE mode, editing the Charter or limits, changing autonomy levels, or creating Tier `1.5`, `2`, or `3` tasks.

### 1.4 Dev-Mode Bypass (`DEV_OWNER_TOKEN`)
- Works **only** when `ENV=dev` or `ENV=test`.
- Setting `DEV_OWNER_TOKEN` when `ENV=prod` causes immediate startup failure (`RuntimeError`).

---

## 2. REST Endpoints (`/api/v1`)

### 2.1 System Health, Status & Emergency Control

| Method | Path | Auth / Scope | Step-Up | Description |
|---|---|---|---|---|
| `GET` | `/health` & `/api/v1/health` | Public | No | Container, DB, Model Router, and Audit Chain health check. |
| `GET` | `/api/v1/status` | Owner or Machine (`read:status`) | No | Returns `mode` (`NORMAL`/`SAFE`), `uptime_seconds`, `trading_mode` (`PAPER`), `board_mode` (`ADVISORY`), `agents_summary`, `queued_tasks_count`, `cost_today_usd`, `daily_budget_usd`. |
| `POST` | `/api/v1/kill-switch` | Owner or Machine (`execute:kill_switch`) | No | Halts all active agents, cancels pending jobs, and enters read-only `SAFE` mode. Works even if Atlas CEO is offline. |
| `POST` | `/api/v1/resume` | Owner (`execute:resume`) | **Yes (5m)** | Leaves `SAFE` mode and restores previously active agents. |

#### `POST /api/v1/kill-switch`
- **Request Body**:
```json
{
  "reason": "Emergency halt triggered from Command Center"
}
```
- **Response (`200 OK`)**:
```json
{
  "mode": "SAFE",
  "kill_switch_engaged": true,
  "actor": "owner:abbass@example.com",
  "reason": "Emergency halt triggered from Command Center",
  "engaged_at": "2026-10-22T19:45:00+00:00",
  "cancelled_tasks_count": 2,
  "halted_agents_count": 2
}
```

### 2.2 Authentication Endpoints

| Method | Path | Request Body | Response |
|---|---|---|---|
| `POST` | `/api/v1/auth/google` | `{ "id_token": "<google_jwt>" }` | `TokenBundleResponse` (`access_token`, `refresh_token`, `expires_in`, `step_up_verified_until`) |
| `POST` | `/api/v1/auth/step-up` | `{ "id_token": "<google_jwt>" }` | `TokenBundleResponse` with fresh 5-minute `step_up_at` claim |
| `POST` | `/api/v1/auth/refresh` | `{ "refresh_token": "rt_..." }` | Rotated `TokenBundleResponse` (`step_up_verified_until: null`) |
| `POST` | `/api/v1/auth/revoke` | `{ "refresh_token": "rt_..." }` | `{ "revoked": true }` |

### 2.3 Agents & Registry (`/api/v1/agents`)

| Method | Path | Auth / Scope | Description |
|---|---|---|---|
| `GET` | `/api/v1/agents?layer=&status=` | Owner (`read:all`) | Lists all 49 catalog agents grouped across 11 layers with `status`, `autonomy_level` (`L0`–`L3`), `health`, `capabilities`, `permissions`, `phase`, `last_run_at`, and `cost_today_usd`. |
| `POST` | `/api/v1/agents/{name}/pause` | Owner (`write:agents`) | Pauses an active agent. |
| `POST` | `/api/v1/agents/{name}/resume` | Owner (`write:agents`) | Resumes a paused agent (blocked if system is in `SAFE` mode or agent is `PLANNED`). |
| `POST` | `/api/v1/agents/{name}/run?action=` | Owner (`write:tasks`) | Executes a capability on an active agent (`PLANNED` agents return `501 Not Implemented`). |

### 2.4 Task Queue (`/api/v1/tasks`)

| Method | Path | Auth / Scope | Description |
|---|---|---|---|
| `GET` | `/api/v1/tasks?status=&agent_name=&limit=100` | Owner or Machine (`read:status`) | Lists queued, running, completed, failed, or cancelled tasks. |
| `POST` | `/api/v1/tasks` | Owner or Machine (`create:low_tier_task`) | Enqueues a task with optional `idempotency_key`. Machine tokens are restricted to `tier` in `("0", "1")`. |
| `POST` | `/api/v1/tasks/process-next` | Owner (`write:tasks`) | Claims and executes the highest-priority due task in the queue. |

#### `POST /api/v1/tasks`
- **Request Body**:
```json
{
  "agent_name": "health",
  "action": "check_system_health",
  "parameters": {},
  "priority": 3,
  "tier": "0",
  "idempotency_key": "idem-health-check-001",
  "estimated_cost_usd": 0.0
}
```

### 2.5 Costs, Audit & Governance Charter

| Method | Path | Auth / Scope | Step-Up | Description |
|---|---|---|---|---|
| `GET` | `/api/v1/costs` | Owner (`read:all`) | No | Daily & monthly global spend, Board daily spend, per-agent and per-provider breakdown, and budget utilization vs caps. |
| `GET` | `/api/v1/audit` | Owner (`read:all`) | No | Read-only hash-chained audit entries (`prev_hash`, `entry_hash`) with `actor`, `action`, `outcome`, `tier`, `limit`, `offset`. |
| `GET` | `/api/v1/audit/verify` | Owner (`read:all`) | No | Verifies SHA-256 hash chain integrity across the entire `audit_log` table. |
| `GET` | `/api/v1/charter` | Owner (`read:all`) | No | Returns active Charter (`v1.0.0`) and full version history. |
| `PUT` | `/api/v1/charter` | Owner (`write:charter`) | **Yes (5m)** | Updates the Charter with optimistic version concurrency check (`expected_version`) and `explicit_confirmation: true`. |
| `PUT` | `/api/v1/settings/limits` | Owner (`write:limits`) | **Yes (5m)** | Updates budget caps and Tier 2 escalation thresholds via a new Charter version. |

### 2.6 Phase 1+ Endpoints (Auth-Guarded Now, Returning `501 Not Implemented` in Phase 0)
- `GET /api/v1/decisions?tier=&status=` (Phase 1 Decision Engine)
- `GET /api/v1/approvals?status=pending` (Phase 1 Approval Inbox)
- `POST /api/v1/approvals/{approval_id}/{decision_action}` (Phase 1 Approval Workflow)
- `GET /api/v1/board/members` (Phase 1 Board of Directors Advisory Mode)
- `GET /api/v1/recommendations` (Phase 2 Learning Layer)
- `GET /api/v1/trading/mode` & `GET /api/v1/trading/pnl` (Phase 4 Paper Trading)

---

## 3. WebSocket Real-Time Stream (`WS /api/v1/events` and `WS /events`)

### 3.1 Connection & Authentication
Connect with a valid Owner JWT or Machine Token:
```text
wss://<host>/api/v1/events?token=<ACCESS_JWT>
```
Unauthenticated connections are closed immediately with code `1008` (`WS_1008_POLICY_VIOLATION`).

### 3.2 Message Envelope Schema
Every WebSocket frame sent from the server is a JSON object:
```json
{
  "event_id": "evt_9a8b7c6d5e4f",
  "timestamp": "2026-10-22T19:45:00.123456+00:00",
  "event_type": "system.kill_switch_engaged",
  "severity": "critical",
  "payload": {
    "mode": "SAFE",
    "actor": "owner:abbass@example.com",
    "reason": "Emergency halt",
    "cancelled_tasks_count": 2,
    "halted_agents_count": 2
  }
}
```

### 3.3 Emitted `event_type` Values
- `ws.connected` (sent immediately upon connection with `recent_events` snapshot)
- `ws.pong` (sent in response to client `"ping"`)
- `system.kill_switch_engaged` (`severity: "critical"`)
- `system.resumed` (`severity: "info"`)
- `task.enqueued`, `task.completed`, `task.failed_escalated`
- `cost.soft_alert` (80% budget warning), `cost.hard_stop` (100% cap reached, agent paused), `cost.runaway_guard`
- `llm.provider_unavailable`, `llm.call_failed`
- `charter.updated`
