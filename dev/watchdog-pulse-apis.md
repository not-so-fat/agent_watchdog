## Agent Watchdog & Agent Pulse APIs

High-level reference for the existing backends that a new frontend or agent SDK can talk to, without changing backend behavior.

---

## 1. Agent-WatchDog

**Purpose**: runtime firewall for AI agents.

- **Kernel**: eBPF program tracing `sys_enter_openat` (file opens).
- **Daemon**: Rust + Axum API server.
- **Dashboard**: React (Vite + Tailwind + shadcn/ui).
- **Ports (default)**:
  - **3000**: dashboard REST + WebSocket + static assets.
  - **3001**: firewall proxy (`/v1/intercept` and friends).

### 1.1 Dashboard API (port 3000)

Base URL: `http://SERVER:3000`

#### 1.1.1 `GET /api/health`

- **Purpose**: liveness probe.
- **Response**: plain text

```text
ok
```

#### 1.1.2 `GET /api/stats`

- **Purpose**: high-level stats for dashboard tiles.
- **Response JSON** (`DashboardStats`):

```json
{
  "today_alerts": 12,
  "active_alerts": 2,
  "blocked_count": 5,
  "ignored_count": 1,
  "total_events": 42
}
```

#### 1.1.3 `GET /api/events`

- **Purpose**: list of all recorded file-open alerts (newest first).
- **Response JSON**: array of `AlertEvent`:

```json
[
  {
    "id": "uuid",
    "timestamp": "2026-02-27T10:00:00Z",
    "pid": 1234,
    "comm": "python3",
    "filename": "/home/user/.ssh/id_rsa",
    "severity": "high",       // "high" | "medium" | "low"
    "status": "active",       // "active" | "blocked" | "ignored"
    "dry_run": false
  }
]
```

#### 1.1.4 `GET /api/alerts`

- **Purpose**: subset of `/api/events` containing only `status == "active"`.
- **Response JSON**: same `AlertEvent` shape as above.

#### 1.1.5 `POST /api/events/{id}/block`

- **Purpose**: mark an alert as blocked and (optionally) send `SIGKILL` to the offending PID.
- **Behavior**:
  - Looks up event by `id`, changes its `status` to `blocked`, increments blocked counter.
  - If `dry_run == false` in config: attempts `kill(PID, SIGKILL)`.
  - If `dry_run == true`: does **not** kill, only logs.
- **Response JSON** (`ActionResponse`):

```json
{
  "success": true,
  "message": "[DRY-RUN] Process cat (PID: 1234) marked as blocked (not actually killed)",
  "event": {
    "id": "uuid",
    "timestamp": "2026-02-27T10:00:00Z",
    "pid": 1234,
    "comm": "cat",
    "filename": "/etc/shadow",
    "severity": "high",
    "status": "blocked",
    "dry_run": true
  }
}
```

- **Error** (`id` not found):

```json
{
  "success": false,
  "message": "Event <id> not found",
  "event": null
}
```

#### 1.1.6 `POST /api/events/{id}/ignore`

- **Purpose**: mark an alert as false positive.
- **Behavior**: sets `status` to `ignored`, increments ignored counter.
- **Response JSON** (`ActionResponse`), same structure as `/block`.

#### 1.1.7 `GET /api/config`

- **Purpose**: expose runtime config relevant to UI.
- **Response JSON**:

```json
{
  "dry_run": false,
  "whitelist_processes": ["systemd", "sshd", "agent-watchdog"],
  "whitelist_pids": [],
  "whitelist_paths": ["/proc/", "/sys/", "/dev/"]
}
```

#### 1.1.8 `GET /ws/events`

- **Purpose**: push real-time alerts to the dashboard.
- **Protocol**:
  - Text WebSocket messages.
  - Each message is a JSON-encoded `AlertEvent` (same shape as `/api/events`).
  - One channel per server; backend uses a broadcast channel to fan out.
- **Client behavior** (current dashboard):
  - Connect to `ws://HOST/ws/events` (or `wss://` under TLS).
  - On message: parse JSON and append to event store.
  - On close/error: attempt reconnect after 3s.

#### 1.1.9 Static assets

- Any other path → React SPA served from `dashboard-dist/`, with fallback to `index.html`.

### 1.2 Firewall Proxy API (port 3001)

**This is the core “agent firewall” surface.**

Base URL: `http://SERVER:3001`

#### 1.2.1 `GET /v1/health`

- **Purpose**: health check for the firewall proxy.
- **Response**: plain text `"ok"`.

#### 1.2.2 `POST /v1/intercept`

- **Purpose**: main enforcement endpoint called by agents or SDK wrappers **before** executing tools.
- **Request JSON** (`InterceptRequest`):

```json
{
  "agent_id": "agent-123",
  "user_id": "user-456",
  "tool": "file_read",
  "args": { "path": "/etc/shadow" },
  "session_id": "optional-session-id",

  "timestamp": 1710000000,           // optional Unix seconds (for replay protection)
  "nonce": "uuid-or-random",         // optional; server will generate if absent
  "signature": null,                 // reserved for future HMAC/mTLS use
  "device_id": "optional-client-id",
  "challenge_response": null         // see step-up flow below
}
```

- **Key behaviors**:
  1. **Risk scoring** via `RiskEngine` (`tool`, `args`, frequency).
  2. **Replay protection** (`timestamp`, `nonce`) using `AntiHijackGateway`.
  3. **Policy evaluation** via `PolicyEngine` and `watchdog.toml` rules.
  4. **Kill-switch / step-up auth** for high-risk tools.
  5. **Audit logging** (recent tool calls + stats).

- **Normal success (allowed)** – `200 OK`:

```json
{
  "decision": "allow",
  "allowed": true,
  "risk_score": 32.5,
  "risk_breakdown": {
    "total": 32.5,
    "tool_weight": 15.0,
    "arg_danger": 10.0,
    "frequency_penalty": 7.5,
    "details": [
      "tool=file_read (medium risk)",
      "arg contains .env",
      "5 calls in last 60s"
    ]
  },
  "reason": "Default allow (no blocking rule matched)",
  "matched_rule": null,           // or rule ID when a rule matched
  "dry_run": false,
  "challenge_id": null,
  "kill_switch_active": null
}
```

- **Policy-explcit block** – `403 Forbidden`:

```json
{
  "decision": "block",
  "allowed": false,
  "risk_score": 90.0,
  "risk_breakdown": { "...": "..." },
  "reason": "Block any tool reading /etc/shadow",
  "matched_rule": "block-shadow-access",
  "dry_run": false,
  "challenge_id": null,
  "kill_switch_active": null
}
```

- **Replay protection failures** – `403 Forbidden`:
  - **Expired timestamp**:

```json
{
  "decision": "block",
  "allowed": false,
  "risk_score": 40.0,
  "risk_breakdown": { "...": "..." },
  "reason": "Replay protection: timestamp expired (age=120s, max=60s)",
  "matched_rule": "antihijack:replay-expired",
  "dry_run": false
}
```

  - **Duplicate nonce**:

```json
{
  "decision": "block",
  "allowed": false,
  "risk_score": 40.0,
  "risk_breakdown": { "...": "..." },
  "reason": "Replay protection: duplicate nonce 'nonce-123'",
  "matched_rule": "antihijack:replay-duplicate",
  "dry_run": false
}
```

- **Kill-switch enforced** – `403 Forbidden`:

```json
{
  "decision": "block",
  "allowed": false,
  "risk_score": 75.0,
  "risk_breakdown": { "...": "..." },
  "reason": "Emergency read-only mode: high-risk tool 'shell_exec' blocked by kill-switch",
  "matched_rule": "antihijack:kill-switch",
  "dry_run": false,
  "kill_switch_active": true
}
```

- **Step-up auth required** – `401 Unauthorized`:

```json
{
  "decision": "block",
  "allowed": false,
  "risk_score": 80.0,
  "risk_breakdown": { "...": "..." },
  "reason": "Step-up authentication required: tool 'shell_exec' classified as High",
  "matched_rule": "antihijack:step-up-required",
  "dry_run": false,
  "challenge_id": "challenge-uuid"
}
```

Step-up flow:

1. Agent calls `POST /v1/intercept` → receives `401` with `challenge_id`.
2. Agent (or human) completes some out-of-band verification and then:
   - Either calls `POST /v1/challenge/verify` (see below),
   - Or re-sends `/v1/intercept` including `challenge_response: "<challenge_id>"`.
3. If challenge is valid, gateway lets the request pass risk gate.

#### 1.2.3 `POST /v1/challenge/verify`

- **Purpose**: verify step-up challenge and mark it as satisfied.
- **Request JSON**:

```json
{
  "challenge_id": "challenge-uuid",
  "verification_token": "optional-string"
}
```

- **Responses**:
  - **200 OK (verified)**:

```json
{
  "verified": true,
  "message": "Challenge verified. Re-send intercept with challenge_response='challenge-uuid'",
  "tool": "shell_exec",
  "challenge_id": "challenge-uuid"
}
```

  - **403 Forbidden (not found/expired)**:

```json
{
  "verified": false,
  "message": "Challenge not found or expired"
}
```

#### 1.2.4 `GET /v1/audit`

- **Purpose**: recent audit records for firewall decisions.
- **Response JSON**:

```json
{
  "records": [
    {
      // AuditRecord – includes agent_id, user_id, tool, args hash, decision, etc.
    }
  ],
  "stats": {
    // AuditStats – aggregate allow/block counts and similar
  }
}
```

#### 1.2.5 `GET /v1/audit/stats`

- **Purpose**: summary-only stats.
- **Response JSON**: `AuditStats` (shape defined in `audit.rs` – counts of allowed/blocked, etc.).

---

## 2. Agent Pulse – Local Portal

**Purpose**: scoped-access wallet / payment gatekeeper for x402-paid APIs.

- **Service**: Node.js / TypeScript Express server.
- **Port**: `4020` (loopback-only, binds `127.0.0.1`).
- **Key concepts**:
  - **Scoped Access grant** (formerly “delegation session”): policy describing domains/APIs, budgets, TTL.
  - **Session handle**: opaque token returned after user approves in browser.
  - **Execute**: HMAC-signed `/execute` calls that perform x402-paid HTTP requests via Agentic Wallet (Awal).

### 2.1 Core agent-facing endpoints

Base URL: `http://127.0.0.1:4020`

#### 2.1.1 `GET /health`

- **Purpose**: service liveness.
- **Response**:

```json
{ "status": "ok" }
```

#### 2.1.2 `GET /wallet-status`

- **Purpose**: detect whether Awal wallet is authenticated before trying scoped-access or execution.
- **Behavior**: runs `npx awal@latest status` inside the portal.
- **Response JSON**:

```json
{
  "authenticated": true,
  "code": 0,
  "stdout": "...raw awal status output...",
  "stderr": "",
  "message": "Optional human-readable hint when unauthenticated"
}
```

- **Failure** (e.g., awal not installed) – `500` with:

```json
{
  "authenticated": false,
  "code": -1,
  "stdout": "",
  "stderr": "error message",
  "message": "Failed to run wallet status. Please ensure Awal is installed (npx awal@latest status)."
}
```

#### 2.1.3 `POST /request-scoped-access`

Backs the `request_scoped_access(policy)` agent operation; conceptually this is **creating a Scoped Access grant**.

- **Request JSON**:

```json
{
  "agent_id": "agent_example_01",    // optional but recommended
  "user_id": "user_example_01",     // optional
  "policy": {
    "allowed_domains": ["api.example.com"],   // REQUIRED, non-empty array
    "max_total_spend": 5000000,              // optional, atomic units (e.g. 5 USDC = 5_000_000)
    "max_per_tx": 500000,                    // optional, atomic units
    "ttl_seconds": 600,                      // optional, default 600s

    // Optional richer API allow-list; if present, domain+method+path are enforced
    "allowed_apis": [
      {
        "domain": "api.example.com",
        "path": "/v1/flights/book",
        "method": "POST",                    // or "*" to allow any method
        "description": "Book flights"
      }
    ],

    // Optional human-facing text used in approval UI & dashboard
    "summary": "Book flights on ExampleAir",
    "description": "Agent can book flights up to 5 USDC total for this session."
  }
}
```

- **Validations**:
  - `policy.allowed_domains` must be an array of strings.
  - If `policy.allowed_apis` is present: it must be an array and each entry must have `domain`, `path`, `method`.
  - `summary` / `description` (if present) must be strings.

- **Response JSON (always 200 on successful creation)**:

```json
{
  "status": "pending",
  "request_id": "uuid",
  "approval_url": "http://localhost:4020/approval/<request_id>",
  "message": "User approval required. Open the approval_url in a browser, then poll /request-delegation/:request_id for result."
}
```

- **Error** (policy invalid) – `400` with `error: "bad_request"` and `message`.

**Flow**:

1. Agent calls `POST /request-scoped-access`.
2. User opens `approval_url` in browser (must be `localhost` to satisfy WebAuthn).
3. User authenticates with passkey and clicks **Approve** or **Deny**.
4. Agent polls `GET /request-scoped-access/:request_id` (below) to get result and obtain a **Scoped Access session_handle**.

#### 2.1.4 `GET /request-scoped-access/:request_id`

- **Purpose**: poll for Scoped Access grant outcome.
- **Responses**:
  - Pending:

```json
{ "status": "pending" }
```

  - Approved:

```json
{
  "status": "approved",
  "session_handle": "opaque-session-id"
}
```

  - Denied:

```json
{
  "status": "denied",
  "reason": "User declined"
}
```

  - Not found – `404` with `{ "error": "not_found" }`.

#### 2.1.5 `POST /execute`

Backs `x402_request(session_handle, url, ...)`.

- **Auth**: requires HMAC-SHA256 signature header:
  - Header: `x-local-portal-signature: <hex>`.
  - Payload: **exact** JSON string of the request body.
  - Key: `LOCAL_PORTAL_SHARED_SECRET` (must match env var used to start server).

- **Request JSON**:

```json
{
  "session_handle": "opaque-session-id",   // from approved delegation
  "operation": "x402_request",             // currently only supported operation
  "params": {
    "url": "https://api.example.com/paid-endpoint",
    "method": "GET",
    "headers": { "Accept": "application/json" },
    "body": null
  },
  "counter": 1,                             // strictly increasing per session
  "idempotency_key": "some-uuid-or-client-id"
}
```

- **Pre-checks**:
  - HMAC signature must be valid (`401 unauthorized` otherwise).
  - `session_handle` must exist and be active (`403 no_session` if unknown).
  - `counter` must be strictly greater than `session.last_counter` (`409 replay` if not).
  - **Policy** (`checkPolicy`):
    - Domain must match `allowed_domains`.
    - If `allowed_apis` set: domain + method + path must match one of them (glob on path).
    - (Budget checks currently not enforced in pre-check; see response notes below.)

- **Calls**:
  - Logs a `Local_API_Requests` row.
  - Invokes `handleX402Request` (Awal `x402 pay`) with the given URL/method/headers/body.

- **On success**:
  - Updates `session.last_counter`.
  - If `result.metadata.x402_paid` is true and `settlement_proof.success` is true:
    - Uses `expected_amount_atomic` as `spentAtomic`.
    - Increments `session.total_spent_atomic` via `addSpentAtomic`.
    - Logs a `Transaction_Logs` row (tx hash, network, amount, etc.).

- **Success response** (`status` mirrors upstream paid API status):

```json
{
  "status": 200,
  "headers": { "content-type": "application/json" },
  "body": { "any": "upstream API body" },
  "metadata": {
    "x402_paid": true,
    "expected_amount_atomic": 12345,
    "settlement_proof": {
      "success": true,
      "payer": "0x...",
      "transaction": "0x...",
      "network": "eip155:84532"
    }
  },
  "idempotency_key": "some-uuid-or-client-id"
}
```

- **Error responses (key cases)**:
  - `401` – missing/invalid HMAC:

```json
{ "error": "unauthorized" }
```

  - `403` – unknown session:

```json
{ "error": "no_session", "message": "Unknown session_handle" }
```

  - `403` – policy denied:

```json
{
  "error": "policy_denied",
  "deny_code": "DOMAIN_NOT_ALLOWED",   // or API_NOT_ALLOWED, BUDGET_EXCEEDED, PER_TX_EXCEEDED, SESSION_EXPIRED
  "message": "Request denied: DOMAIN_NOT_ALLOWED"
}
```

  - `409` – replay / non-monotonic counter:

```json
{ "error": "replay", "message": "Non-monotonic counter" }
```

  - `503` – wallet not authenticated (Awal error surfaced):

```json
{
  "error": "wallet_not_authenticated",
  "message": "Wallet is not authenticated. Ask the user to run 'npx awal@latest status' and sign in, then retry."
}
```

### 2.2 Dashboard & account JSON APIs

These endpoints back the Local Portal’s HTML dashboard and account UI. They are useful if you want to build a richer frontend around existing behavior.

#### 2.2.1 `GET /api/wallet`

- **Purpose**: wallet info for dashboard.
- **Response JSON** (shape from `awalAdapter.getWalletInfo`):

```json
{
  "authenticated": true,
  "email": "user@example.com",
  "address": "0x...",
  "balances": {
    "USDC": "10.00",
    "ETH": "0.01",
    "WETH": "0.00"
  }
}
```

#### 2.2.2 `GET /api/scoped-access?active_only=true|false`

- **Purpose**: list Scoped Access grants (sessions) for dashboard.
- **Response JSON**: array of sessions, e.g.

```json
[
  {
    "session_id": "uuid",
    "agent_id": "agent_example_01",
    "user_id": "user_example_01",
    "allowed_domains": ["api.example.com"],
    "allowed_apis": [
      { "domain": "api.example.com", "path": "/v1/flights/book", "method": "POST", "description": "Book flights" }
    ],
    "summary": "Book flights on ExampleAir",
    "description": "Agent can book flights up to 5 USDC total for this session.",
    "max_total_spend": 5000000,
    "max_per_tx": 500000,
    "total_spent_atomic": 12345,
    "ttl_seconds": 600,
    "ttl_remaining_seconds": 420,
    "expires_at": 1710006000000,
    "created_at": 1710005400000,
    "is_active": true,
    "last_counter": 3,
    "revoked_at": null
  }
]
```

#### 2.2.3 `POST /api/scoped-access/:session_id/revoke`

- **Purpose**: revoke an existing Scoped Access session from the dashboard.
- **Request JSON** (optional):

```json
{ "reason": "string (optional)" }
```

- **Responses**:
  - Success:

```json
{
  "success": true,
  "session_id": "uuid",
  "revoked_at": 1710007000000
}
```

  - Errors: `400` invalid ID, `404` not found, `400` already revoked, `500` generic.

#### 2.2.4 `GET /api/transactions?session_id=<optional>&limit=<optional>`

- **Purpose**: transaction history (x402 payments).
- **Response JSON**: array of rows joined with session info:

```json
[
  {
    "tx_id": "uuid",
    "session_id": "uuid",
    "operation": "x402_request",
    "amount": "500000",                // atomic units, string
    "recipient": "0xpayer",
    "domain": "nickeljoke.vercel.app",
    "api_path": "/api/joke",
    "method": "POST",
    "decision": "APPROVED",            // or "DENIED"
    "deny_code": null,
    "counter": 1,
    "idempotency_key": "test-id-1",
    "http_402_proof_hash": null,
    "tx_hash": "0x...",
    "network": "eip155:84532",
    "created_at": 1710005500000,
    "agent_id": "agent_example_01"
  }
]
```

### 2.3 Passkey & browser-session APIs

These are primarily for the built-in HTML UIs (`/account`, `/approval/:request_id`), but can be reused by a new frontend.

- `GET /api/user`
  - Requires authenticated wallet (via Awal).
  - On success: `{ user_id, email, passkeys: [{ credential_id, device_name, created_at }] }`.
  - On unauthenticated wallet: `401 { "error": "wallet_not_authenticated" }`.

- `POST /api/passkey/register-challenge`
  - Returns WebAuthn registration options + `challenge_id`.

- `POST /api/passkey/register-verify`
  - Accepts `{ challenge_id, credential, device_name }`; persists passkey, starts browser session, returns `{ verified: true }` on success.

- `POST /api/passkey/auth-challenge`
  - Returns WebAuthn authentication options + `challenge_id`.

- `POST /api/passkey/auth-verify`
  - Accepts `{ challenge_id, credential, approval_rid? }`.
  - If `approval_rid` (delegation request ID) is set, marks that specific request as authenticated (`approvalAuth`).
  - Creates browser session.

- `DELETE /api/passkey/:credential_id`
  - Requires active browser session.
  - Prevents deleting the last passkey.

- `POST /api/logout`
  - Clears browser session cookie.

### 2.4 HTML pages

The Local Portal also serves HTML UIs that a new frontend can either reuse or replace:

- `/account`
  - Wallet connection & passkey management.
  - Uses `/api/user`, `/api/passkey/*`, `/api/logout`.
- `/dashboard`
  - Wallet summary, Scoped Access grants, and transaction history.
  - Uses `/api/wallet`, `/api/scoped-access` (Scoped Access grants), `/api/transactions`.

### 2.5 CLI execution API

The Local Portal also exposes a CLI execution endpoint that enforces Scoped Access CLI capabilities.

#### 2.5.1 `POST /cmd/execute`

- **Purpose**: execute a shell command on the host under a Scoped Access grant.
- **Request JSON**:

```json
{
  "session_handle": "opaque-session-id",
  "command": "git status",
  "cwd": "/path/to/repo",
  "timeout_ms": 30000
}
```

- **Enforcement**:
  - Looks up the grant by `session_handle`.
  - Verifies grant is active (`expires_at` in the future, not revoked).
  - Checks `capabilities.cli.commands_allow` on the grant; the command string must start with one of the allowed patterns.
  - If not allowed, the command is not executed.

- **Success response**:

```json
{
  "allowed": true,
  "stdout": "…process stdout…",
  "stderr": "",
  "exit_code": 0,
  "grant_id": "g_123"
}
```

- **Denied / error responses**:
  - Grant missing/expired/revoked:

```json
{
  "allowed": false,
  "stdout": "",
  "stderr": "Scoped Access grant expired or revoked",
  "exit_code": null,
  "reason": "grant_expired",
  "grant_id": "g_123"
}
```

  - Command not in `commands_allow`:

```json
{
  "allowed": false,
  "stdout": "",
  "stderr": "Command not allowed by Scoped Access grant (cli.commands_allow)",
  "exit_code": null,
  "reason": "command_not_allowed",
  "grant_id": "g_123"
}
```
- `/approval/:request_id`
  - Delegation approval UI; **only** way to approve new sessions.
  - Uses WebAuthn auth endpoints and, on approve, creates the delegation session.
- `/delegation/:session_id`
  - Read-only detail view for a specific delegation.

---

## 3. Notes for Frontend Redesign

- **Watchdog dashboard**:
  - Can be rebuilt purely against:
    - `GET /api/stats`, `GET /api/events`, `GET /api/alerts`, `GET /api/config`,
    - `POST /api/events/{id}/block`, `POST /api/events/{id}/ignore`,
    - `GET /ws/events` for live updates.
- **Watchdog firewall clients (agents)**:
  - Integrate via `POST /v1/intercept` and optionally `POST /v1/challenge/verify`.
  - Replay protection strongly prefers you to send `timestamp` and `nonce`.
- **Pulse agent skills / host apps**:
  - Use `GET /wallet-status` before doing anything paid.
  - Use `POST /request-delegation` (request Scoped Access) → browser approval → `GET /request-delegation/:id` → `session_handle`.
  - Use HMAC-signed `POST /execute` with monotonic `counter` for all paid HTTP requests.
- **Pulse dashboards**:
  - For a new UX, rely on:
    - `GET /api/wallet`, `GET /api/delegations` (Scoped Access grants), `POST /api/delegations/:id/revoke`,
    - `GET /api/transactions`, `GET /api/user`, and passkey endpoints.

