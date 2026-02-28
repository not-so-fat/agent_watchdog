## Local Portal (MVP) – Dev README

This service is the **Local Portal** described in `dev/PRD`, `dev/ERD`, and `dev/DESIGN-local-portal.md`.
It exposes a loopback-only HTTP API that an AI agent can use via two skills:

- `request_scoped_access(policy)` (formerly `request_delegation(policy)`)
- `x402_request(session_handle, url, method?, headers?, body?)`

All wallet and x402 payment logic is executed **inside this process** via Coinbase **Agentic Wallet** (`awal`).
The agent must never call `awal` directly.

---

### 1. Prerequisites

- Node.js 18+ (for native `fetch` and TS tooling).
- `npx awal@latest` installed/available (from Coinbase Agentic Wallet docs).
- A wallet authenticated with Agentic Wallet and funded with USDC (for real x402 payments).

> In dev, authentication is checked via `npx awal@latest status` inside the Local Portal.

---

### 1.1 Initial Agentic Wallet Setup (One-Time)

This step is done **by the user, in a normal terminal**, **not** by the agent and **not** programmatically by Local Portal.

1. Open a terminal.
2. Run:

   ```bash
   npx awal@latest status
   ```

3. If not authenticated, follow the **email/OTP** prompts from Agentic Wallet.
4. Ensure your wallet has enough **USDC** for the x402 APIs you plan to call.

After this one-time setup, Local Portal will only:

- Call `npx awal@latest status` to **check** that you are authenticated.
- Call `npx awal@latest x402 pay ...` to handle payments.

The agent never sees or triggers the OTP flow directly.

---

### 2. Install & Build

From the project root:

```bash
cd local-portal
npm install
```

For TypeScript build:

```bash
npm run build
```

---

### 3. Running the Local Portal (Dev)

Dev mode (ts-node):

```bash
cd local-portal
export LOCAL_PORTAL_SHARED_SECRET="change-me-dev-secret"  # HMAC key for /execute; see §3.1
npx ts-node src/server.ts
```

Or after building:

```bash
npm run build
LOCAL_PORTAL_SHARED_SECRET="change-me-dev-secret" npm start
```

The server listens on:

- `http://127.0.0.1:4020` (and `http://localhost:4020` — use **localhost** for WebAuthn/passkey pages)

Check health:

```bash
curl http://127.0.0.1:4020/health
# -> { "status": "ok" }
```

SQLite DB (default path):

- `local-portal/local-portal.db`

---

### 3.3 Launch and test (user auth + Scoped Access)

**Prerequisites:** Node 18+, `npx awal@latest` available. Authenticate the Agentic Wallet once: run `npx awal@latest status` in a terminal and complete email/OTP if needed.

**1. Start the server**

```bash
cd local-portal
export LOCAL_PORTAL_SHARED_SECRET="change-me-dev-secret"
npx ts-node src/server.ts
```

**2. First-time setup — register a passkey**

- Open **http://localhost:4020/account** in your browser (use `localhost`, not `127.0.0.1`, for WebAuthn).
- If the wallet is not authenticated, the page will say so; run `npx awal@latest status` and sign in, then refresh.
- Click **Register New Passkey** and complete the browser/OS prompt (Touch ID, Windows Hello, or device PIN).
- You should see your passkey listed and be signed in.

**3. Test Scoped Access approval (requires passkey every time)**

In another terminal:

```bash
# Create a pending scoped-access request
curl -s -X POST http://127.0.0.1:4020/request-scoped-access \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "test_agent",
    "policy": {
      "allowed_domains": ["api.example.com"],
      "max_total_spend": 5000000,
      "max_per_tx": 500000,
      "ttl_seconds": 600
    }
  }'
```

Copy the `approval_url` from the response (e.g. `http://localhost:4020/approval/<request_id>`).

- Open that URL in your browser (**localhost**).
- You should see **Authenticate to approve scoped access** — click **Authenticate with passkey** and complete the prompt (every scoped-access request requires this).
- After authentication, the approval page appears: domains, limits, TTL. Click **Approve** or **Deny**.
- Poll for the result:

```bash
curl -s http://127.0.0.1:4020/request-scoped-access/<request_id>
# When approved: { "status": "approved", "session_handle": "..." }
# When denied:  { "status": "denied", "reason": "..." }
```

**4. Optional checks**

- **Dashboard:** http://localhost:4020/dashboard — wallet info, active/past scoped-access grants, transactions.
- **Second scoped-access request:** Run the same `curl` again, open the new approval URL — you must authenticate with passkey again (no 24h skip for approvals).
- **Wallet status:** `curl http://127.0.0.1:4020/wallet-status`

---

#### 3.1 Who uses the signing secret? (target: keychain / passkey)

**What signing is for:** Security. Only an authorized caller can call `POST /execute`, so other local programs (or malware) cannot forge paid requests even with a stolen `session_handle`.

**Target design (post-MVP):** The secret lives in **OS keychain**; the host uses it to sign `/execute`, so the user does not type a passphrase. **Passkey is for delegation approval only** (user proves identity when approving), not for signing each execute. See PRD §4.2.2 and `dev/DESIGN-local-portal.md` §4.2.

**MVP (current):** We use **HMAC** with a shared secret. Until keychain/passkey is implemented:

| Entity | Role | How it gets the secret (MVP) |
|--------|------|------------------------------|
| **Local Portal server** | Verifies HMAC on every `POST /execute`. | Reads `LOCAL_PORTAL_SHARED_SECRET` from env at server startup. |
| **Caller of `POST /execute`** (agent, host, script) | Must sign the request body with HMAC. | **Ask the user** for the passphrase when the agent needs to call `/execute` (same value as server). Interim approach until we have keychain/passkey for signing. |

#### 3.2 Wallet status (detect unauthenticated wallet)

**`GET http://127.0.0.1:4020/wallet-status`** runs `npx awal@latest status` and returns:

- **`authenticated`** (boolean) – true if the wallet is signed in and ready for x402.
- **`code`**, **`stdout`**, **`stderr`** – exit code and output from the status command.
- **`message`** – when not authenticated, a short message for the user (e.g. ask them to run `npx awal@latest status` and sign in).

The agent should call this **before** proposing scoped access or paid calls. If `authenticated` is false, ask the user to authenticate their wallet and do not proceed until it is true.

If the agent skips this and calls `POST /execute` while the wallet is not authenticated, the server returns **503** with body `{ "error": "wallet_not_authenticated", "message": "..." }` so the agent can then ask the user to sign in and retry.

---

### 4. Flow Overview

1. **Agent/host** calls **`POST /request-scoped-access`** with a policy. The server does **not** create a session yet; it creates a **pending request** and returns an **approval URL**.
2. **User** must open that URL in a browser. **Approving on that page is the only way to approve**; there is no auto-approve and no other endpoint that creates a session.
3. After the user clicks **Approve** or **Deny** on the approval page, the host can poll **`GET /request-scoped-access/:request_id`** to get the result (`approved` + `session_handle`, or `denied`).
4. Agent then uses **`x402_request(session_handle, url, ...)`**, backed by **`POST /execute`**.

You can inspect:

- `Delegation_Sessions` – session policies and metadata (under the hood for Scoped Access).
- `Local_API_Requests` – raw `/execute` calls.
- `Transaction_Logs` – x402 decisions.

---

### 5. Approval URL – the only way to approve

When you call **`POST /request-scoped-access`**, the response looks like:

```json
{
  "status": "pending",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "approval_url": "http://127.0.0.1:4020/approval/550e8400-e29b-41d4-a716-446655440000",
  "message": "User approval required. Open the approval_url in a browser, then poll /request-scoped-access/:request_id for result."
}
```

- **URL the user must open:** use **`approval_url`** from the response, or build it as:
  - **`http://127.0.0.1:4020/approval/<request_id>`**
  - where **`<request_id>`** is the UUID from the response (e.g. `550e8400-e29b-41d4-a716-446655440000`).
- **No session exists** until the user opens that URL and clicks **Approve** on the page. Clicking **Approve** on that UI is the **only** way to create a session; there is no API or backdoor that creates a session without that step.
- To get the result after the user has approved or denied, poll:
  - **`GET http://127.0.0.1:4020/request-scoped-access/<request_id>`**
  - Response when approved: `{ "status": "approved", "session_handle": "..." }`.
  - Response when denied: `{ "status": "denied", "reason": "..." }`.

**Example: create pending request**

```bash
curl -X POST http://127.0.0.1:4020/request-scoped-access \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent_example_01",
    "user_id": "user_example_01",
    "policy": {
      "allowed_domains": ["api.example.com"],
      "max_total_spend": 5000000,
      "max_per_tx": 500000,
      "ttl_seconds": 600
    }
  }'
```

Then open the returned **`approval_url`** in your browser, click **Approve**, and poll **`GET /request-scoped-access/<request_id>`** to obtain **`session_handle`**.

---

### 6. `/execute` (x402_request) – Testing

**Endpoint**

- `POST http://127.0.0.1:4020/execute`

**Envelope fields**

```json
{
  "session_handle": "<opaque>",
  "operation": "x402_request",
  "params": {
    "url": "https://api.example.com/paid-endpoint",
    "method": "GET",
    "headers": {
      "Accept": "application/json"
    },
    "body": null
  },
  "counter": 1,
  "idempotency_key": "some-uuid-or-client-id"
}
```

**HMAC signature (required)**

- Compute `HMAC-SHA256(LOCAL_PORTAL_SHARED_SECRET, JSON.stringify(body))` and send it as HTTP header `x-local-portal-signature: <hex>`.
- Until keychain/passkey is implemented, the agent may obtain the passphrase from the user (e.g. prompt once) so the agent can sign.

**Example (Node snippet)**

```ts
import crypto from "crypto";

// In practice the agent should ask the user for this (same value as server's LOCAL_PORTAL_SHARED_SECRET).
const secret = process.env.LOCAL_PORTAL_SHARED_SECRET || "change-me-dev-secret";

const body = {
  session_handle: "your-session-handle",
  operation: "x402_request",
  params: {
    url: "https://api.example.com/paid-endpoint",
    method: "GET",
    headers: { Accept: "application/json" },
    body: null
  },
  counter: 1,
  idempotency_key: "test-id-1"
};

const payload = JSON.stringify(body);
const sig = crypto.createHmac("sha256", secret).update(payload).digest("hex");

const res = await fetch("http://127.0.0.1:4020/execute", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "x-local-portal-signature": sig
  },
  body: payload
});

console.log(await res.json());
```

**Responses to expect (MVP)**

- **401 Unauthorized** – missing or invalid HMAC (caller must sign with the same secret the server was started with).
- **403 no_session** – unknown `session_handle`.
- **409 replay** – `counter` ≤ `last_counter` (replay or out-of-order).
- **402 Denied by policy** – domain not in `allowed_domains`, TTL expired, etc.
- **200 / 2xx** – on success when Awal x402 pays and returns a response.

---

### 7. Agentic Wallet (Awal) Integration Notes

- Local Portal uses:

  ```bash
  npx awal@latest status
  npx awal@latest x402 pay <url> [-X METHOD] [-d BODY] [-h HEADERS_JSON] --json
  ```

- These are invoked **only inside** `AwalAdapter`:
  - The agent never sees or calls `awal` directly.
  - All amounts / payment details stay inside Agentic Wallet infrastructure.

Before testing real x402 flows:

1. Run `npx awal@latest status` manually to ensure you’re authenticated.
2. Ensure your wallet has sufficient USDC for the targeted paid API.

---

### 8. Troubleshooting: "Payment was authorized but rejected by server"

When `POST /execute` returns **502** with a body like *"Bridge communication error: X402 submission failed: Payment was authorized but rejected by server"*, the wallet authorized the payment but the **x402 facilitator** (server-side) rejected it.

**Debug logging:** On each failure, the Local Portal appends a log entry to **`.temporal/logs/awal-x402-pay-debug.log`** (project root) with timestamp, URL, method, exit code, and the last 2000 chars of stdout/stderr from `npx awal x402 pay`. Inspect that file for full Awal output.

**Common causes:**

| Cause | What to check |
|-------|----------------|
| **Facilitator signature rejection** | The facilitator may return `invalid_exact_evm_payload_signature`. With **Coinbase Smart Wallet** (passkey / ERC-6492), there is a [known issue](https://github.com/coinbase/x402/issues/623): the facilitator does not parse ERC-6492 signatures correctly. See [PR #672](https://github.com/coinbase/x402/pull/672) for a fix. Until your facilitator or the upstream x402 package includes that fix, payments from Awal (Smart Wallet) can be rejected. |
| **Network / balance** | Wallet must be on the same network as the resource (e.g. **base-sepolia** for nickeljoke). You need testnet USDC on that network. Run `npx awal@latest status` and check balance. |
| **KYT / payer flagged** | Facilitator may reject with a KYT-related reason; see [x402 troubleshooting](https://docs.cdp.coinbase.com/x402/support/troubleshooting). |

**Manual test:** Run the same command the Portal uses to see raw output:

```bash
npx awal@latest x402 pay "https://nickeljoke.vercel.app/api/joke" -X POST \
  -d '{"discoverable":true,"method":"POST","type":"http"}' \
  -h '{"Content-Type":"application/json"}' --json
```

If the facilitator returns a JSON error body, it may include an `error` or `invalidReason` field (e.g. `invalid_exact_evm_payload_signature`).

---

### 9. Current Limitations (MVP)

- Budget enforcement (`max_total_spend`, `max_per_tx`) is not yet wired to amounts reported by x402 challenges.
  - Awal is still called with implicit limits; we will later add explicit `--max-amount` and stateful spend tracking.
- `Transaction_Logs` is created but not yet fully populated on each decision.
- Approval requires the user to open the approval URL and authenticate with passkey; there is no auto-approve.

These are acceptable for early testing of the **delegated x402 flow** and can be iterated on later. 

