## Local Portal & Agentic Wallet – Design (MVP)

This document captures the implementation design for the **Local Portal** and its integration with **Coinbase Agentic Wallet**. It is aligned with `dev/PRD` and `dev/ERD` and is intended as the main reference while building the MVP.

---

### 1. Goals & Scope

- **Goal (MVP)**: Enable an AI agent to access **x402-protected APIs safely** using a **fixed procedure skill**, with:
  - Local-only enforcement.
  - User-approved session policy (allowed domains, spend limits, TTL).
  - Agent never performing payment logic directly.

- **Non-goals (post-MVP)**:
  - Global Portal (dashboard, telemetry, remote kill switch).
  - Multi-device sync.
  - Hardware auth (biometrics / PIN).
  - mTLS.
  - Key rotation.
  - Enterprise monitoring.

---

### 2. High-Level Architecture

MVP is **local-only**:

> Agent ⇄ Local Skills ⇄ Local Portal ⇄ Agentic Wallet (`awal`) ⇄ x402 APIs

**Key properties:**

- Agent is **semi-trusted**, has **no wallet keys**, and **no payment logic**.
- Local Portal enforces **Scoped Access (grant) policy** before any payment.
- Agentic Wallet (`awal`) provides wallet + x402 payment capabilities; Local Portal is the enforcement and proxy layer.

---

### 3. Agent-Facing Skills

The agent integrates exactly **two logical skills**. Only **one of them** (`x402_request`) is backed by a direct network tool. The other (`propose_scoped_access`) is an **intent** that must be mediated by a **user-facing Approval UI**.

#### 3.1 `propose_scoped_access(policy)` (agent intent, not HTTP)

**Purpose:** Agent proposes a Scoped Access policy (grant). The host runtime surfaces this proposal to the **Local Portal Approval UI**, and only the **user** can approve/deny using their authenticated wallet / passkey. The agent itself never calls the approval endpoint.

**Conceptual signature (agent side):**

```ts
propose_scoped_access(policy: {
  allowed_domains: string[];
  max_total_spend: string; // e.g. "5.00"
  max_per_tx: string;      // e.g. "0.50"
  ttl_seconds: number;
}): {
  status: "approved" | "denied";
  session_handle?: string;
  reason?: string;
}
```

**Trust boundary:**

- `propose_scoped_access` is **not** allowed to hit `/request-scoped-access` directly.
- Instead, the host runtime:
  - Receives the proposed `policy` (Scoped Access grant) from the agent.
  - Launches the **Local Portal Approval UI** (see §4.1.1).
  - Only upon explicit **user approval** does the UI/backend call `/request-scoped-access` on the Local Portal.
  - Returns `{ status, session_handle? }` back to the agent.

**Flow (end-to-end):**

1. Agent calls `propose_scoped_access(policy)`.
2. Host runtime opens Local Portal **Approval UI** for this proposal:
   - Shows agent name / origin.
   - Shows allowed domains.
   - Shows spend limits (max_total_spend / max_per_tx).
   - Shows TTL.
3. User approves/denies via passkey / Awal-authenticated session.
4. **UI backend** (not the agent) calls `POST /request-scoped-access` on Local Portal with the approved `policy`.
5. Local Portal creates a `Delegation_Sessions` row and returns an opaque `session_handle` to the UI backend.
6. Host returns `{ status: "approved", session_handle }` or `{ status: "denied", reason }` to the agent’s `propose_scoped_access` call.

The agent **never** has direct access to `/request-scoped-access` and cannot create or modify policies on its own.

#### 3.2 `x402_request(session_handle, url, method?, headers?, body?)`

**Purpose:** Agent performs HTTP requests which may hit an x402 paywall. The skill **encapsulates the entire x402 protocol**:

- Agent sends the desired HTTP request.
- Local Portal:
  - Sends the request.
  - Handles 402 (parse challenge, validate policy, pay via Agentic Wallet, retry).
  - Returns the final response + metadata.

**Conceptual signature (agent side):**

```ts
x402_request(
  session_handle: string,
  url: string,
  method?: "GET" | "POST" | "PUT" | "DELETE" | "PATCH",
  headers?: Record<string, string>,
  body?: string
): {
  status: number;
  headers: Record<string, string>;
  body: string;
  metadata: {
    x402_paid?: boolean;
    deny_code?: string;
  };
}
```

**On-wire payload to Local Portal (backed by `/execute`):**

```json
{
  "session_handle": "opaque_handle_xxx",
  "operation": "x402_request",
  "params": {
    "url": "https://api.example.com/data",
    "method": "GET",
    "headers": { "Accept": "application/json" },
    "body": null
  },
  "counter": 1,
  "idempotency_key": "uuid-or-client-key",
  "signature": "hmac_hex..."
}
```

Agent never sees or calls Agentic Wallet / `awal` directly.

---

### 4. Local Portal Components

Local Portal is a local daemon exposing a loopback-only HTTP API and using `awal` under the hood.

#### 4.1 HTTP API Layer & Approval UI

- **Endpoints (daemon):**
  - `POST /request-scoped-access` (formerly `POST /request-delegation`)
    - **UI-only** endpoint for creating Scoped Access grants.
    - Called by the **Local Portal Approval UI backend** (or a trusted host process), **never by the agent directly**.
  - `POST /execute`
    - Called by `x402_request(...)` (operation=`"x402_request"`).
- **Binding:**
  - Bind only to `127.0.0.1`.
  - Document OS firewall rules to prevent external access.

##### 4.1.1 Approval UI & Passkey / Wallet Auth (Conceptual)

The Approval UI is responsible for:

- Displaying proposed Scoped Access policies (grants) from the agent (`propose_scoped_access(policy)`).
- Binding approvals to a **real user** via:
  - Awal authentication (email/OTP) and/or
  - Passkey / platform authenticator (post-MVP).
- Calling `POST /request-scoped-access` **only after** the user confirms.

**MVP simplification (today):**

- `/request-scoped-access` auto-approves and does not yet have a real UI.
- During development, **manual `curl` invocations** of `/request-scoped-access` are treated as “the user calling the approval API directly”.
- The long-term design in this document makes it clear that:
  - Agent-facing skills must be limited to `propose_scoped_access` + `x402_request`.
  - Approval remains a **user-only** action via UI.

#### 4.2 Auth & Envelope Validator

**Scoped Access vs execute:**

- **Scoped Access grant (approval):** The only place the user is in the loop. Signing / passkey is needed **only here** — the user approves the Scoped Access grant (e.g. via passkey on the approval UI). No human approval on each paid call.
- **Execute:** The actor is always the **agent** under an already-approved Scoped Access grant. No human approval per `/execute`. The agent (via the host) calls `/execute` with a valid `session_handle`; the Portal enforces policy and replays. HMAC on the request body only proves that the caller holds the shared secret (authorized host), so other local programs cannot forge execute calls even if they steal a `session_handle`.

**Target (post-MVP):** The secret used for HMAC lives in **OS keychain**; the host reads it to sign `/execute`. The user does not type a passphrase. **Passkey is for delegation approval only** (user proves identity when approving), not for signing each execute.

**MVP (current):** HMAC with a shared secret from env (`LOCAL_PORTAL_SHARED_SECRET`). Until keychain is implemented, the agent may ask the user for the passphrase so the host can sign — interim only.

- For every `/execute` call we validate:
  - `session_handle` present.
  - `x-local-portal-signature` header is valid HMAC of the request body using the server’s shared secret (today: `LOCAL_PORTAL_SHARED_SECRET`; target: secret from OS keychain).
  - `counter` is a positive integer.
  - `idempotency_key` present.
- If invalid → reject and **do not** hit any wallet / network.

#### 4.3 Session Manager

Implements session lifecycle using `Delegation_Sessions` (see `dev/ERD`).

Responsibilities:

- Look up session by opaque `session_handle`.
- Enforce **session validity**:
  - TTL not exceeded.
  - Not revoked.
  - Budget not exhausted.
- **Replay protection**:
  - Ensure `counter > last_counter` before processing.
  - Update `last_counter` after each accepted request.
- Track remaining budget:
  - Deduct amounts on APPROVED x402 payments.

#### 4.4 Policy Engine

Given `(session, operation, params)` decides:

- **ALLOW**:
  - Operation in `allowed_operations` (must be `"x402_request"`).
  - Domain in `allowed_domains`.
  - Amount within remaining budget and `max_per_tx`.
  - Within TTL and rate limits.
- **DENY**:
  - Returns `deny_code`:
    - `DOMAIN_NOT_ALLOWED`
    - `BUDGET_EXCEEDED`
    - `PER_TX_EXCEEDED`
    - `SESSION_EXPIRED`

Results are logged into `Transaction_Logs` and `Local_API_Requests` per ERD.

---

### 5. x402 Engine (Inside Local Portal)

The x402 Engine owns the **procedural behavior** of `x402_request`.

#### 5.1 Interface (internal)

```ts
type X402Params = {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string | null;
};

type X402Result = {
  status: number;
  headers: Record<string, string>;
  body: string;
  metadata: {
    x402_paid: boolean;
    deny_code?: string;
  };
};

async function handleX402Request(
  session: DelegationSession,
  params: X402Params
): Promise<X402Result> { /* see algorithm below */ }
```

#### 5.2 Algorithm (MVP)

1. **Initial HTTP request**
   - Send HTTP request with given `url`, `method`, `headers`, `body`.
   - Record `Local_API_Requests` entry (auth, counter, params_hash, etc.).

2. **If status = 200**
   - Return `status`, `headers`, `body`, `metadata: { x402_paid: false }`.

3. **If status = 402**
   - Extract x402 **challenge** from the response as defined by the Agentic Wallet x402 docs.
   - Compute and store `http_402_proof_hash` in `Transaction_Logs`.
   - Run **Policy Engine** with:
     - URL domain.
     - Required amount from challenge.
   - If DENY:
     - Log `Transaction_Logs` with `decision = DENIED`, `deny_code`, `counter`, `idempotency_key`, `http_402_proof_hash`.
     - Return response with `metadata: { x402_paid: false, deny_code }`.

4. **If ALLOW**
   - Call **Awal Adapter**:

     ```ts
     const payResult = await awalAdapter.payX402Challenge(challenge);
     ```

   - If payment fails:
     - Map Awal / Agentic Wallet error to a `deny_code`.
     - Log DENIED transaction.
     - Return error to agent.

5. **Retry HTTP request with payment proof**
   - Attach necessary proof headers or tokens returned from Agentic Wallet.
   - Make a second HTTP call to the same URL.
   - Expect a 200 (or other terminal status) that now reflects paid access.

6. **Log & return**
   - Log APPROVED `Transaction_Logs` row with:
     - `operation = "x402_request"`.
     - `amount`, `domain`, `decision = APPROVED`, `http_402_proof_hash`, `tx_hash`, `counter`, `idempotency_key`.
   - Update:
     - `Delegation_Sessions.last_counter`.
     - Remaining budget (`max_total_spend` minus spent).
   - Return final HTTP status, headers, body, and `metadata: { x402_paid: true }`.

---

### 6. Awal Adapter (Agentic Wallet Integration)

The Awal Adapter isolates all Agentic Wallet / `awal` specifics behind a small interface.

#### 6.1 Interface

```ts
type X402Challenge = {
  // Fields derived from 402 response and Agentic Wallet x402 spec
};

type X402PaymentResult = {
  success: boolean;
  tx_hash?: string;
  proofHeaders?: Record<string, string>;
  error_code?: string;
  error_message?: string;
};

interface AwalAdapter {
  ensureAuthenticated(): Promise<void>;
  payX402Challenge(challenge: X402Challenge): Promise<X402PaymentResult>;
}
```

#### 6.2 Implementation Notes

- Use `awal` CLI (see Agentic Wallet docs) for:
  - Authentication (email OTP).
  - Paying x402 challenges (mapping challenge → CLI args).
- `ensureAuthenticated()` ensures the user is logged in, prompting via `awal` if necessary.
- `payX402Challenge`:
  - Serializes the x402 challenge into the expected format.
  - Invokes `awal` CLI and parses the structured output.
  - Returns payment proof headers and `tx_hash` for logging.

The agent never learns about `awal` commands or any wallet-specific details.

---

### 7. Data & Logging (ERD Alignment)

This design assumes the schema from `dev/ERD`:

- **Delegation_Sessions**
  - Stores policy (`allowed_domains`, `max_total_spend`, `max_per_tx`, `ttl_seconds`, etc.).
  - Tracks `last_counter`, `revoked_at`, `client_fingerprint`, etc.

- **Transaction_Logs**
  - One row per wallet-related decision (APPROVED / DENIED).
  - Records `operation`, `amount`, `domain`, `decision`, `deny_code`, `counter`, `idempotency_key`, `http_402_proof_hash`, `tx_hash`, `created_at`.

- **Local_API_Requests**
  - One row per `/execute` call.
  - Records `operation`, `params_hash`, `auth_valid`, `counter`, `ip`, `created_at`.

These tables support:

- **Replay protection** (via `last_counter` and `counter`).
- **Audit and disputes** (via `Transaction_Logs` and `http_402_proof_hash`).
- **Forensics** (via `Local_API_Requests`).

---

### 8. Implementation cost: keychain and passkey

**Important:** Execute is always done by the **agent** under a Scoped Access grant; there is no human approval per `/execute`. Signing (and passkey) is needed **for grant approval only** — i.e. when the user approves the session. We do **not** do passkey (or any user gesture) per execute call.

Rough options and effort:

| Approach | What it does | Effort | Notes |
|----------|----------------|--------|--------|
| **A. OS keychain only** | Store the HMAC secret in OS keychain. Portal and host read it to sign/verify `/execute`; no passphrase. | **Medium** (2–5 days) | Keychain lib (e.g. `keytar` or `@napi-rs/keychain`). Portal writes secret at first run (or from env once); host that calls `/execute` reads same keychain entry to sign. |
| **B. Passkey on grant approval only** | When the user opens the **Scoped Access approval** page, authenticate with WebAuthn/passkey before creating the session. `/execute` is still signed with HMAC (env or keychain); no passkey per execute. | **Medium** (2–4 days) | Passkey is only for approval UI. Server: challenge, credential storage, assertion verify (e.g. `@simplewebauthn/server`). Browser approval page: `navigator.credentials.get()`. |
| **C. Keychain + passkey for approval** | A + B: secret in keychain; user approves **Scoped Access grant** with passkey. Agent then calls `/execute` with HMAC (keychain); no human in the loop on execute. | **Medium** (A + B, some overlap) | Best UX: one passkey at approval time; no passphrase; execute stays agent-only. |

We do **not** implement “passkey per `/execute`”: the actor for execute is always the agent under an already-approved Scoped Access grant; signing is for grant approval only.

---

### 9. Security Checklist (MVP)

To be implemented and verified:

- API bound to **127.0.0.1** only.
- **Auth for `/execute`:** Target = secret in OS keychain (host signs with it; no passkey per execute). **Passkey is for delegation approval only.** MVP = HMAC with env-based secret; agent may ask user for passphrase until keychain is implemented.
- **Opaque `session_handle`** usage (agent never sees full policy).
- **TTL + inactivity timeout** enforced on sessions.
- **Domain allowlist** (`allowed_domains`) enforced for every request.
- **Per-tx and rate limit** (`max_per_tx`, `rate_limit`) enforced before payment.
- **Replay protection** using (`counter`, `last_counter`, `idempotency_key`).
- **Keychain / OS secure storage** for Awal / Agentic Wallet tokens and secrets.

This doc should be kept in sync with `dev/PRD` and `dev/ERD` as those evolve.

