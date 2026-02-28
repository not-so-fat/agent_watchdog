## User Authentication – Design

This document describes the user authentication model for the Local Portal. It supersedes the passkey-per-request approach used in the initial MVP.

---

### 1. Problem

The original passkey flow ran WebAuthn **registration** (create a new credential) on every delegation approval. Credentials were stored in an in-memory `Map`, lost on restart, and not tied to any persistent user identity. This meant:

- No actual authentication — only a physical presence check.
- A new passkey created each time — wasteful and confusing.
- No persistent user record — cannot link delegation history to a person.

### 2. Principles

- **Wallet email = user identity.** The email from `awal status` is the canonical user identifier. No separate registration form or password.
- **Register once, authenticate many.** Passkey registration happens once on the Account page. Delegation approvals use WebAuthn **authentication** (assert an existing credential).
- **Persist in SQLite.** Users, passkey credentials, and browser sessions are stored in `local-portal.db` alongside the existing tables.

### 3. Data Model

Three new tables added in `db.ts`:

**Users**

| Column | Type | Notes |
|--------|------|-------|
| user_id | TEXT PK | UUID |
| email | TEXT UNIQUE NOT NULL | From `awal status` |
| created_at | INTEGER NOT NULL | Epoch ms |

**Passkey_Credentials**

| Column | Type | Notes |
|--------|------|-------|
| credential_id | TEXT PK | Base64url WebAuthn credential ID |
| user_id | TEXT FK → Users | Owner |
| public_key | BLOB NOT NULL | WebAuthn public key |
| counter | INTEGER NOT NULL DEFAULT 0 | Signature counter for replay detection |
| transports | TEXT | JSON array of transports (e.g. `["internal"]`) |
| device_name | TEXT | Human-readable label |
| created_at | INTEGER NOT NULL | Epoch ms |

**Browser_Sessions**

| Column | Type | Notes |
|--------|------|-------|
| session_token | TEXT PK | Random 32-byte hex |
| user_id | TEXT FK → Users | Authenticated user |
| expires_at | INTEGER NOT NULL | Epoch ms |
| created_at | INTEGER NOT NULL | Epoch ms |

### 4. User Identity

The user does not create an account manually. Instead:

1. User authenticates with the Agentic Wallet (`awal status`) — this gives us their email.
2. On first interaction (visiting `/account` or any API that resolves the user), a `Users` row is created automatically via `findOrCreateUserByEmail(email)`.
3. The wallet email is the single source of truth for identity.

If the awal wallet is re-authenticated with a different email, a new user is created. This is acceptable for MVP (one user per local portal instance).

### 5. Passkey Lifecycle

**Registration (one-time, on `/account`)**

1. User visits `/account`.
2. Portal calls `awal status` to get the wallet email.
3. Portal finds/creates the `Users` row.
4. User clicks "Register New Passkey".
5. Client calls `POST /api/passkey/register-challenge` → server returns WebAuthn registration options + `challenge_id`.
6. Browser runs `navigator.credentials.create()` (biometric / PIN prompt).
7. Client sends result to `POST /api/passkey/register-verify` with `challenge_id`.
8. Server verifies, stores credential in `Passkey_Credentials`, creates a browser session, sets `portal_session` cookie.

**Authentication (on EVERY delegation approval — per-delegation, not session-based)**

1. User opens `/approval/:rid`.
2. Server checks if this **specific `rid`** has been authenticated via `approvalAuth` map.
3. If not authenticated (regardless of browser session): show "Authenticate" button.
4. Client calls `POST /api/passkey/auth-challenge` → server returns WebAuthn authentication options + `challenge_id`.
5. Browser runs `navigator.credentials.get()` (biometric / PIN prompt).
6. Client sends assertion to `POST /api/passkey/auth-verify` with `challenge_id` **and `approval_rid`**.
7. Server verifies, updates counter, marks `approvalAuth[rid] = user_id`, also creates a browser session (for non-approval pages).
8. Page reloads → `approvalAuth.get(rid)` returns a user → approval UI shown.
9. When approved or denied, `approvalAuth` entry is cleaned up.

**Key security property:** Browser sessions (24h cookie) are **never** sufficient for delegation approval. Each delegation requires a fresh passkey authentication. Sessions are only used for non-critical pages (`/account`, `/dashboard`).

### 6. Registration vs Authentication

| | Registration | Authentication |
|--|--|--|
| When | Once, on `/account` | **Every** delegation approval |
| WebAuthn API | `navigator.credentials.create()` | `navigator.credentials.get()` |
| Server functions | `generateRegistrationOptions` / `verifyRegistrationResponse` | `generateAuthenticationOptions` / `verifyAuthenticationResponse` |
| Result | New row in `Passkey_Credentials` | Per-delegation `approvalAuth[rid]` + browser session |

### 7. Browser Session

- HTTP-only cookie named `portal_session`.
- Value: random 32-byte hex token.
- `SameSite=Strict`, `Path=/`.
- TTL: 24 hours (configurable via `DEFAULT_SESSION_TTL_MS` in `userManager.ts`).
- Looked up in `Browser_Sessions` table → maps to `user_id`.
- Expired sessions cleaned periodically (every 10 minutes).
- **Used for:** `/account` page, `/dashboard`, API endpoints that need user identity.
- **NOT used for:** delegation approval — that always requires per-delegation passkey auth.

### 8. API Endpoints

**New endpoints:**

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/user` | Current user info + passkey list (requires awal auth) |
| POST | `/api/passkey/register-challenge` | WebAuthn registration options (requires awal auth) |
| POST | `/api/passkey/register-verify` | Verify registration, store credential, create session |
| POST | `/api/passkey/auth-challenge` | WebAuthn authentication options |
| POST | `/api/passkey/auth-verify` | Verify assertion, create session; optionally mark `approval_rid` |
| DELETE | `/api/passkey/:credential_id` | Remove a passkey (requires session) |
| POST | `/api/logout` | Clear browser session |

**New page:**

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/account` | Account management page (wallet status, passkey CRUD) |

**Modified:**

- `GET /approval/:rid` — checks per-delegation `approvalAuth` map (not browser session).
- `POST /approval/:rid/approve` — verifies per-delegation `approvalAuth` entry; uses the authenticated user's `user_id` for the delegation.

**Removed:**

- `POST /approval/:rid/passkey-challenge` — replaced by `/api/passkey/auth-challenge`.
- `POST /approval/:rid/passkey-verify` — replaced by `/api/passkey/auth-verify`.

### 9. In-Memory State

**WebAuthn challenges** (`webauthnChallenges` map): Ephemeral (valid for ~60 seconds). Stored keyed by a random `challenge_id` (UUID). Each entry tracks:

- `challenge`: the base64url challenge string.
- `userId`: set for registration challenges (identifies who is registering).
- `type`: `"register"` or `"auth"`.
- `createdAt`: used for cleanup.

A `setInterval` purges entries older than 5 minutes.

**Per-delegation authentication** (`approvalAuth` map): Maps `request_id → user_id`. Populated when `POST /api/passkey/auth-verify` receives an `approval_rid` parameter. Cleaned up when the request is approved or denied. This ensures every delegation approval requires a fresh passkey authentication, even if the user has an active browser session.

### 10. Pages & Flow

```
/account          — Set up: wallet connection + passkey registration
/approval/:rid    — Delegation approval (authenticates if needed)
/dashboard        — Existing dashboard (unchanged)
```

When a user first installs the portal:

1. Authenticate agentic wallet: `npx awal@latest status`
2. Visit `http://localhost:4020/account`
3. Register a passkey.
4. When an agent requests delegation, open the approval URL.
5. Authenticate with existing passkey (or skip if session cookie still valid).
6. Approve or deny.

### 11. Module Structure

- `db.ts` — Schema migrations (now includes Users, Passkey_Credentials, Browser_Sessions).
- `userManager.ts` — CRUD for users, passkey credentials, and browser sessions.
- `server.ts` — Express routes, page rendering, WebAuthn endpoints.
- `sessionManager.ts` — Delegation session management (unchanged).

### 12. Security Notes

- Passkey private keys never leave the authenticator device (WebAuthn guarantee).
- `portal_session` cookie is HTTP-only (not accessible to JavaScript) and SameSite=Strict.
- The portal binds to `127.0.0.1` only — browser sessions are local-only.
- Removing the last passkey is blocked to prevent lockout.
- WebAuthn requires `localhost` (not `127.0.0.1`); the portal redirects automatically.
