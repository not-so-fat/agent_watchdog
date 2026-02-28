# Agent Pulse

**Stop AI agents from draining your wallet.**

Agent Pulse is a **Scoped Access** enforcement layer that lets AI agents access [x402](https://www.x402.org/)-protected paid APIs without ever touching your private keys or wallet directly. The agent gets a constrained session; a local gatekeeper enforces budgets, domain allowlists, and time limits on every request.

## The Problem

Autonomous AI agents equipped with crypto wallets have unrestricted access to funds once authenticated. This creates a risk of runaway spending, loop-based drain, or unauthorized transactions — what we call **agentic leakage**.

## The Solution

Instead of giving the agent the wallet, we give it a **proxy** to a local deterministic service that holds the wallet connection. This **Local Portal** acts as a gatekeeper:

```
Agent  ──(skill calls)──▶  Local Portal  ──(x402 + payment)──▶  Paid API
                               │
                          Policy Engine
                        (budget, domains, TTL)
```

The agent interacts through exactly **two operations**:

| Operation | What it does |
|-----------|-------------|
| **request_scoped_access(policy)** | Agent proposes a Scoped Access grant (session policy: domains, spend limits, TTL). User approves via browser with passkey. Portal returns an opaque `session_handle`. |
| **x402_request(session_handle, url, ...)** | Agent asks the Portal to make a paid HTTP request. Portal checks policy, handles the x402 payment protocol internally, and returns the response. |

The agent never performs payment logic, never sees private keys, and cannot exceed the approved policy.

## Quick Start

### Prerequisites

- Node.js 18+
- [Coinbase Agentic Wallet](https://docs.cdp.coinbase.com/agentic-wallet/docs/overview) (`npx awal@latest`) — authenticated and funded with USDC

### 1. Start the Local Portal

```bash
cd local-portal
npm install
export LOCAL_PORTAL_SHARED_SECRET="your-secret-here"
npx ts-node src/server.ts
```

Portal runs at `http://127.0.0.1:4020`. Use `localhost` for browser pages (WebAuthn requires it).

### 2. Register a Passkey

Open http://localhost:4020/account and register a passkey (Touch ID / Windows Hello / device PIN). This is required to approve Scoped Access sessions (grants).

### 3. Use from an AI Agent

The agent (e.g. Cursor with the included skills) follows this flow:

1. Check wallet status → `GET /wallet-status`
2. Request Scoped Access → `POST /request-scoped-access` with a policy
3. User approves in browser (passkey required)
4. Make paid requests → `POST /execute` with session handle + HMAC signature

See [local-portal/README.md](local-portal/README.md) for full API reference, HMAC signing details, and troubleshooting.

## Project Structure

```
agent-pulse/
├── local-portal/          # The gatekeeper service (Node.js / TypeScript)
│   ├── src/
│   │   ├── server.ts          # HTTP server + approval UI
│   │   ├── sessionManager.ts  # Delegation sessions & policy storage
│   │   ├── policyEngine.ts    # Per-request policy enforcement
│   │   ├── x402Engine.ts      # x402 protocol handling
│   │   ├── awalAdapter.ts     # Coinbase Agentic Wallet CLI bridge
│   │   ├── userManager.ts     # Passkey (WebAuthn) registration & auth
│   │   └── db.ts              # SQLite persistence
│   └── README.md              # Detailed dev docs & API reference
├── .cursor/skills/        # AI agent skill definitions
│   ├── agent-pulse-delegation/    # How the agent requests sessions
│   ├── agent-pulse-x402/          # How the agent makes paid requests
│   └── agent-pulse-wallet-status/ # How the agent checks wallet auth
└── dev/                   # Design documents
    ├── PRD                # Product requirements
    ├── ERD                # Entity-relationship diagram
    └── DESIGN-*.md        # Component design specs
```

## Security Model

- **No keys in agent context** — The agent never sees wallet credentials or private keys.
- **User approval required** — Every delegation session requires passkey authentication in the browser.
- **Policy enforcement** — Domain allowlists, per-transaction limits, total budget caps, and session TTL are checked on every request.
- **HMAC-signed requests** — `/execute` calls require HMAC-SHA256 signatures to prevent unauthorized local access.
- **Loopback only** — The Local Portal binds to `127.0.0.1`; it is not exposed to the network.

## License

MIT
