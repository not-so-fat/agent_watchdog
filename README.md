# Agent Control Plane -- Hackathon Demo

An **Agent Control Plane** that monitors what AI agents do on your machine and controls how they spend your money. The demo uses **Cursor as the AI agent**: Watchdog blocks Cursor from running `awal` directly, and the user grants scoped access through **Pulse**, which handles payment on Cursor's behalf -- autonomously within the approved scope.

## System Overview

```
                         User (browser)
                  Dashboard + Approval UI
                  http://localhost:4020/dashboard
                           |
      +--------------------+---------------------+
      |                                           |
+-----v------+                          +---------v---------+
|  Watchdog  |                          |  Pulse            |
|  (wrapper) |                          |  (Node.js :4020)  |
|            |                          |                   |
|  Block     |                          |  Scoped Access    |
|  awal from |                          |  Policy engine    |
|  Cursor    |                          |  x402 engine      |
|  PIDs      |                          |  Calls awal       |
|            |                          |  Dashboard        |
+-----+------+                          +---------+---------+
      |  monitors                                 |  calls
      v                                           v
+-------------+                          +---------------+
|  Cursor     |---blocked--------------->|  awal CLI     |
|  (AI Agent) |                          |  (wallet)     |
|             |---via Pulse skill------->|  (whitelisted)|
+-------------+                          +---------------+
                                                  |
                                           x402 payment
                                                  v
                                         +----------------+
                                         |  Paid API      |
                                         |  (x402-enabled)|
                                         +----------------+
```

## Quick Start

### 1. Start Pulse (Portal + Dashboard)

```bash
cd pulse/local-portal
cp .env.example .env
# Edit .env: set LOCAL_PORTAL_SHARED_SECRET

npm install
npm run build
npm start   # Runs on http://0.0.0.0:4020
```

Open **http://localhost:4020/dashboard** -- the unified Agent Control Plane dashboard with:
- **Activity** -- merged timeline of blocked commands, payments, observations
- **Scoped Access** -- manage grants (create, view, revoke)
- **Wallet** -- agentic wallet status and transaction history
- **Security** -- PID tree monitoring, blocked commands log

### 2. Install the awal Wrapper (macOS)

The wrapper intercepts `awal` calls and blocks them when they come from Cursor:

```bash
# Add the wrapper directory to the front of your PATH
export PATH="$(pwd)/watchdog/awal-wrapper:$PATH"

# Verify (should show the wrapper path first)
which awal
```

When Cursor tries to run `awal`, the wrapper:
1. Walks the process tree to find Cursor as an ancestor
2. Blocks the call and reports to the Pulse dashboard
3. Returns a clear error telling Cursor to use the Pulse delegation skill instead

### 3. (Optional) Start Watchdog Rust Daemon (Linux only)

```bash
cd watchdog
cargo xtask build-ebpf
cargo build --release
sudo ./target/release/watchdog   # Runs on :3000
```

On macOS, the awal wrapper provides blocking. The Rust daemon adds eBPF-level enforcement on Linux.

---

## Demo Flow (~3 minutes)

### 0:00--0:30 -- Intro & Dashboard
> "This is our Agent Control Plane. It monitors what AI agents do on your machine
> and controls how they spend your money."
>
> Show dashboard: empty activity, wallet with balance.

### 0:30--1:00 -- The Problem
> "I'm going to ask Cursor to fetch data from a paid API."
>
> In Cursor, ask: "Fetch the latest joke from demo-x402.vercel.app using x402."
>
> Cursor tries `awal` -> **BLOCKED**.
> Dashboard shows: "BLOCKED: Cursor attempted awal"
>
> "The AI agent tried to pay directly, but Watchdog caught it."

### 1:00--1:45 -- The Solution
> "Now I'll grant it scoped access -- a controlled, time-limited permission."
>
> Click [Grant Access] on the blocked event -> grant editor opens (pre-filled).
> Set: domain `demo-x402.vercel.app`, budget $1 USDC, TTL 5 min.
> Approve.
>
> Cursor retries via Pulse skill -> payment goes through -> joke returned.
> Dashboard shows: "PAID: $0.001 to demo-x402.vercel.app"

### 1:45--2:30 -- Autonomy Within Scope
> "The agent can now make more calls within the approved scope."
>
> Ask Cursor: "Get me 3 more jokes."
> Cursor makes 3 calls -> all succeed -> dashboard shows payments.
>
> "Budget, time limits, and domain restrictions are all enforced automatically."

### 2:30--3:00 -- Wrap-up
> Show Scoped Access tab: grant with spend counter.
> Show Wallet tab: transactions with tx hashes.
> Show Security tab: PID tree, blocked commands log.
>
> "The agent is autonomous within scope, but can never exceed budget, access other APIs,
> or bypass the control plane. Every action is audited."

---

## Environment Variables

### Pulse (`pulse/local-portal/.env`)

| Variable | Description |
|----------|-------------|
| `PORT` | Portal port (default: 4020) |
| `LOCAL_PORTAL_SHARED_SECRET` | **Required.** Secret for HMAC auth |
| `PUBLIC_BASE_URL` | For remote access (e.g. `http://YOUR_IP:4020`) |

### awal Wrapper

| Variable | Description |
|----------|-------------|
| `PULSE_URL` | Pulse API base URL (default: `http://localhost:4020`) |
| `REAL_AWAL` | Absolute path to real awal binary (auto-detected if unset) |

---

## Repository layout

This repo is the main **agent_watchdog** project. It uses two submodules:

| Path     | Submodule repo |
|----------|----------------|
| `pulse/` | [not-so-fat/agent-pulse](https://github.com/not-so-fat/agent-pulse) |
| `watchdog/` | [isabellakqq/Agent-WatchDog](https://github.com/isabellakqq/Agent-WatchDog) |

Clone with submodules:

```bash
git clone --recurse-submodules https://github.com/not-so-fat/agent_watchdog.git
```

Or if you already cloned:

```bash
git submodule update --init --recursive
```

---

## Architecture

| Component | Role | Port |
|-----------|------|------|
| **Pulse** | Scoped access, policy engine, x402 payments, unified dashboard | 4020 |
| **Watchdog-Lite** | PID tracking + command blocking events (built into Pulse for macOS) | -- |
| **awal wrapper** | PATH-level interception of `awal` from Cursor process tree | -- |
| **Watchdog (Rust)** | eBPF-based enforcement (Linux only, optional) | 3000 |

### Key APIs

| Endpoint | Description |
|----------|-------------|
| `POST /api/watchdog/register-pid` | Register a PID set (cursor/pulse) |
| `GET /api/watchdog/pid-sets` | View registered PIDs and process trees |
| `POST /api/watchdog/events` | Report a blocked/allowed command event |
| `GET /api/watchdog/events` | List watchdog events |
| `GET /api/watchdog/stats` | Watchdog statistics |
| `POST /api/watchdog/auto-detect-cursor` | Auto-detect and register Cursor PID |
| `POST /request-scoped-access` | Create a delegation grant request |
| `POST /execute` | Execute a paid x402 request through a grant |

---

## Troubleshooting

- **Cursor keeps trying `awal` directly:** Make sure the wrapper is first in PATH (`which awal` should show `watchdog/awal-wrapper/awal`). The wrapper error message tells Cursor to use the Pulse skill.
- **Wrapper doesn't block:** Verify Cursor process name detection: `ps aux | grep -i cursor`.
- **Dashboard empty:** Pulse needs to be running. Check `http://localhost:4020/health`.
- **Wallet not authenticated:** Run `npx awal@latest status` in a terminal and sign in.
- **Grant approval fails:** Open the dashboard via `localhost` (not `127.0.0.1`) for WebAuthn passkey support.
