# Agent Watchdog -- Hackathon Demo

An **Agent Watchdog** that monitors what AI agents do on your machine and controls how they spend your money. **Watchdog** is an eBPF-based runtime that can block or allow processes (e.g. which PIDs may execute payment CLIs). **Pulse** provides scoped access (grants), policy, and x402 payment; the user approves grants via the dashboard. The demo uses **Cursor as the AI agent**: Cursor is not allowed to run `awal` directly; it must go through Pulse.

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
|  (eBPF)    |                          |  (Node.js :4020)  |
|            |                          |                   |
|  Enforce   |                          |  Scoped Access    |
|  which PIDs|                          |  Policy engine    |
|  may run   |                          |  x402 engine      |
|  awal      |                          |  Dashboard        |
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

### 2. Watchdog (enforcement)

**Linux:** Watchdog is an eBPF-based daemon that enforces which processes may run the payment CLI. Build and run:

```bash
cd watchdog
cargo xtask build-ebpf
cargo build --release
sudo ./target/release/watchdog   # Runs on :3000
```

**macOS (demo only):** eBPF is not available. For the hackathon demo we include a small PATH hook under `watchdog/awal-wrapper/` that blocks direct `awal` and reports to Pulse; it is not the production enforcement mechanism.

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
> Cursor tries `awal` -> **BLOCKED** (by Watchdog / enforcement layer).
> Dashboard shows the blocked attempt.
>
> "The AI agent tried to pay directly; Watchdog blocks that."

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

**One-time (maintainers):** To push pulse content to agent-pulse and switch this repo to submodules:

```bash
# 1. Push pulse to agent-pulse (from this repo; needs push access to agent-pulse)
git remote add agent-pulse https://github.com/not-so-fat/agent-pulse.git
git push agent-pulse pulse-standalone:main

# 2. Replace pulse and watchdog with submodule checkouts
git rm -r --cached pulse
mv pulse pulse.bak && git submodule add https://github.com/not-so-fat/agent-pulse.git pulse
mv watchdog watchdog.bak && git submodule add https://github.com/isabellakqq/Agent-WatchDog.git watchdog
git add .gitmodules pulse watchdog && git commit -m "Use pulse and watchdog as submodules"
```

---

## Architecture

| Component | Role | Port |
|-----------|------|------|
| **Watchdog** | eBPF-based enforcement: which PIDs may run payment CLI (Linux). See [Agent-WatchDog](https://github.com/isabellakqq/Agent-WatchDog). | 3000 |
| **Pulse** | Scoped access (grants), policy engine, x402 payments, unified dashboard | 4020 |
| **Watchdog-Lite** | PID tracking + event log in Pulse (macOS demo; no eBPF) | -- |
| **awal-wrapper** | macOS demo only: PATH hook to show blocking when eBPF is not available | -- |

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

- **Blocking not working (macOS demo):** Ensure the PATH hook is first: `export PATH="$(pwd)/watchdog/awal-wrapper:$PATH"`. On Linux, run the eBPF Watchdog daemon.
- **Dashboard empty:** Pulse must be running. Check `http://localhost:4020/health`.
- **Wallet not authenticated:** Run `npx awal@latest status` in a terminal and sign in.
- **Grant approval fails:** Use the dashboard at `localhost` (not `127.0.0.1`) for WebAuthn.
