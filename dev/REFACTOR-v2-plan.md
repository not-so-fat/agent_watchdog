# Refactor Plan v2 — "Cursor Pays" Scenario

## 1. Summary of Change

We are pivoting from a **custom autonomous agent** scenario to a **Cursor-as-the-agent** scenario where the demo is:

> A Cursor AI agent needs to make a paid API call. Watchdog blocks Cursor from running `awal` directly. The user grants scoped access through Pulse, and Pulse handles the payment on behalf of Cursor — autonomously within the approved scope.

### What stays
- Watchdog (runtime monitor)
- Pulse (scoped access + payment gateway)
- Coinbase Agentic Wallet (`awal`) integration
- x402 payment protocol
- Passkey-based user approval
- Dashboard for visibility and control

### What goes away
- `agent/` directory (custom Mastra agent) — Cursor IS the agent now
- eBPF file-access blocking (keep observation for future, but not the demo story)
- Firewall proxy (`/v1/intercept`) as the primary enforcement surface
- Tavily, Neo4j, Reka sponsor tool integrations

### What's new
- **Command-level blocking**: Watchdog intercepts `awal` CLI execution from Cursor
- **PID-aware enforcement**: Watchdog knows which PIDs are Cursor vs. Pulse, and allows Pulse to run `awal` while blocking Cursor
- **Simplified demo flow**: Cursor tries to pay → blocked → user grants scoped access via Pulse → Pulse pays on behalf → Cursor gets result
- **Updated dashboards**: unified view showing blocked attempts, scoped access grants, and payment history

---

## 2. New Scenario: Cursor Pays via x402

### Story (Demo)

1. User is working in Cursor. The Cursor agent needs data from a paid API (x402-protected).
2. Cursor attempts to run `awal` (or an `npx awal` variant) to pay — **Watchdog blocks it**.
3. Cursor (via a skill/tool) calls Pulse to request scoped access: "I need to call `https://api.example.com/data`, budget 1 USDC, for 10 minutes."
4. User sees the request in Pulse dashboard (or browser popup), reviews the scope, and **approves with passkey**.
5. Pulse now autonomously handles the x402 payment on Cursor's behalf — calls `awal` internally (Watchdog allows this because Pulse's PID is whitelisted).
6. Cursor receives the API response. The payment, scope, and audit trail are all visible in the dashboard.

### Why This Is Better

- **Real-world scenario**: Developers using Cursor is a real use case, not a contrived custom agent.
- **No custom agent code needed**: Cursor is already the agent; we just need skills and the control plane.
- **Cleaner security story**: "Your IDE's AI can't spend your money without your approval" is immediately understandable.
- **Simpler demo**: fewer moving parts, more focused narrative.

---

## 3. Architecture (v2)

```
┌──────────────────────────────────────────────────────────────┐
│  User (browser)                                              │
│  • Pulse Dashboard: scoped access, wallet, transactions      │
│  • Watchdog Dashboard: blocked commands, observations         │
│  • Approval UI: passkey-authenticated grant approval          │
└──────────┬───────────────────────────────────────────────────┘
           │
┌──────────▼───────────────────────────────────────────────────┐
│  Local Machine                                               │
│                                                              │
│  ┌─────────────────┐     ┌──────────────────────────┐       │
│  │  Watchdog        │     │  Pulse (Local Portal)    │       │
│  │  (Rust daemon)   │     │  (Node.js :4020)         │       │
│  │                  │     │                          │       │
│  │  • Monitor all   │     │  • Scoped Access grants  │       │
│  │    processes      │     │  • Policy engine         │       │
│  │  • Block `awal`  │     │  • x402 engine           │       │
│  │    from Cursor   │     │  • Calls `awal` internally│      │
│  │  • Allow `awal`  │     │  • Dashboard + approval   │       │
│  │    from Pulse    │     │  • Audit log              │       │
│  │  • PID tracking  │     │                          │       │
│  └──────┬───────────┘     └──────────┬───────────────┘       │
│         │ monitors                   │ calls                  │
│         ▼                            ▼                        │
│  ┌──────────────┐            ┌──────────────┐                │
│  │  Cursor      │            │  awal CLI    │                │
│  │  (AI Agent)  │──blocked──▶│  (wallet)    │                │
│  │              │            │              │                │
│  │  Uses Pulse  │──allowed──▶│  via Pulse   │                │
│  │  skill to pay│            │  (whitelisted)│               │
│  └──────────────┘            └──────────────┘                │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼  x402 payment
                     ┌─────────────────┐
                     │  Paid API       │
                     │  (x402-enabled) │
                     └─────────────────┘
```

---

## 4. PID Management (Key Technical Change)

### Problem

Watchdog needs to distinguish between:
- **Cursor** (and its child processes) running `awal` → **BLOCK**
- **Pulse** running `awal` → **ALLOW**

### Design

#### 4.1 PID Registration

When Watchdog starts, it needs to know the PIDs of:
1. **Cursor** — the process to monitor/block
2. **Pulse** — the process to whitelist

Options for PID discovery:
- **Option A: Manual registration** — User provides PIDs via config or API call at startup (`POST /api/register-pid { name: "cursor", pid: 12345 }`).
- **Option B: Process-name matching** — Watchdog scans for process names matching patterns (e.g., `Cursor`, `cursor`, `Electron` for Cursor; `node` with cwd matching pulse path for Pulse).
- **Option C: Startup integration** — Pulse and a Cursor wrapper script register themselves with Watchdog on startup.

**Recommendation: Option A (manual) for MVP + Option B (name matching) for convenience.** Allow both: API registration overrides auto-detection.

#### 4.2 Child Process Tracking

Cursor spawns child processes (shell, node, python, etc.) that could also try to run `awal`. Watchdog must track the **process tree**:

- When a monitored PID (Cursor) spawns a child, that child inherits the "Cursor" classification.
- Implementation approaches:
  - **eBPF `sched_process_fork` tracepoint**: Capture `fork()`/`clone()` to build parent→child mapping. When a new process is created, check if its parent is in the Cursor PID set; if so, add the child.
  - **Polling `/proc`**: Periodically scan `/proc/*/stat` to build the process tree. Less real-time but simpler.
  - **macOS**: Use `proc_listchildpids()` or `sysctl` for process tree. (Note: eBPF is Linux-only; macOS needs a different approach — see §4.5.)

**Recommendation**: eBPF `sched_process_fork` on Linux. For macOS demo, use polling or `dtrace`/`EndpointSecurity` framework.

#### 4.3 Command Interception

When any process in the Cursor tree attempts to `exec` a binary matching `awal` (or `npx` with `awal` args):

- **Linux**: eBPF tracepoint on `sys_enter_execve` — inspect the filename and argv. If the process is in the Cursor PID set and the command matches `awal`, **block** (return -EPERM or kill the process).
- **macOS**: EndpointSecurity framework `ES_EVENT_TYPE_AUTH_EXEC` — same logic, can deny the exec.

#### 4.4 Decision Flow

```
Process X calls execve("awal", ...)
  │
  ├─ Is X (or any ancestor) in Cursor PID set?
  │    ├─ YES → BLOCK + alert to dashboard
  │    └─ NO  → continue
  │
  ├─ Is X (or any ancestor) in Pulse PID set?
  │    ├─ YES → ALLOW (whitelisted)
  │    └─ NO  → (default policy: allow or alert-only)
  │
  └─ Unknown process → configurable: allow/alert/block
```

#### 4.5 macOS Considerations

The current Watchdog is Linux+eBPF. For the hackathon demo (likely on macOS):

- **Option A: EndpointSecurity framework** (macOS native) — Requires entitlement from Apple (takes time) or disabling SIP for dev.
- **Option B: `ptrace`-based** — Attach to Cursor's child processes and intercept `exec`. Limited and fragile.
- **Option C: PATH manipulation** — Place a wrapper script named `awal` earlier in `$PATH` that checks the calling process and either blocks or forwards to the real `awal`. Simple but bypassable.
- **Option D: Launchd/filesystem permissions** — Make the real `awal` binary only executable by Pulse's user/group.

**Recommendation for hackathon: Option C (PATH wrapper)** as the simplest demo-ready approach. The wrapper script:
1. Checks its parent PID chain.
2. If any ancestor is Cursor → deny and report to Watchdog API.
3. If ancestor is Pulse (or manual invocation) → forward to real `awal`.

This can be combined with the Watchdog daemon for alerting/dashboard even without kernel-level blocking.

---

## 5. Component Changes

### 5.1 Watchdog — Changes Required

| Area | Current | New |
|------|---------|-----|
| **Primary enforcement** | eBPF `sys_enter_openat` (file opens) | eBPF `sys_enter_execve` (command exec) or PATH wrapper |
| **What's blocked** | Sensitive file reads | `awal` command from Cursor PIDs |
| **PID awareness** | None (monitors all) | PID set management: Cursor (block), Pulse (allow) |
| **Child process tracking** | None | Process tree tracking (fork/clone) |
| **File monitoring** | Active blocking | **Observation-only** (keep for future, demote from primary) |
| **Dashboard data** | File access alerts | Blocked command attempts + process observations |
| **API** | `/api/events`, `/api/alerts`, `/api/stats` | Add: `/api/register-pid`, `/api/pid-sets`, update event types |

**New Watchdog API additions:**

```
POST /api/register-pid
  { "name": "cursor" | "pulse", "pid": 12345 }
  → Registers a root PID for tracking

GET /api/pid-sets
  → Returns current tracked PID sets and their process trees

DELETE /api/register-pid/:name
  → Removes a PID set

GET /api/events  (updated)
  → Events now include type: "command_blocked" | "file_observed" | "process_spawned"
  → Each event includes: source_pid_set ("cursor" | "pulse" | "unknown")
```

### 5.2 Pulse — Changes Required

| Area | Current | New |
|------|---------|-----|
| **Core functionality** | Scoped Access + x402 payments | Same (no major changes) |
| **Agent integration** | Generic agent via HMAC | Cursor via skill (same protocol) |
| **Dashboard** | Wallet + grants + transactions | Add: Watchdog integration panel, unified view |
| **Startup** | Manual | Auto-register PID with Watchdog on startup |

**Pulse changes:**

1. **Startup PID registration**: On boot, Pulse calls Watchdog `POST /api/register-pid { name: "pulse", pid: process.pid }` to whitelist itself.
2. **Dashboard updates** (see §6).
3. **Cursor skill updates**: Update skill docs to reflect the new scenario (Cursor is the agent, not a custom Mastra agent).

### 5.3 Agent Directory — Removal

The `agent/` directory (Mastra-based custom agent) is no longer needed. Cursor IS the agent.

- **Action**: Archive or remove `agent/` directory.
- **Replacement**: Cursor skills (`.cursor/skills/`) that teach Cursor how to interact with Pulse.

### 5.4 Cursor Skills — New/Updated

Skills that Cursor needs:

| Skill | Purpose |
|-------|---------|
| `agent-pulse-delegation` | Request scoped access (existing, update for new scenario) |
| `agent-pulse-x402` | Make paid API requests through Pulse (existing, minor updates) |
| `agent-pulse-wallet-status` | Check wallet auth status (existing, keep as-is) |
| `agent-pulse-debug-codebase` | This is the demo scenario |

The key change in skills: remove references to "the agent" as a separate process; instead, instructions are for Cursor itself.

---

## 6. Dashboard Design (v2)

### 6.1 Unified Dashboard Concept

Instead of separate Watchdog and Pulse dashboards, create a **unified dashboard** served from Pulse (since it already has the richer UI).

**Tabs / Sections:**

#### Tab 1: Activity (default)
Shows what's happening right now.

```
┌─────────────────────────────────────────────────────────────┐
│  🔴 BLOCKED: Cursor (PID 4521) attempted `npx awal pay`   │
│     3 seconds ago                                           │
│     [Grant Access]  [Dismiss]                               │
├─────────────────────────────────────────────────────────────┤
│  ✅ PAID: api.example.com/data — 0.50 USDC                │
│     via Scoped Access grant g_abc (expires in 8:32)         │
│     12 seconds ago                                          │
├─────────────────────────────────────────────────────────────┤
│  ⚠️  OBSERVED: Cursor opened ~/.ssh/id_rsa (read-only)     │
│     45 seconds ago                                          │
│     [This is observation-only, no action needed]            │
└─────────────────────────────────────────────────────────────┘
```

- **Blocked attempts** (from Watchdog): Shows `awal` commands blocked from Cursor, with a CTA to grant scoped access.
- **Payments** (from Pulse): Shows successful/failed x402 payments made through Pulse.
- **Observations** (from Watchdog): File access observations (non-blocking, informational).

#### Tab 2: Scoped Access
Manage grants (existing Pulse UI, refined).

```
┌─────────────────────────────────────────────────────────────┐
│  Active Grants                                              │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Grant g_abc                                           │  │
│  │ Domains: api.example.com                              │  │
│  │ Budget: 0.50 / 5.00 USDC   TTL: 8:32 remaining      │  │
│  │ Created: 2 min ago          [Revoke]                  │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  Past Grants (collapsed)                                    │
│  ▶ 3 expired grants                                        │
└─────────────────────────────────────────────────────────────┘
```

#### Tab 3: Wallet
Wallet info and transaction history (existing Pulse UI, keep as-is).

```
┌─────────────────────────────────────────────────────────────┐
│  Wallet                                                     │
│  Address: 0x1234...5678  [Copy]                             │
│  USDC: $12.50  |  ETH: 0.003  |  WETH: 0.00               │
│                                              [Refresh]      │
├─────────────────────────────────────────────────────────────┤
│  Transaction History                                        │
│  Time       | Domain              | Amount | Status | TX    │
│  2:30 PM    | api.example.com     | $0.50  | ✅     | 0x... │
│  2:28 PM    | api.example.com     | $0.50  | ❌     | —     │
└─────────────────────────────────────────────────────────────┘
```

#### Tab 4: Security (Watchdog)
Process monitoring and configuration.

```
┌─────────────────────────────────────────────────────────────┐
│  Monitored Processes                                        │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Cursor (PID 4521)              Status: Monitored      │  │
│  │   └─ Child: node (PID 4530)                          │  │
│  │   └─ Child: zsh (PID 4535)                           │  │
│  │   └─ Child: python3 (PID 4540)                       │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Pulse (PID 3200)              Status: Whitelisted     │  │
│  │   └─ Child: node (PID 3205)                          │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  Blocked Commands (last 24h): 5                             │
│  Observed File Accesses (last 24h): 142                     │
│                                                             │
│  Configuration                                              │
│  Blocked commands: [awal, npx awal]                         │
│  Observed keywords: [.env, id_rsa, credentials, ...]        │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 User Flow: "Blocked → Grant → Pay"

This is the core demo flow and should be seamless:

```
Step 1: Cursor tries `awal` → Watchdog blocks
         Dashboard shows: "🔴 BLOCKED: Cursor attempted awal"
         CTA: [Grant Access]
                    │
Step 2: User clicks [Grant Access]
         → Opens grant editor (pre-filled from blocked request context)
         → User sets: domains, budget, TTL
         → User approves with passkey
                    │
Step 3: Grant is active
         → Cursor retries via Pulse skill (POST /request-scoped-access)
         → Already approved → gets session_handle
         → Cursor calls POST /execute with session_handle
         → Pulse runs awal internally → payment succeeds
         → Dashboard shows: "✅ PAID: 0.50 USDC to api.example.com"
                    │
Step 4: Audit trail visible
         → Activity tab shows full sequence: blocked → granted → paid
         → Scoped Access tab shows active grant with spend tracking
         → Wallet tab shows transaction
```

### 6.3 Alternative Quick Flow: "Skill-first"

For the case where Cursor is smart enough to NOT try `awal` directly:

```
Step 1: Cursor calls Pulse skill (POST /request-scoped-access)
         → Dashboard shows: "⏳ PENDING: Cursor requests access to api.example.com"
                    │
Step 2: User approves in browser (passkey)
         → Grant active
                    │
Step 3: Cursor calls POST /execute → payment handled → response returned
         → Dashboard shows: "✅ PAID: 0.50 USDC to api.example.com"
```

---

## 7. Demo Script (v2, ~3 minutes)

### Setup (before demo)
- Watchdog running, Pulse running, Cursor open
- Wallet authenticated with USDC balance
- Dashboard open in browser tab

### Demo

**0:00–0:30 — Intro & Dashboard**
> "This is our Agent Control Plane. It monitors what AI agents do on your machine and controls how they spend your money. Let me show you."
>
> Show dashboard: empty activity, wallet with balance.

**0:30–1:00 — The Problem**
> "I'm going to ask Cursor to fetch data from a paid API."
>
> In Cursor, ask: "Fetch the latest joke from nickeljoke.vercel.app using the x402 payment protocol."
>
> Cursor tries to run `awal` → **BLOCKED**.
> Dashboard lights up: "Cursor attempted to run awal — blocked."
>
> "See? The AI agent tried to pay directly, but Watchdog caught it. No money left my wallet."

**1:00–1:45 — The Solution**
> "Now I'll grant it scoped access — a controlled, time-limited permission."
>
> Click [Grant Access] on the blocked event → grant editor opens.
> Set: domain `nickeljoke.vercel.app`, budget $1 USDC, TTL 5 min.
> Approve with passkey (Touch ID).
>
> "Now the agent has a narrow permission. Let me retry."
>
> Cursor retries via Pulse skill → payment goes through → joke response returned.
> Dashboard shows: "✅ PAID: $0.001 to nickeljoke.vercel.app"

**1:45–2:30 — Autonomy Within Scope**
> "The agent can now make more calls within the approved scope — no more approvals needed."
>
> Ask Cursor: "Get me 3 more jokes."
> Cursor makes 3 more calls → all succeed → dashboard shows payments ticking up.
>
> "Each payment is tracked. Budget, time limits, and domain restrictions are all enforced automatically."

**2:30–3:00 — Wrap-up**
> Show Scoped Access tab: grant with spend counter.
> Show Wallet tab: transactions with tx hashes.
> Show Security tab: PID tree, blocked commands log.
>
> "The agent is autonomous within the scope I approved, but it can never exceed my budget, access other APIs, or bypass the control plane. Every action is audited."

---

## 8. Implementation Plan

### Phase 1: Watchdog — PID + Command Blocking (Priority: HIGH)

| Task | Description | Effort |
|------|-------------|--------|
| 1.1 PID registration API | `POST /api/register-pid`, `GET /api/pid-sets`, `DELETE /api/register-pid/:name` | 2–3h |
| 1.2 Process tree tracking | Track child processes of registered PIDs (polling `/proc` or eBPF fork tracing) | 3–4h |
| 1.3 Command interception | Detect `awal` execution; block if from Cursor PID set (eBPF `execve` or PATH wrapper) | 3–4h |
| 1.4 Updated event model | New event types: `command_blocked`, `file_observed`, `process_spawned`; include `source_pid_set` | 2h |
| 1.5 Dashboard API updates | Serve new event types and PID info to frontend | 1–2h |
| 1.6 macOS PATH wrapper | Fallback for macOS: wrapper script that checks parent PID chain | 2–3h |

### Phase 2: Pulse — Cursor Integration (Priority: HIGH)

| Task | Description | Effort |
|------|-------------|--------|
| 2.1 Auto-register with Watchdog | On startup, call `POST /api/register-pid` with own PID | 1h |
| 2.2 Update Cursor skills | Rewrite skill docs for Cursor-as-agent scenario | 2h |
| 2.3 "Grant from blocked event" flow | When dashboard shows a blocked event, provide a CTA that pre-fills grant request | 2–3h |
| 2.4 Watchdog data proxy | Pulse dashboard fetches Watchdog data (`GET /api/events`, `/api/pid-sets`) to show in unified UI | 2h |

### Phase 3: Unified Dashboard (Priority: MEDIUM)

| Task | Description | Effort |
|------|-------------|--------|
| 3.1 Activity tab | Merge Watchdog events + Pulse payments into unified timeline | 3–4h |
| 3.2 Security tab | PID tree visualization, blocked commands log, config | 2–3h |
| 3.3 "Blocked → Grant" flow | CTA on blocked events that opens grant editor pre-filled | 2–3h |
| 3.4 Refine Scoped Access tab | Polish existing UI for new scenario | 1–2h |
| 3.5 Refine Wallet tab | Keep mostly as-is, minor polish | 1h |

### Phase 4: Cleanup & Demo Polish (Priority: LOW)

| Task | Description | Effort |
|------|-------------|--------|
| 4.1 Remove/archive `agent/` | Remove custom agent code; keep as archived reference | 1h |
| 4.2 Update root README | New project overview reflecting v2 scenario | 1h |
| 4.3 Update `dev/` docs | Archive old specs, update `agent-control-spec.md` | 1h |
| 4.4 Demo rehearsal | End-to-end test of the 3-minute demo | 2h |

**Total estimated effort: ~35–45 hours**

---

## 9. Open Questions / Decisions Needed

| # | Question | Options | Recommendation |
|---|----------|---------|----------------|
| 1 | **macOS vs Linux for demo?** | (a) Linux VM with eBPF, (b) macOS with PATH wrapper, (c) macOS with EndpointSecurity | (b) macOS PATH wrapper for hackathon simplicity |
| 2 | **How does Cursor discover Watchdog blocked it?** | (a) Cursor skill polls Watchdog API, (b) the `awal` wrapper returns error message that Cursor reads, (c) user tells Cursor | (b) Wrapper returns clear error → Cursor reads it and uses Pulse skill instead |
| 3 | **Unified dashboard or two dashboards?** | (a) Single dashboard in Pulse, (b) Keep separate dashboards | (a) Single dashboard — simpler for demo, Pulse proxies Watchdog data |
| 4 | **What happens to the Watchdog React dashboard?** | (a) Replace entirely, (b) Keep as secondary/admin view, (c) Merge components into Pulse | (c) Merge the useful parts (Security tab) into Pulse dashboard |
| 5 | **Should Pulse auto-detect Cursor PID?** | (a) User provides, (b) Pulse scans for Cursor process, (c) Cursor skill registers itself | (a) for MVP; (b) as a convenience feature |
| 6 | **File observation: still show in dashboard?** | (a) Yes, as "Observations" in Activity tab, (b) No, remove for now | (a) Keep as low-priority observations — shows the system is watching, adds depth to demo |

---

## 10. Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| macOS blocking is unreliable (PATH wrapper bypass) | Demo fails if Cursor finds real `awal` | Medium | Ensure wrapper is first in PATH; demo script doesn't try to bypass |
| Cursor doesn't consistently use skills | Agent ignores Pulse skill, keeps trying `awal` | Medium | Make the wrapper error message very clear; add explicit instruction in Cursor rules |
| PID tree tracking misses child processes | Cursor child process runs `awal` undetected | Low | Conservative matching: block `awal` from ANY unknown process, only allow from Pulse PID set |
| Dashboard integration takes too long | Separate dashboards for demo | Medium | Fallback: keep two browser tabs (Pulse + Watchdog) instead of unified |
| eBPF `execve` blocking is too complex for timeline | Can't do kernel-level blocking | Medium | PATH wrapper is the fallback and works for the demo |

---

## 11. File / Directory Impact

```
aa_hackathon/
├── watchdog/                    # MAJOR CHANGES
│   ├── agent-watchdog/src/
│   │   ├── main.rs              # Add PID tracking, execve tracing
│   │   ├── api.rs               # Add PID registration endpoints
│   │   ├── pid_manager.rs       # NEW: PID set management + tree tracking
│   │   ├── command_monitor.rs   # NEW: execve interception logic
│   │   ├── event_store.rs       # Update event types
│   │   └── ...
│   ├── agent-watchdog-ebpf/src/
│   │   └── main.rs              # Add sys_enter_execve tracepoint (Linux)
│   ├── awal-wrapper/            # NEW: macOS PATH wrapper script
│   │   └── awal                 # Wrapper that checks parent PID
│   └── dashboard/               # May be deprecated (merge into Pulse)
│
├── pulse/                       # MODERATE CHANGES
│   ├── local-portal/src/
│   │   ├── server.ts            # Add Watchdog proxy endpoints, PID registration on startup
│   │   └── ...                  # Minor updates to existing code
│   ├── .cursor/skills/          # UPDATE existing skills for Cursor scenario
│   └── dev/                     # Update design docs
│
├── agent/                       # REMOVE (archive)
│
├── dev/
│   ├── REFACTOR-v2-plan.md      # THIS DOCUMENT
│   ├── agent-control-spec.md    # Update for v2
│   └── watchdog-pulse-apis.md   # Update with new endpoints
│
└── README.md                    # Rewrite for v2 scenario
```

---

## 12. Success Criteria

- [ ] Watchdog can register PIDs and track process trees
- [ ] Watchdog blocks `awal` execution from Cursor's process tree
- [ ] Watchdog allows `awal` execution from Pulse's process tree
- [ ] Blocked events appear in the dashboard in real-time
- [ ] User can grant scoped access from a blocked event with one-click flow
- [ ] Pulse handles x402 payment autonomously after grant approval
- [ ] Unified dashboard shows: blocked attempts → grants → payments → audit trail
- [ ] 3-minute demo is clean and compelling
- [ ] Works on macOS (PATH wrapper approach) for hackathon presentation
