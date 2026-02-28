# Agent Control Plane — Hackathon Spec (Draft)

## Goal
Enable safe autonomy for coding agents by enforcing a **deny-by-default firewall** and allowing users to grant **time-bounded, scoped permissions** (“Scoped Access”) with a clear audit trail.

## Components
### 1) Firewall Service (Enforcement)
**Responsibility:** deterministic runtime enforcement for agent actions.
- Intercepts/monitors actions (e.g., CLI commands, file access, network requests)
- Evaluates policies + current active Scoped Access grants
- **Default:** block + alert when action is not permitted
- Records every decision (blocked/allowed) to the Audit store

**Primary outputs**
- `ALLOW | BLOCK | PAUSE/REVIEW` decision (keep MVP to ALLOW/BLOCK)
- Audit events: `{timestamp, agent_id, process_id, action_type, target, risk, decision, reason, grant_id?}`

### 2) Scoped Access Service (Authorization / Grants)
**Responsibility:** issue and manage temporary permissions that expand what the Firewall allows.
- Receives a request from agent (“I need permission to do X within scope Y”)
- Presents an approval UI to the user (human-in-the-loop)
- If approved, creates an **active grant** with TTL + scope constraints
- Notifies Firewall Service of new/updated/revoked grants (push or pull)
- Records grant lifecycle events to Audit store

**Core concept: Scoped Access Grant**
A grant is a structured permission with explicit limits:
- **TTL:** expires automatically
- **Scope constraints:** e.g. allowed commands, allowed file paths, allowed domains
- Optional quotas: max spend, max calls, max frequency

Example:
```json
{
  "grant_id": "g_123",
  "agent_id": "a_1",
  "ttl_seconds": 600,
  "scope": {
    "commands_allow": ["git status", "git diff", "cat .env"],
    "paths_allow": ["~/repo/**"],
    "domains_allow": ["github.com"]
  },
  "created_by": "user",
  "created_at": "2026-02-27T..."
}
```

### 3) Dashboard Service (Control + Visibility)
**Responsibility:** single UI for:
- real-time alerts
- approvals
- permissions management
- audit review
- policy configuration

The dashboard reads from the Audit store and the current state of Grants/Policies.

## Runtime Flows
### A) Default Enforcement (no extra permission)
1. Agent attempts an action (CLI/file/network).
2. Firewall evaluates against static policy + active grants.
3. If not permitted → **BLOCK** + create Alert event.
4. Dashboard shows alert in real time.

### B) Scoped Access Request (temporary permission)
1. Agent calls a skill/command that sends a **grant request** to Scoped Access Service.
2. Scoped Access Service shows **Approval UI** to user:
   - Summary of intended action(s)
   - Proposed scope + TTL (editable)
3. User approves/denies.
4. If approved:
   - Grant is created and becomes active
   - Firewall learns the grant (push notify or periodic pull)
   - Dashboard updates “Active Permissions”
5. Agent retries action; Firewall allows if within scope and TTL.

## UI Information Architecture (Recommended)
### Tab 1: **Agent Activity** (default)
- Current agent(s), current task
- Live alerts + blocked attempts
- Primary CTA when blocked:
  - **Approve Once**
  - **Approve with Scope** (opens grant editor)

### Tab 2: **Permissions** (Scoped Access)
- Active grants (with countdown/expiry)
- Past grants
- CTAs: **Revoke**, **Extend**, **Create new grant**

### Tab 3: **Audit Log**
- All events: blocked, allowed, approvals, revocations
- Filters: agent, risk, action type, time

### Tab 4: **Policies**
- Sensitive files
- Forbidden commands
- Allowed domains/tools
- Default risk thresholds (optional for MVP)

*(Optional later)* Tab 5: **Resources**
- Wallet / API quotas / external integrations (not MVP)

## Authentication / Security (MVP-friendly)
For a hackathon MVP, keep it simple but safe:

### Dashboard (User permissions require auth)
- **Require login** to approve grants and edit policies.
- Simplest: single local user with session cookie.
- If running on EC2 for demo: protect dashboard behind:
  - basic auth OR
  - an SSH tunnel / VPN (Tailscale) OR
  - allowlist your IP during demo

### Agent → Scoped Access
- Use a shared secret (HMAC) between agent CLI wrapper and Scoped Access API.
- Only accept requests signed by that secret.

### Scoped Access → Firewall
- Use internal network only (localhost / docker network) OR mTLS later.
- MVP: shared secret or same-host call.

## User Flow (Concept)

- 1. User creates an account (to identify user)
  - email
  - passkey registration
- 2. User registers an agent
  - install watchdog & pulse on the same computer as agent
- 3. User can monitor processes from agent
  - UI shows processes by agent, and scores risk
- 4. User can configure risk configuration on UI
  - what to prohibit
- 5. Agent acts autonomously
  - if it is risky, automatically blocked
- 6. Agent can use skills to ask approval
  - pop-up browser to ask for approval
- 7. User can approve or deny
  - define more details: one-time / limited time, budget, target files etc.
- 8. Once agent get scoped access, it can act autonomously 


## Data / State
Minimum persistent store (SQLite is fine):
- `grants` (active/past)
- `events` (audit log)
- `policies` (config)

Real-time updates:
- simplest: dashboard polls every 1–2s
- nicer: WebSocket / SSE

## Minimal API Sketch
### Scoped Access Service
- `POST /grant/request` (agent) → returns `pending_id`
- `POST /grant/{pending_id}/approve` (user) → returns `grant_id`
- `POST /grant/{pending_id}/deny` (user)
- `GET /grants` (dashboard)
- `POST /grant/{grant_id}/revoke` (dashboard)

### Firewall Service
- `POST /enforce` (called by wrapper/proxy OR internal hooks) → `{decision, reason, grant_id?}`
- `POST /grants/sync` (optional push)
- `GET /health`

### Dashboard Service
- `GET /events`
- `GET /alerts`
- `GET /policies` / `POST /policies`


## Demo Scenario (Hackathon)
1. Agent tries `cat .env` → blocked → alert appears.
2. Agent requests Scoped Access (TTL 5 min, allow `cat .env` in repo path).
3. User approves in dashboard.
4. Agent retries → allowed.
5. Audit log shows: blocked → approved grant → allowed execution.

## Open Questions (Decide quickly)
- What exactly is “action” for V1: CLI only, or CLI + file open?
- How does Firewall identify “agent-controlled process” (PID allowlist, wrapper-only, or tag)?
- Do we need PAUSE/REVIEW mode or just BLOCK for V1?
