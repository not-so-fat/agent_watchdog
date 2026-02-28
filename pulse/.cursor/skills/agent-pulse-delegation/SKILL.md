---
name: agent-pulse-delegation
description: Create a scoped-access payment session (grant) for x402-protected APIs. Use when accessing a paid API, when you need a session_handle, or when the user says "access", "call", or "fetch" an x402 endpoint. IMPORTANT -- you CANNOT run `awal` directly; Watchdog will block it. You must delegate payment through Pulse.
---

# Scoped Access (Grants)

## Critical: Do NOT Run `awal` Directly

Watchdog monitors this machine and blocks any attempt by Cursor to run `awal` or `npx awal`.
If you try, you will get a "BLOCKED by Agent Watchdog" error. Instead, always use Pulse
to handle payments on your behalf by following this skill.

## Base URL

Use **`PULSE_BASE_URL`** env var if set, otherwise default to `http://127.0.0.1:4020`.

Key endpoints:
- `POST ${PULSE_BASE_URL}/request-scoped-access` -- create a grant request
- `GET ${PULSE_BASE_URL}/request-scoped-access/:request_id` -- poll for approval
- `GET ${PULSE_BASE_URL}/api/scoped-access?active_only=true` -- list active grants

## Before Creating a New Session

Check for an existing active Scoped Access session:

```
GET ${PULSE_BASE_URL}/api/scoped-access?active_only=true
```

If a grant with matching `allowed_apis` exists and `is_active` is true, reuse its `session_id`
as `session_handle`. Skip to the x402 skill.

## Creating a New Session

1. **Get the passphrase** -- Check env var `LOCAL_PORTAL_SHARED_SECRET`. If not set, ask the user once.

2. **Build the policy** with `allowed_apis`, `summary`, and `description`:
   - Each API entry: `domain`, `path`, `method`, and optionally `description`
   - Use glob patterns for paths (e.g., `/api/*/book/*`)
   - `summary`: Short title (~40 chars) shown on approval screen
   - `description`: Detailed explanation including what, why, and choices

   Example:
   ```json
   {
     "policy": {
       "allowed_domains": ["api.example.com"],
       "allowed_apis": [
         { "domain": "api.example.com", "path": "/data", "method": "GET", "description": "Fetch data" }
       ],
       "summary": "Fetch paid API data",
       "description": "Task: Retrieve data from api.example.com.\n\nWhy payment needed: Endpoint is x402-protected, costs ~$0.001 per request.\n\nCursor will call this API through Pulse after grant approval.",
       "max_total_spend": 1000000,
       "max_per_tx": 500000,
       "ttl_seconds": 600
     }
   }
   ```

   Policy fields:
   - `allowed_domains`: Array of domains (required)
   - `allowed_apis`: Array of `{ domain, path, method, description }`
   - `summary` / `description`: Human-readable context for the user
   - `max_total_spend` / `max_per_tx`: In USDC atomic units (1 USDC = 1000000 on Base). Use realistic estimates.
   - `ttl_seconds`: Grant duration in seconds

3. **Request scoped access:**
   ```
   POST ${PULSE_BASE_URL}/request-scoped-access
   Content-Type: application/json

   {
     "agent_id": "cursor",
     "policy": { ... }
   }
   ```

4. **Approval** -- Response returns `approval_url`. Open it in the user's browser so they can approve immediately:
   ```bash
   open "<approval_url>"   # macOS
   ```
   Then poll:
   ```
   GET ${PULSE_BASE_URL}/request-scoped-access/<request_id>
   ```
   - `"approved"` -> store `session_handle`, proceed to x402 skill.
   - `"denied"` -> inform user, stop.

   Alternatively, if Watchdog already blocked an `awal` attempt, the user may have already
   created a grant from the dashboard's "Grant Access" button on the blocked event.
   Check `GET /api/scoped-access?active_only=true` for a matching grant.

## Error Handling

- **400 bad_request** -- Invalid policy (check `allowed_domains`, `allowed_apis` fields).
- **404 on poll** -- Request expired or already processed; create a new one.
- **"BLOCKED by Agent Watchdog"** -- You tried to run `awal` directly. Use this skill instead.
