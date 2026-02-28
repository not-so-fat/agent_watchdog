---
name: agent-pulse-x402
description: Make paid HTTP requests to x402-protected APIs via Pulse. Use when you have a Scoped Access session_handle (grant) and passphrase and need to call a paid endpoint. NEVER run awal directly -- Watchdog will block it.
---

# x402 Payment Request

**IMPORTANT:** Do NOT run `awal` or `npx awal` directly. Watchdog will block it. All payments
go through Pulse via the `/execute` endpoint below.

Send a paid request through `POST http://127.0.0.1:4020/execute`.

## Prerequisites

- `session_handle` (from scoped-access / grant skill, discovered via `GET /api/scoped-access?active_only=true` or created via `request_scoped_access`)
- `passphrase` - Check env var `LOCAL_PORTAL_SHARED_SECRET` first
- Target URL must be in the session's `allowed_domains`

## Making the Call

Build the JSON body, compute HMAC, then POST:

```bash
BODY='{"session_handle":"<HANDLE>","operation":"x402_request","params":{"url":"https://example.com/api/endpoint","method":"GET","headers":{"Accept":"application/json"},"body":null},"counter":<LAST_COUNTER+1>,"idempotency_key":"<UNIQUE_ID>"}'

SIG=$(echo -n "$BODY" | openssl dgst -sha256 -hmac "<PASSPHRASE>" | awk '{print $NF}')

curl -s -X POST http://127.0.0.1:4020/execute \
  -H "Content-Type: application/json" \
  -H "x-local-portal-signature: $SIG" \
  -d "$BODY"
```

- `counter`: must exceed the session's `last_counter`. For a new session start with `1`. For reused sessions, check `last_counter` from `GET /api/delegations?active_only=true` and use `last_counter + 1`.
- `idempotency_key`: any unique string (e.g. UUID or `<purpose>-<timestamp>`).

## Response

- `status` / `body` – the upstream HTTP response.
- `metadata.x402_paid` – true if payment succeeded.
- `metadata.tx_hash` – blockchain transaction hash (if available).

## Error Handling

| Status | Meaning | Action |
|--------|---------|--------|
| 401 | Bad HMAC signature | Verify passphrase matches server's `LOCAL_PORTAL_SHARED_SECRET` |
| 402 | Denied by policy | Check domain allowlist, budget, or session TTL |
| 403 | Unknown session | Session expired or revoked; create new scoped-access grant |
| 409 | Replay | Counter too low; increment and retry |
| 502 | Awal payment failed (e.g. network, server reject) | Check `.temporal/logs/awal-x402-pay-debug.log` |
| 503 | Wallet not authenticated | The Agentic Wallet (awal) is not signed in, so payment could not be made. Response body explains; use wallet-status skill and ask user to run `npx awal@latest status` and sign in, then retry. |
