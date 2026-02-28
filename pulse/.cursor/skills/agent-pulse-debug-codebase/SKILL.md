---
name: agent-pulse-debug-codebase
description: Debug this codebase using x402-paid LLM inference. Use when the user asks to "debug this codebase" with paid APIs. Demonstrates the Cursor + Watchdog + Pulse demo flow where Cursor delegates payment through Pulse instead of running awal directly.
---

# Debug Codebase (x402 LLM) -- Demo Scenario

When the user asks to **debug this codebase**, demonstrate the full Agent Control Plane flow:

1. Cursor (you) needs a paid API call
2. Watchdog prevents direct `awal` usage
3. Cursor requests scoped access through Pulse
4. User approves; Pulse handles payment autonomously
5. Cursor gets the result

## IMPORTANT: Do NOT run `awal` directly

Watchdog monitors this machine. If you attempt `awal` or `npx awal`, it will be blocked
and the blocked attempt will appear in the dashboard. Use the Pulse delegation flow instead.

## Flow

1. **Gather context** -- Collect error messages, logs, relevant code snippets for the debug prompt.

2. **Check wallet** -- Use `agent-pulse-wallet-status`. If not authenticated, have user run
   `npx awal@latest status` in a terminal and sign in.

3. **Discover models** -- Use `agent-pulse-discovery` to get available LLM models and rates.

4. **Estimate cost** -- For ~0.1M tokens: cost = `0.1 x rate_per_Mtoken` (USD).

5. **Request scoped access** -- Use `agent-pulse-delegation`:
   - `allowed_domains`: the LLM host (e.g., `["demo-x402.vercel.app"]`)
   - `allowed_apis`: the specific infer endpoint(s)
   - `max_total_spend`: estimated budget in USDC atomic units
   - `summary`: "Code review with AI"
   - `description`: explain what APIs will be called and estimated cost

6. **Wait for approval** -- Tell user to check the Pulse dashboard (`http://localhost:4020/dashboard`)
   and approve the grant. If a blocked `awal` attempt happened first, the dashboard will show
   a "Grant Access" button that pre-fills the grant form.

7. **Call the LLM** -- Use `agent-pulse-x402` with the approved `session_handle` to POST
   to the infer endpoint with JSON body:
   ```json
   { "task": "debug", "input": "<debug prompt>", "max_output_tokens": 20000 }
   ```

8. **Apply fixes** -- Use the model's response to suggest or apply fixes; run tests/linters to verify.

## Available LLM Endpoints

| Model          | Path                                   |
|----------------|----------------------------------------|
| opus-4-6       | `POST /api/anthropic/infer/opus-4-6`  |
| gpt-5.2-codex  | `POST /api/openai/infer/gpt-5.2-codex` |

Host: `demo-x402.vercel.app` (production) or user's ngrok URL for local mock services.

## Dependencies

- **agent-pulse-wallet-status** -- before delegation
- **agent-pulse-discovery** -- list models and rates
- **agent-pulse-delegation** -- create grant with budget and allowed_domains
- **agent-pulse-x402** -- paid POST to infer endpoint
