---
name: agent-pulse-discovery
description: Discover available x402-protected services. Use when looking for paid APIs, browsing a service catalog, finding flights, or before deciding which x402 endpoint to call.
---

# Discover x402 Services

Fetch the catalog of available x402-protected services (flights and LLM models) from the mock discovery endpoints.

## Usage

**Production (Vercel):** Use the hosted demo URLs:

```bash
# Flights
curl -s https://agent-pulse-nu.vercel.app/api/discovery/flights | jq .

# LLM models
curl -s https://agent-pulse-nu.vercel.app/api/discovery/models | jq .
```


## What You Get

### Flights

A JSON array of flight objects. Each entry contains:

- `id` — Flight identifier (e.g. `e-202`)
- `provider` — Service provider (`United` or `Expedia`)
- `airline`, `stops`, `stop_via` — Flight routing details
- `departs`, `arrives` — Schedule times
- `origin`, `destination` — Airport codes
- `price_usd` — Human-readable price
- `price_atomic` — USDC atomic units (6 decimals) for x402 payment
- `booking_url` — The x402-paywalled POST endpoint to book this flight (points to the same host, e.g. Vercel or ngrok)

### LLM models

A JSON object:

```json
{
  "models": [
    { "id": "opus-4-6", "provider": "anthropic", "rate_per_Mtoken": 0.5 },
    { "id": "gpt-5.2-codex", "provider": "openai", "rate_per_Mtoken": 0.1 }
  ]
}
```

Each model entry contains:

- `id` — Model identifier
- `provider` — Model provider (`anthropic` or `openai`)
- `rate_per_Mtoken` — Cost in USD per 1M tokens (used to compute x402 prices)

## After Discovery

**Flights:**

1. **Evaluate** the options against the user's constraints (budget, stops, arrival time, airline preferences).
2. **Estimate** the potential flights that satisfies all constraints and suggest budget.
3. **Delegate** — Use the `agent-pulse-delegation` skill to request a payment session with:
   - `allowed_domains`: `["<host>"]` (e.g., `["agent-pulse-nu.vercel.app"]`)
   - `allowed_apis`: Array of API objects for the booking endpoints
   - `max_total_spend` covering anticipated flights
4. **Select** the best flight that satisfies all constraints.
5. **Book** — Use the `agent-pulse-x402` skill with the approved `session_handle` to call the `booking_url`.

**LLM models:**

1. **Choose** a model based on task type and budget (e.g. cheaper `gpt-5.2-codex` vs more expensive `opus-4-6`).
2. **Estimate** cost for a request using the model's `rate_per_Mtoken`, a rough input size, and a `max_output_tokens` cap.
3. **Delegate** — Use the `agent-pulse-delegation` skill with:
   - `allowed_domains`: `["agent-pulse-nu.vercel.app"]`
   - `allowed_apis`: `[{ "domain": "agent-pulse-nu.vercel.app", "path": "/api/*/infer/*", "method": "POST" }]`
   - `max_total_spend` covering anticipated LLM usage
4. **Infer** — Use the `agent-pulse-x402` skill with the approved `session_handle` to call the appropriate infer endpoint, e.g. `POST /api/openai/infer/gpt-5.2-codex`.

## Important

- The `booking_url` values in the catalog response are **dynamically generated** from the request host (Vercel or ngrok).
- The host (e.g. `agent-pulse-nu.vercel.app`) must be included in `allowed_domains` when requesting delegation.

## Error Handling

- **Connection refused** — The mock services server is not running. Ask the user to start it: `cd demo/mock-services && npm run dev`
- **Empty response** — Check that the server started correctly on port 5000.
- **HTTPS required** — The `awal` CLI blocks localhost/127.0.0.1 (SSRF protection). Use the Vercel URL or ngrok for x402 payments.
