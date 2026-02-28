---
name: agent-pulse-wallet-status
description: Check Agentic Wallet authentication status. Use before any x402 paid API call, before requesting scoped access (grants), or when the portal returns wallet_not_authenticated (503).
---

# Wallet Status

`GET http://127.0.0.1:4020/wallet-status`

- `authenticated: true` → Proceed with scoped access (grant request) or x402 request.
- `authenticated: false` → Tell user to run `npx awal@latest status` in a terminal, sign in, then confirm. Do not proceed until authenticated.

## Error Handling

- **Connection refused** → Local Portal not running. Ask user to start it (`npx ts-node src/server.ts` in `local-portal/`).
- **503 wallet_not_authenticated** from `/execute` → Call this endpoint, then guide user to sign in.
