## Dashboard Portal – Design

This document describes the design for a local dashboard portal that allows users to review wallet balance, **Scoped Access grants** (formerly delegations), and transactions.

---

### 1. Goals & Scope

- **Goal**: Provide a local web UI (`GET /dashboard`) to view:
  - Wallet account info (email, address) and balances (USDC, ETH, WETH)
  - Active and past **Scoped Access** sessions (grants)
  - Transaction history (x402 payments)
- **Data Sources**:
  - **Wallet info**: Agentic Wallet (`awal` CLI) – `status`, `address`, `balance`
  - **Scoped Access grants**: Local Portal SQLite DB (`Delegation_Sessions` table)
  - **Transactions**: Local Portal SQLite DB (`Transaction_Logs` table)
- **Non-goals (MVP)**:
  - Authentication on dashboard (localhost-only, trusted)
  - Real-time WebSocket updates
  - Charts/analytics
  - Multi-user support

---

### 2. API Endpoints

All endpoints served by Local Portal Express server:

#### 2.1 `GET /dashboard`
- **Purpose**: Serve HTML dashboard page
- **Response**: HTML page with embedded JavaScript
- **UI Sections**:
  1. **Wallet Panel**: Email, address (truncated + copy button), balances (USDC/ETH/WETH), refresh button
  2. **Active Scoped Access**: Table with agent, domains, budget (spent/max), TTL remaining, status badge, revoke button
  3. **Past Scoped Access**: Collapsed/expandable list of expired/revoked sessions
  4. **Transaction History**: Table with time, domain, amount (USDC), decision, tx hash (block explorer link), filterable by session

#### 2.2 `GET /api/wallet`
- **Purpose**: Get wallet account and balance info from Agentic Wallet
- **Response**:
  ```json
  {
    "authenticated": true,
    "email": "user@example.com",
    "address": "0x...",
    "balances": {
      "USDC": "12.50",
      "ETH": "0.003",
      "WETH": "0.00"
    }
  }
  ```
- **Implementation**: Calls `awal status`, `awal address`, `awal balance` via `awalAdapter`

#### 2.3 `GET /api/scoped-access`
- **Purpose**: List all Scoped Access sessions (delegation grants) from DB
- **Query Params**: `?active_only=true` (optional, default false)
- **Response**:
  ```json
  [
    {
      "session_id": "...",
      "agent_id": "agent_cursor_01",
      "user_id": "user_01",
      "allowed_domains": ["nickeljoke.vercel.app"],
      "max_total_spend": 50000,
      "max_per_tx": 5000,
      "total_spent_atomic": 5000,
      "ttl_seconds": 300,
      "expires_at": 1740000000000,
      "is_active": true,
      "created_at": 1739999700000,
      "last_counter": 2
    }
  ]
  ```
- **Derived Fields**: `is_active = !revoked_at && expires_at > now`

#### 2.4 `GET /api/transactions`
- **Purpose**: List transaction logs from DB
- **Query Params**: 
  - `?session_id=...` (optional, filter by session)
  - `?limit=50` (optional, default 100)
- **Response**:
  ```json
  [
    {
      "tx_id": "...",
      "session_id": "...",
      "operation": "x402_request",
      "amount": "5000",
      "recipient": "0x...",
      "domain": "nickeljoke.vercel.app",
      "decision": "APPROVED",
      "deny_code": null,
      "tx_hash": "0x...",
      "counter": 1,
      "created_at": 1740000000000
    }
  ]
  ```

#### 2.5 `POST /api/scoped-access/:session_id/revoke`
- **Purpose**: Revoke an active Scoped Access session (grant)
- **Response**:
  ```json
  {
    "success": true,
    "session_id": "...",
    "revoked_at": 1740000000000
  }
  ```
- **Implementation**: Updates `Delegation_Sessions.revoked_at` and `revoked_reason`

---

### 3. Implementation Changes

#### 3.1 `awalAdapter.ts`
**New Methods**:
- `getAddress(): Promise<string>` – calls `npx awal address` and parses output
- `getBalance(): Promise<{ USDC: string; ETH: string; WETH: string }>` – calls `npx awal balance --json` and parses

**New Type**:
```ts
export type WalletInfo = {
  authenticated: boolean;
  email?: string;
  address?: string;
  balances?: {
    USDC: string;
    ETH: string;
    WETH: string;
  };
};
```

#### 3.2 `sessionManager.ts`
**New Functions**:
- `listSessions(activeOnly?: boolean): DelegationSession[]` – queries `Delegation_Sessions` table
- `revokeSession(sessionId: string, reason?: string): void` – updates `revoked_at` and `revoked_reason`

#### 3.3 `server.ts`
**New Endpoints**:
- `GET /dashboard` – serves HTML dashboard page
- `GET /api/wallet` – returns wallet info JSON
- `GET /api/delegations` – returns delegations JSON
- `GET /api/transactions` – returns transactions JSON
- `POST /api/delegations/:session_id/revoke` – revokes a session

**Static Assets**:
- Dashboard HTML/CSS/JS can be inline in the route handler (like approval UI) or served from a `public/` directory

#### 3.4 `db.ts`
- **No schema changes needed** – existing tables (`Delegation_Sessions`, `Transaction_Logs`) already have all required fields

---

### 4. Dashboard UI Design

**Layout**: Single-page application with 4 collapsible panels:

1. **Wallet Panel** (always visible)
   - Email: `user@example.com`
   - Address: `0x1234...5678` [Copy]
   - Balances:
     - USDC: `$12.50`
     - ETH: `0.003 ETH`
     - WETH: `0.00 WETH`
   - [Refresh] button

2. **Active Delegations** (expandable)
   - Table columns: Agent | Domains | Budget (Spent/Max) | TTL Remaining | Status | Actions
   - Status badges: Active (green), Expired (gray), Revoked (red)
   - Actions: [Revoke] button per row

3. **Past Delegations** (collapsed by default)
   - Same table format, but only expired/revoked sessions
   - [Expand] / [Collapse] toggle

4. **Transaction History** (expandable)
   - Table columns: Time | Domain | Amount (USDC) | Decision | TX Hash | Session
   - Decision badges: Approved (green), Denied (red)
   - TX Hash: Link to Base Sepolia block explorer (`https://sepolia.basescan.org/tx/0x...`)
   - Filter dropdown: [All Sessions] or specific session_id
   - Pagination: Show 50 per page

**Styling**: Match approval UI style (system-ui font, clean tables, minimal colors)

---

### 5. Security Considerations

- **Access Control**: Dashboard is localhost-only (same as other Local Portal endpoints)
- **No Authentication**: MVP assumes single-user local machine; can add passkey auth later
- **Read-Only by Default**: Only revocation endpoint modifies data; all other endpoints are read-only
- **Input Validation**: Session ID validation on revoke endpoint; SQL injection protection via parameterized queries

---

### 6. Future Enhancements (Post-MVP)

- Passkey authentication for dashboard access
- Real-time updates via WebSocket
- Charts/graphs for spending over time
- Export transaction history (CSV/JSON)
- Filter transactions by date range
- Search/filter delegations by agent or domain

---

This design aligns with the existing Local Portal architecture and reuses existing database schemas.
