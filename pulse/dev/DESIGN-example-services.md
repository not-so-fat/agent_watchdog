# Technical Design Document: Mock Flight Booking & x402 Environment

## 1. System Objective
Build a localized, mock merchant environment to demonstrate the "Delegated Session" capabilities of the Agentic Wallet Control Portal. The system consists of a single Node.js/Express application simulating two distinct travel providers (United and Expedia) and a centralized discovery directory.

The goal is to force the AI Agent to:
1. Discover flights via a local Read-Only API.
2. Evaluate constraints (budget, stops, arrival times).
3. Request human approval for a specific budget and domain constraint.
4. Execute an x402 payment using the approved Local Portal session without directly handling the payment logic.

## 2. The Scenario Definition

**The User Prompt (Given to Agent):**
> "Find and book a flight from SFO to JFK for tomorrow. My absolute maximum budget is $400. I strongly prefer a direct flight on United, but I will accept a 1-stop flight on any airline if it costs less than $300 and arrives before 8:00 PM."

**The Expected Agent Outcome:**
The agent must evaluate the catalog, reject United (too expensive), reject Expedia Option 1 (too expensive), reject Expedia Option 3 (arrives too late), and select **Expedia Option 2**. It will request a $280 delegation budget restricted to the Expedia mock domain.

---

## 3. Mock Data: Flight Catalog

The server will host this static catalog. Prices are in USD and atomic units (USDC, 6 decimals). Prices are scaled down by x0.001 to keep testnet token costs minimal.

| ID | Provider | Airline | Stops | Departs (SFO) | Arrives (JFK) | Price | USDC Atomic |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `u-101` | United | United | 0 (Direct) | 08:00 AM | 04:30 PM | $0.0045 | 4500 |
| `u-102` | United | United | 1 (ORD) | 10:00 AM | 08:00 PM | $0.0035 | 3500 |
| `e-201` | Expedia | Delta | 0 (Direct) | 09:00 AM | 05:30 PM | $0.0041 | 4100 |
| `e-202` | Expedia | American | 1 (DFW) | 06:00 AM | **04:00 PM** | **$0.0028** | **2800** |
| `e-203` | Expedia | JetBlue | 1 (BOS) | 01:00 PM | 11:30 PM | $0.0025 | 2500 |

---

## 4. Network Topology: ngrok Tunnel

### 4.1 Why ngrok is Required
The Coinbase Agentic Wallet (`awal` CLI) has built-in SSRF protection. If the agent attempts to pay an x402 invoice hosted on `localhost` or `127.0.0.1`, the CLI will block the transaction. ngrok creates a secure, temporary public URL (e.g., `https://a1b2c3d4.ngrok.app`) that forwards traffic to your local Express server, allowing the CLI to treat it as a standard public merchant.

### 4.2 Security Rule
Two local services run simultaneously. Only one may be exposed:

* **✅ SAFE TO EXPOSE: Port 5000 (Mock Merchant).** A fake storefront — no private keys, no real money, no access to the local system.
* **❌ NEVER EXPOSE: Port 4020 (Local Portal).** The gatekeeper daemon — holds the Coinbase CDP authentication token and can sign real transactions. Must remain bound to `127.0.0.1`.

### 4.3 Starting the Tunnel
Once the Express mock server is running on port 5000, open a new terminal:

```bash
ngrok http 5000
```

Note the **Forwarding** URL (e.g., `https://a1b2c3d4.ngrok.app`). Keep this terminal open.

### 4.4 Dynamic `booking_url` Resolution
Because free ngrok URLs change on every restart, the `GET /api/discovery/flights` endpoint dynamically reads the incoming `Host` header and `x-forwarded-proto` to build `booking_url` values. When queried through ngrok, the returned URLs automatically point to the ngrok tunnel — no hardcoded hostnames.

---

## 5. API Specification

The Node.js server runs on `localhost:5000` (HTTPS) and is exposed via ngrok.

### 5.1 Discovery Endpoint (The Catalog)
This acts as the "Bazaar" for the agent to find options.

* **Endpoint:** `GET /api/discovery/flights`
* **Response:** `200 OK`
* **Payload:** A JSON array of the flight catalog (based on the table above). Each flight object includes a `booking_url` dynamically derived from the request host (e.g., `https://a1b2c3d4.ngrok.app/api/expedia/book/e-202`).

### 5.2 Booking Endpoints (The x402 Paywalls)
These endpoints simulate the providers. They share the same logic but represent different merchant domains in the Local Portal's policy engine.

* **Endpoints:**
    * `POST /api/united/book/:id`
    * `POST /api/expedia/book/:id`

**Execution Logic (The x402 Handshake):**

**Step A: Check for Payment**
When the POST request hits the endpoint, the server checks the request headers for an `x-payment-receipt`.

**Step B: If No Payment (Return 402)**
If the header is missing, lookup the flight `:id` to get the required atomic amount. Respond strictly with HTTP 402.

* **Response Status:** `402 Payment Required`
* **Headers:**
    ```text
    WWW-Authenticate: x402 network="base-sepolia", address="0x63d775a6B271F540f84193C3A18fc2C52f131898", amount="<atomic_price>", currency="USDC"
    ```
* **Body:**
    ```json
    {
      "error": "Payment Required",
      "message": "Please remit payment on base-sepolia to book this flight.",
      "payment_details": {
        "network": "base-sepolia",
        "currency": "USDC",
        "amount_atomic": 2800,
        "recipient": "0x63d775a6B271F540f84193C3A18fc2C52f131898"
      }
    }
    ```

**Step C: If Payment Present (Verify & Return 200)**
If the `x-payment-receipt` header exists (containing a `tx_hash` passed by the Local Portal), execute the following verification sequence:

1.  **Extract the Hash:** Read the `tx_hash` from the `x-payment-receipt` header.
2.  **Connect to Network:** Connect to Base Sepolia via a public RPC (e.g., `https://sepolia.base.org`).
3.  **Fetch Transaction:** Look up the transaction using `eth_getTransactionByHash`. If the transaction is not found, return `400` with reason `"transaction not found"`.
4.  **Validate 3 Rules:**
    * **Rule 1 (Recipient):** Does the `to` address match the Mock Merchant's wallet address (`0x63d775a6B271F540f84193C3A18fc2C52f131898`)? For ERC-20 (USDC) transfers, the `to` field is the token contract — decode the `transfer(address,uint256)` calldata to extract the actual recipient.
    * **Rule 2 (Amount):** Does the value match the exact atomic price of the requested flight (e.g., `2800`)? For ERC-20 transfers, decode the amount from calldata rather than the transaction `value` field.
    * **Rule 3 (Replay Protection):** Has this `tx_hash` already been used for a previous booking? The server maintains an in-memory set of consumed transaction hashes. If the hash has been seen before, return `400` with reason `"tx_hash already used"`.
5.  **On Failure:** If any rule fails, respond with `400 Bad Request` and a JSON body indicating which rule failed:
    ```json
    {
      "error": "Payment verification failed",
      "reason": "recipient mismatch"
    }
    ```
6.  **On Success — Confirm Booking:** Mark the `tx_hash` as consumed, then respond:
    * **Response Status:** `200 OK`
    * **Body:**
        ```json
        {
          "status": "confirmed",
          "booking_reference": "XYZ-9876",
          "flight_id": "e-202",
          "message": "Flight booked successfully. Have a great trip!"
        }
        ```

---

## 6. Agent Skills Architecture

The agent (Cursor) will be equipped with exactly three custom skills. Skills 1 and 2 route through the Local Portal CLI wrapper to ensure absolute security. Skill 3 is a direct read-only terminal command.

1. **`discover_x402_services` (Skill 3 - New):** Teaches the agent to execute a raw terminal command (`curl -s https://<NGROK_URL>/api/discovery/flights | jq .`) to fetch the catalog JSON and review options before planning. The agent asks the user for the current ngrok URL.
2. **`request_delegation` (Skill 1 - Locked):** The agent proposes a plan (e.g., budget, target domain) via the Local Portal CLI wrapper. Pauses agent execution until human approval is granted in the UI. Returns a `session_handle`.
3. **`x402_request` (Skill 2 - Locked):** The agent passes the `session_handle` and the target URL via the Local Portal CLI wrapper. The Portal handles the HTTP request, 402 intercept, and payment execution internally.

---

## 7. End-to-End Agent Execution Flow

1.  **Agent Initialization:** The agent receives the user's prompt containing flight constraints and budget.
2.  **Discovery (Skill 3):** The agent asks the user for the ngrok URL and uses `discover_x402_services` to execute a `GET` request to the discovery endpoint via the ngrok tunnel.
3.  **Reasoning:** The agent's LLM parses the printed JSON array. It filters out flights over $400, filters out 1-stops over $300, and evaluates the `arrival_time`. It determines `e-202` is the only valid choice.
4.  **Delegation (Skill 1):** The agent determines it needs to call `POST /api/expedia/book/e-202`. It uses the `request_delegation` skill, passing `"budget": "0.0028"` and `"allowed_domains": ["<NGROK_HOST>"]` (the ngrok domain from the `booking_url`).
5.  **Human Approval:** The Local Portal intercepts the CLI execution, shows the user the $280 request, secures approval, and returns an opaque `session_handle` to the agent.
6.  **Execution (Skill 2):** The agent uses the `x402_request` skill, passing the `session_handle` and the `e-202` booking URL.
7.  **The Handshake (Inside Local Portal):**
    * Local Portal calls `POST /api/expedia/book/e-202`.
    * Mock Server returns `402 Payment Required` with the Base Sepolia headers.
    * Local Portal intercepts the 402, verifies the $280 is within the approved session policy, and uses the Agentic Wallet to send Sepolia USDC.
    * Local Portal retries the `POST` with the `tx_hash` in the header.
    * Mock Server validates the hash and returns `200 OK`.
8.  **Completion:** Local Portal passes the `200 OK` (booking reference) back to the agent's stdout. The agent reports success to the user.