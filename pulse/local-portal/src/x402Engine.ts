import type { DelegationSession } from "./sessionManager";
import { checkPolicy } from "./policyEngine";
import { awalAdapter, X402Challenge } from "./awalAdapter";

/**
 * x402 services may return payment-required info in either:
 * - A PAYMENT-REQUIRED (or payment-required) header (JSON or base64), or
 * - The 402 response body as JSON (e.g. { x402Version, accepts: [{ amount, maxAmountRequired, ... }] }).
 * This helper parses amount in atomic units from either source.
 */
function parsePaymentRequiredAmount(
  headerValue: string | null,
  bodyJson: unknown
): number | undefined {
  type AcceptEntry = { amount?: string; maxAmountRequired?: string };
  const fromAccepts = (accepts: AcceptEntry[] | undefined): number | undefined => {
    if (!accepts?.[0]) return undefined;
    const a = accepts[0];
    if (a.amount) {
      const n = parseInt(a.amount, 10);
      if (!isNaN(n) && n > 0) return n;
    }
    if (a.maxAmountRequired) {
      const n = parseInt(a.maxAmountRequired, 10);
      if (!isNaN(n) && n > 0) return n;
    }
    return undefined;
  };
  if (headerValue) {
    try {
      const raw = headerValue.trim();
      const parsed: Record<string, unknown> = raw.startsWith("{")
        ? JSON.parse(raw)
        : JSON.parse(Buffer.from(raw, "base64").toString("utf-8"));
      const amount = fromAccepts(parsed.accepts as AcceptEntry[]);
      if (amount !== undefined) return amount;
    } catch {
      // ignore
    }
  }
  if (bodyJson !== null && typeof bodyJson === "object" && "accepts" in bodyJson) {
    return fromAccepts((bodyJson as { accepts?: AcceptEntry[] }).accepts);
  }
  return undefined;
}

export interface X402Params {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string | null;
}

export interface SettlementProof {
  success: boolean;
  transaction: string;
  network: string;
  payer: string;
}

export interface X402Result {
  status: number;
  headers: Record<string, string>;
  body: string;
  metadata: {
    x402_paid: boolean;
    /** Expected amount from PAYMENT-REQUIRED (policy check max), used as spent when settlement succeeds */
    expected_amount_atomic?: number;
    /** Settlement proof from PAYMENT-RESPONSE header */
    settlement_proof?: SettlementProof;
    deny_code?: string;
    tx_hash?: string;
  };
}

export async function handleX402Request(
  session: DelegationSession,
  params: X402Params
): Promise<X402Result> {
  const url = new URL(params.url);
  const domain = url.hostname;
  const path = url.pathname;
  const method = params.method || "GET";

  // Compute conservative max amount for this call (atomic units).
  const remaining = session.max_total_spend - session.total_spent_atomic;
  if (remaining <= 0) {
    return {
      status: 402,
      headers: {},
      body: "Budget exceeded",
      metadata: { x402_paid: false, deny_code: "BUDGET_EXCEEDED" },
    };
  }
  const maxForThisCall = Math.min(session.max_per_tx, remaining);

  // Run policy check before attempting any paid x402 call.
  const policyResult = checkPolicy({
    session,
    domain,
    path,
    method,
    amountAtomic: maxForThisCall,
  });

  if (policyResult.decision === "DENY") {
    return {
      status: 402,
      headers: {},
      body: "Denied by policy",
      metadata: { x402_paid: false, deny_code: policyResult.deny_code },
    };
  }

  // Preflight: GET 402 so we have the payee's price. Payment-required may be in header or in 402 body (see parsePaymentRequiredAmount).
  // After payment, the wallet often returns only the final 200, so we may not see PAYMENT-REQUIRED again—hence we capture it here.
  let preflightAmountAtomic: number | undefined;
  try {
    const preflightInit: RequestInit = {
      method: params.method ?? "GET",
      headers: params.headers ?? {},
      redirect: "manual",
    };
    if (params.body != null && params.body !== "") {
      preflightInit.body = params.body;
    }
    const preflightRes = await fetch(params.url, preflightInit);
    if (preflightRes.status === 402) {
      const headerVal =
        preflightRes.headers.get("payment-required") ?? preflightRes.headers.get("PAYMENT-REQUIRED");
      let bodyJson: unknown = null;
      try {
        const bodyText = await preflightRes.text();
        bodyJson = bodyText ? JSON.parse(bodyText) : null;
      } catch {
        // not JSON
      }
      preflightAmountAtomic = parsePaymentRequiredAmount(headerVal, bodyJson);
    }
  } catch {
    // Preflight failed (e.g. network); we may still get amount from 200 response or wallet
  }

  // Delegate the full x402 flow (request + payment + retry) to Awal.
  const challenge: X402Challenge = {
    url: params.url,
    method: params.method ?? "GET",
    headers: params.headers ?? {},
    body: params.body ?? null,
  };

  await awalAdapter.ensureAuthenticated();
  const payResult = await awalAdapter.payX402Challenge(challenge);

  if (!payResult.success || payResult.status === undefined) {
    const errMsg = payResult.error_message || "awal x402 pay failed";
    const isAuthRequired =
      /Authentication required/i.test(errMsg) || /not authenticated/i.test(errMsg);
    if (isAuthRequired) {
      return {
        status: 503,
        headers: {},
        body:
          "Payment failed: Agentic Wallet is not authenticated, so the payment could not be made. " +
          "Run 'npx awal@latest status' in a terminal and sign in (e.g. email OTP or 'npx awal show'), then retry.",
        metadata: { x402_paid: false, deny_code: "WALLET_NOT_AUTHENTICATED" },
      };
    }
    return {
      status: 502,
      headers: {},
      body: errMsg,
      metadata: { x402_paid: false },
    };
  }

  // Extract actual amount from payee-only sources (never from delegation budget).
  // 1) PAYMENT-REQUIRED (402 response) – may be missing when we only have the final 200 from the wallet.
  // 2) PAYMENT-RESPONSE – some servers include amount in the settlement response.
  // 3) Wallet result – amount_atomic if the wallet reports what it paid.
  let expectedAmountAtomic: number | undefined;
  const paymentRequiredHeader =
    payResult.headers?.["PAYMENT-REQUIRED"] ??
    payResult.headers?.["payment-required"] ??
    payResult.headers?.["X-PAYMENT-REQUIRED"] ??
    payResult.headers?.["x-payment-required"];

  if (paymentRequiredHeader) {
    expectedAmountAtomic = parsePaymentRequiredAmount(paymentRequiredHeader, null);
  }

  // If still unknown, try PAYMENT-RESPONSE (200 response; some servers include amount)
  if (expectedAmountAtomic === undefined) {
    const paymentResponseHeader =
      payResult.headers?.["PAYMENT-RESPONSE"] ??
      payResult.headers?.["payment-response"] ??
      payResult.headers?.["X-PAYMENT-RESPONSE"] ??
      payResult.headers?.["x-payment-response"];
    if (paymentResponseHeader) {
      try {
        const raw = paymentResponseHeader.trim();
        let paymentResponse: Record<string, unknown>;
        if (raw.startsWith("{")) {
          paymentResponse = JSON.parse(raw);
        } else {
          paymentResponse = JSON.parse(
            Buffer.from(paymentResponseHeader, "base64").toString("utf-8")
          );
        }
        const amount =
          paymentResponse.amount_atomic ??
          paymentResponse.amount ??
          paymentResponse.charged_amount;
        const n = typeof amount === "number" ? amount : parseInt(String(amount), 10);
        if (!isNaN(n) && n > 0) {
          expectedAmountAtomic = n;
        }
      } catch {
        // Ignore
      }
    }
  }

  // If still unknown, use amount reported by the wallet (from 402 when it did the pay)
  if (expectedAmountAtomic === undefined && payResult.amount_atomic != null && payResult.amount_atomic > 0) {
    expectedAmountAtomic = payResult.amount_atomic;
  }

  // If still unknown, use amount from preflight 402 (payee's price)
  if (expectedAmountAtomic === undefined && preflightAmountAtomic != null) {
    expectedAmountAtomic = preflightAmountAtomic;
  }

  if (expectedAmountAtomic === undefined) {
    return {
      status: 502,
      headers: {},
      body: "Could not determine price from payee (PAYMENT-REQUIRED, PAYMENT-RESPONSE, or wallet amount)",
      metadata: { x402_paid: false, deny_code: "PRICE_UNAVAILABLE" },
    };
  }

  // Validate price doesn't exceed user's budget limit
  if (expectedAmountAtomic > maxForThisCall) {
    return {
      status: 402,
      headers: {},
      body: `Price ${expectedAmountAtomic} exceeds budget limit ${maxForThisCall}`,
      metadata: { x402_paid: false, deny_code: "EXCEEDS_BUDGET" },
    };
  }

  // Parse settlement proof from PAYMENT-RESPONSE header (x402 protocol)
  // This contains: success, transaction (tx hash), network, payer
  let settlementProof: SettlementProof | undefined;

  const paymentResponseHeader =
    payResult.headers?.["PAYMENT-RESPONSE"] ??
    payResult.headers?.["payment-response"] ??
    payResult.headers?.["X-PAYMENT-RESPONSE"] ??
    payResult.headers?.["x-payment-response"];

  if (paymentResponseHeader) {
    try {
      let paymentResponse: Record<string, unknown>;
      const raw = paymentResponseHeader.trim();
      if (raw.startsWith("{")) {
        paymentResponse = JSON.parse(paymentResponseHeader);
      } else {
        paymentResponse = JSON.parse(
          Buffer.from(paymentResponseHeader, "base64").toString("utf-8")
        );
      }
      // Only create settlementProof if we have success (the minimum required field)
      if (paymentResponse.success !== undefined) {
        settlementProof = {
          success: Boolean(paymentResponse.success),
          transaction: typeof paymentResponse.transaction === "string"
            ? paymentResponse.transaction
            : "",
          network: typeof paymentResponse.network === "string"
            ? paymentResponse.network
            : "",
          payer: typeof paymentResponse.payer === "string"
            ? paymentResponse.payer
            : "",
        };
      }
    } catch {
      // Parsing failed, settlementProof stays undefined
    }
  }

  // Determine spent amount: use the expected amount from x402 header when settlement succeeded.
  let spentAtomic = 0;
  if (settlementProof?.success && expectedAmountAtomic !== undefined) {
    spentAtomic = expectedAmountAtomic;
  }

  const metadata: X402Result["metadata"] = {
    x402_paid: true,
    expected_amount_atomic: expectedAmountAtomic!,
    ...(settlementProof && { settlement_proof: settlementProof }),
    ...(settlementProof?.transaction && { tx_hash: settlementProof.transaction }),
  };

  return {
    status: payResult.status,
    headers: payResult.headers ?? {},
    body: payResult.body ?? "",
    metadata,
  };
}

