import express, { Request, Response } from "express";
import { createProxyMiddleware } from "http-proxy-middleware";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type { GenerateRegistrationOptionsOpts } from "@simplewebauthn/server";

import { db, runMigrations } from "./db";
import {
  getSession,
  updateLastCounter,
  addSpentAtomic,
  listSessions,
  revokeSession,
  type GrantCapabilities,
} from "./sessionManager";
import { handleX402Request } from "./x402Engine";
import { checkPolicy } from "./policyEngine";
import { awalAdapter } from "./awalAdapter";
import { exec } from "child_process";
import {
  registerPid,
  unregisterPid,
  getPidSets,
  addEvent,
  getEvents,
  dismissEvent,
  getStats as getWatchdogStats,
  autoDetectCursorPid,
  type PidSetName,
} from "./watchdogLite";
import { getDashboardHtml } from "./dashboardV2";
import {
  findOrCreateUserByEmail,
  getUserById,
  addPasskeyCredential,
  getPasskeyCredentialsByUserId,
  getPasskeyCredentialById,
  getAllPasskeyCredentials,
  updatePasskeyCounter,
  deletePasskeyCredential,
  createBrowserSession,
  getBrowserSession,
  deleteBrowserSession,
  cleanExpiredSessions,
} from "./userManager";
import type { User } from "./userManager";

if (!process.env.LOCAL_PORTAL_SHARED_SECRET) {
  console.error(
    "FATAL: LOCAL_PORTAL_SHARED_SECRET env var is required.\n" +
    "Start the server with:\n\n" +
    '  LOCAL_PORTAL_SHARED_SECRET="your-secret" npx ts-node src/server.ts\n'
  );
  process.exit(1);
}
const SHARED_SECRET: string = process.env.LOCAL_PORTAL_SHARED_SECRET;

const HMAC_LOG_DIR = path.resolve(__dirname, "..", "..", ".temporal", "logs");
const HMAC_LOG_PATH = path.join(HMAC_LOG_DIR, "local-portal-hmac-debug.log");

// ============================================================
// Atomic Unit Conversion Helpers
// USDC on Base uses 6 decimal places (1 USDC = 1_000_000 atomic units).
// Approval form, delegation details, and dashboard all use this consistently.
const ATOMIC_UNITS = 1_000_000;

function atomicToUSD(atomic: number): string {
  return (Number(atomic) / ATOMIC_UNITS).toFixed(6);
}

function usdToAtomic(usd: number): number {
  return Math.round(usd * ATOMIC_UNITS);
}

try {
  fs.mkdirSync(HMAC_LOG_DIR, { recursive: true });
} catch {
  // best-effort; if this fails, we just won't log to file
}

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Proxy Watchdog API so the dashboard can reach it without exposing port 3000.
app.use(
  "/watchdog",
  createProxyMiddleware({
    target: "http://127.0.0.1:3000",
    changeOrigin: false,
    pathRewrite: { "^/watchdog": "" },
  })
);

runMigrations();

// Clean expired browser sessions periodically (every 10 minutes)
setInterval(() => cleanExpiredSessions(), 10 * 60 * 1000);

function parseCookies(req: Request): Record<string, string> {
  const header = req.headers.cookie || "";
  const cookies: Record<string, string> = {};
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key) cookies[key] = rest.join("=");
  }
  return cookies;
}

function getSessionUser(req: Request): User | null {
  const cookies = parseCookies(req);
  const token = cookies["portal_session"];
  if (!token) return null;
  const session = getBrowserSession(token);
  if (!session) return null;
  return getUserById(session.user_id);
}

function setSessionCookie(res: Response, token: string): void {
  res.setHeader(
    "Set-Cookie",
    `portal_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400`
  );
}

function clearSessionCookie(res: Response): void {
  res.setHeader(
    "Set-Cookie",
    `portal_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`
  );
}

function hmacValid(
  body: unknown,
  signature: string | undefined
): boolean {
  if (!signature) return false;
  const payload = JSON.stringify(body);
  const h = crypto.createHmac("sha256", SHARED_SECRET);
  h.update(payload);
  const expected = h.digest("hex");

  // Best-effort debug log for HMAC behavior.
  // This writes to .temporal/logs/local-portal-hmac-debug.log at repo root.
  try {
    fs.appendFileSync(
      HMAC_LOG_PATH,
      JSON.stringify(
        {
          ts: new Date().toISOString(),
          payload,
          expected,
          received: signature,
        },
        null,
        2
      ) + "\n"
    );
  } catch {
    // ignore logging errors
  }

  return crypto.timingSafeEqual(
    Buffer.from(expected, "hex"),
    Buffer.from(signature, "hex")
  );
}

// Healthcheck
app.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok" });
});

// Wallet status: run `awal status` and return result so the agent can detect unauthenticated wallet and ask the user.
app.get("/wallet-status", async (_req: Request, res: Response) => {
  try {
    const status = await awalAdapter.getWalletStatus();
    return res.json(status);
  } catch (e) {
    return res.status(500).json({
      authenticated: false,
      code: -1,
      stdout: "",
      stderr: (e as Error).message,
      message: "Failed to run wallet status. Please ensure Awal is installed (npx awal@latest status).",
    });
  }
});

function createDelegationSession(
  agent_id: string | null,
  user_id: string | null,
  policy: any
): { status: "approved"; session_handle: string } {
  if (!policy || !Array.isArray(policy.allowed_domains)) {
    throw new Error("invalid policy");
  }

  const sessionHandle = crypto.randomUUID();
  const now = Date.now();
  const ttlMs = (policy.ttl_seconds ?? 600) * 1000;

  const stmt = db.prepare(`
    INSERT INTO Delegation_Sessions (
      session_id, user_id, agent_id, node_id,
      policy_hash, policy_version,
      max_total_spend, max_per_tx,
      allowed_domains, allowed_apis, allowed_recipients,
      rate_limit, ttl_seconds, expires_at,
      last_counter, revoked_at, revoked_reason,
      client_fingerprint, summary, description, created_at, capabilities
    ) VALUES (
      @session_id, @user_id, @agent_id, @node_id,
      @policy_hash, @policy_version,
      @max_total_spend, @max_per_tx,
      @allowed_domains, @allowed_apis, @allowed_recipients,
      @rate_limit, @ttl_seconds, @expires_at,
      @last_counter, @revoked_at, @revoked_reason,
      @client_fingerprint, @summary, @description, @created_at, @capabilities
    )
  `);

  const policyHash = crypto
    .createHash("sha256")
    .update(JSON.stringify(policy))
    .digest("hex");

  stmt.run({
    session_id: sessionHandle,
    user_id: user_id ?? null,
    agent_id: agent_id ?? null,
    node_id: null,
    policy_hash: policyHash,
    policy_version: 1,
    max_total_spend: Number(policy.max_total_spend ?? 0),
    max_per_tx: Number(policy.max_per_tx ?? 0),
    allowed_domains: JSON.stringify(policy.allowed_domains),
    allowed_apis: JSON.stringify(policy.allowed_apis ?? []),
    allowed_recipients: "[]",
    rate_limit: policy.rate_limit ?? null,
    ttl_seconds: policy.ttl_seconds ?? 600,
    expires_at: now + ttlMs,
    last_counter: 0,
    revoked_at: null,
    revoked_reason: null,
    client_fingerprint: null,
    summary: policy.summary ?? null,
    description: policy.description ?? null,
    created_at: now,
    capabilities: policy.capabilities
      ? JSON.stringify(policy.capabilities as GrantCapabilities)
      : null,
  });

  return {
    status: "approved" as const,
    session_handle: sessionHandle,
  };
}

// Approval UI endpoint - shows pending scoped-access (delegation) request
app.get("/approval/:request_id", (req: Request, res: Response) => {
  const rid = String(req.params.request_id ?? "");
  const pending = pendingRequests.get(rid);
  if (!pending) {
    return res.status(404).send("Request not found or already processed");
  }

  // Redirect if accessed via 127.0.0.1 to localhost for WebAuthn compatibility
  const host = req.headers.host || "";
  if (host.startsWith("127.0.0.1:")) {
    const port = host.split(":")[1] || PORT.toString();
    return res.redirect(`http://localhost:${port}/approval/${rid}`);
  }

  // Per-request auth: check if THIS specific scoped-access request has been authenticated
  const authenticatedUserId = approvalAuth.get(rid);
  const authenticatedUser = authenticatedUserId ? getUserById(authenticatedUserId) : null;
  const allCreds = getAllPasskeyCredentials();
  const hasPasskeys = allCreds.length > 0;

  // Use same atomic→USD as delegation details/dashboard (1 USDC = 1e6 on Base)
  const maxTotalUSD = atomicToUSD(pending.policy.max_total_spend);
  const maxPerTxUSD = atomicToUSD(pending.policy.max_per_tx);
  const ttlHours = Math.floor(pending.policy.ttl_seconds / 3600);
  const ttlMinutes = Math.floor((pending.policy.ttl_seconds % 3600) / 60);

  if (!hasPasskeys) {
    // No passkeys registered — send user to /account to set up
    return res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Agent Watchdog - Setup Required</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
    * { box-sizing: border-box; }
    body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; font-size: 0.9em; max-width: 600px; margin: 40px auto; padding: 20px; background: #0D0D0D; color: #E0E0E0; line-height: 1.6; }
    h1 { font-size: 1.5em; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; margin: 0 0 20px 0; border-bottom: 1px solid #708090; padding-bottom: 10px; }
    p { color: #708090; margin: 15px 0; }
    .mono { font-family: 'IBM Plex Mono', monospace; color: #4FD1C5; }
    a { color: #4FD1C5; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .divider { border-top: 1px solid #708090; margin: 20px 0; }
    button { padding: 12px 24px; font-size: 0.9em; border: 1px solid #4FD1C5; cursor: pointer; background: #0D0D0D; color: #4FD1C5; font-family: 'Inter', sans-serif; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 20px; }
    button:hover { background: rgba(79, 209, 197, 0.1); }
  </style>
</head>
<body>
  <h1>ACCOUNT SETUP REQUIRED</h1>
  <div class="divider"></div>
  <p><strong>AGENT ID:</strong> <span class="mono">${pending.agent_id ?? "UNKNOWN"}</span> is requesting scoped access.</p>
  <p>YOU NEED TO REGISTER A PASSKEY BEFORE YOU CAN APPROVE DELEGATIONS.</p>
  <p>GO TO YOUR <a href="/account">ACCOUNT PAGE</a> TO:</p>
  <p>1. CONNECT YOUR AGENTIC WALLET</p>
  <p>2. REGISTER A PASSKEY</p>
  <p>THEN RETURN TO THIS PAGE TO APPROVE.</p>
  <a href="/account"><button>GO TO ACCOUNT SETUP</button></a>
</body>
</html>
    `);
  }

  if (!authenticatedUser) {
    // Not yet authenticated for THIS delegation — always require passkey
    return res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Agent Watchdog - Authenticate Scoped Access</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
    * { box-sizing: border-box; }
    body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; font-size: 0.9em; max-width: 600px; margin: 40px auto; padding: 20px; background: #0D0D0D; color: #E0E0E0; line-height: 1.6; }
    h1 { font-size: 1.5em; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; margin: 0 0 20px 0; border-bottom: 1px solid #708090; padding-bottom: 10px; }
    p { color: #708090; margin: 15px 0; }
    button { padding: 12px 24px; font-size: 0.9em; border: 1px solid #708090; cursor: pointer; background: #0D0D0D; color: #E0E0E0; font-family: 'Inter', sans-serif; text-transform: uppercase; letter-spacing: 0.05em; transition: border-color 0.2s; margin-top: 20px; }
    button:hover { border-color: #4FD1C5; color: #4FD1C5; }
    button:disabled { opacity: 0.5; cursor: not-allowed; border-color: #708090; color: #708090; }
    .status { margin: 20px 0; color: #708090; font-family: 'IBM Plex Mono', monospace; font-size: 0.85em; }
    .error { color: #8B0000; font-family: 'IBM Plex Mono', monospace; }
    .divider { border-top: 1px solid #708090; margin: 20px 0; }
  </style>
</head>
<body>
  <h1>AUTHENTICATE TO APPROVE SCOPED ACCESS</h1>
  <div class="divider"></div>
  <p><strong>AGENT ID:</strong> <span class="mono">${pending.agent_id ?? "UNKNOWN"}</span></p>
  <p>VERIFY YOUR IDENTITY WITH YOUR REGISTERED PASSKEY TO APPROVE THIS SCOPED ACCESS REQUEST.</p>
  <button id="authBtn" onclick="authenticate()">AUTHENTICATE WITH PASSKEY</button>
  <div id="status" class="status"></div>

  <script>
    function bufferToBase64URL(buffer) {
      const bytes = new Uint8Array(buffer);
      let str = '';
      for (const b of bytes) str += String.fromCharCode(b);
      return btoa(str).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
    }

    function base64URLToBuffer(b64url) {
      const base64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes.buffer;
    }

    async function authenticate() {
      const btn = document.getElementById('authBtn');
      const status = document.getElementById('status');
      btn.disabled = true;
      status.textContent = 'REQUESTING CHALLENGE...';

      try {
        const challengeRes = await fetch('/api/passkey/auth-challenge', { method: 'POST' });
        if (!challengeRes.ok) {
          const err = await challengeRes.json().catch(function() { return {}; });
          throw new Error(err.message || 'FAILED TO GET CHALLENGE');
        }
        const { options, challenge_id } = await challengeRes.json();

        const publicKeyOptions = {
          ...options,
          challenge: base64URLToBuffer(options.challenge)
        };
        if (options.allowCredentials) {
          publicKeyOptions.allowCredentials = options.allowCredentials.map(function(c) {
            return { ...c, id: base64URLToBuffer(c.id) };
          });
        }

        status.textContent = 'WAITING FOR PASSKEY...';
        const credential = await navigator.credentials.get({ publicKey: publicKeyOptions });
        if (!credential) throw new Error('NO CREDENTIAL RETURNED');

        status.textContent = 'VERIFYING...';
        const verifyRes = await fetch('/api/passkey/auth-verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            challenge_id: challenge_id,
            approval_rid: '${rid}',
            credential: {
              id: credential.id,
              rawId: bufferToBase64URL(credential.rawId),
              response: {
                authenticatorData: bufferToBase64URL(credential.response.authenticatorData),
                clientDataJSON: bufferToBase64URL(credential.response.clientDataJSON),
                signature: bufferToBase64URL(credential.response.signature),
                userHandle: credential.response.userHandle ? bufferToBase64URL(credential.response.userHandle) : undefined
              },
              type: credential.type,
              clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {}
            }
          })
        });

        const verifyData = await verifyRes.json();
        if (verifyData.verified) {
          status.textContent = 'AUTHENTICATED. REDIRECTING...';
          setTimeout(function() { window.location.reload(); }, 500);
        } else {
          throw new Error(verifyData.message || verifyData.error || 'VERIFICATION FAILED');
        }
      } catch (e) {
        let errorMsg = e.message || 'UNKNOWN ERROR';
        if (errorMsg.toLowerCase().includes('domain') || errorMsg.toLowerCase().includes('origin') || errorMsg.toLowerCase().includes('rp')) {
          errorMsg = 'DOMAIN MISMATCH: Access via localhost (not 127.0.0.1) for WebAuthn.';
        }
        status.textContent = 'ERROR: ' + errorMsg.toUpperCase();
        status.className = 'status error';
        btn.disabled = false;
      }
    }
  </script>
</body>
</html>
    `);
  }

  // Authenticated — show approval UI
  // Build the APIs section - show checkboxes if allowed_apis is provided
  const hasAllowedApis = pending.policy.allowed_apis && pending.policy.allowed_apis.length > 0;
  let apisHtml = "";
  if (hasAllowedApis) {
    apisHtml = pending.policy.allowed_apis.map((api: any, index: number) => `
      <label class="api-option">
        <input type="checkbox" name="selected_apis" value="${index}" checked>
        <div class="api-card">
          <div class="api-method">${api.method}</div>
          <div class="api-path">${api.path}</div>
          <div class="api-domain">${api.domain}</div>
          ${api.description ? `<div class="api-description">${api.description}</div>` : ''}
        </div>
      </label>
    `).join("");
  }

  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Agent Watchdog - Approve Scoped Access</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
    * { box-sizing: border-box; }
    body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; font-size: 0.9em; max-width: 700px; margin: 40px auto; padding: 20px; background: #0D0D0D; color: #E0E0E0; line-height: 1.6; }
    h1, h2 { font-family: 'Inter', sans-serif; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; margin: 0 0 15px 0; color: #E0E0E0; }
    h1 { font-size: 1.5em; border-bottom: 1px solid #708090; padding-bottom: 10px; }
    h2 { font-size: 1em; margin-top: 25px; padding-bottom: 8px; border-bottom: 1px solid #708090; }
    .divider { border-top: 1px solid #708090; margin: 20px 0; }
    p { margin: 10px 0; color: #E0E0E0; }
    .domain { background: transparent; padding: 10px; margin: 6px 0; border: 1px solid #708090; font-family: 'IBM Plex Mono', monospace; color: #4FD1C5; font-size: 1em; }
    .budget { font-size: 1.15em; font-weight: 600; color: #4FD1C5; font-family: 'IBM Plex Mono', monospace; margin: 8px 0; }
    .buttons { margin-top: 40px; display: flex; gap: 15px; }
    button { padding: 12px 24px; font-size: 0.9em; border: 1px solid; cursor: pointer; font-family: 'Inter', sans-serif; text-transform: uppercase; letter-spacing: 0.05em; transition: border-color 0.2s; flex: 1; }
    .approve { background: #0D0D0D; color: #4FD1C5; border-color: #4FD1C5; }
    .approve:hover { background: rgba(79, 209, 197, 0.1); }
    .deny { background: #0D0D0D; color: #8B0000; border-color: #8B0000; }
    .deny:hover { background: rgba(139, 0, 0, 0.1); }
    .only-way { font-size: 0.85em; color: #708090; margin-top: 15px; font-family: 'IBM Plex Mono', monospace; }
    .authenticated { color: #4FD1C5; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.9em; }
    .mono { font-family: 'IBM Plex Mono', monospace; color: #4FD1C5; }
    strong { text-transform: uppercase; font-size: 0.75em; letter-spacing: 0.05em; color: #708090; font-weight: 600; }
    .summary { font-size: 1.1em; font-weight: 600; color: #E0E0E0; margin: 15px 0; padding: 12px; background: rgba(79, 209, 197, 0.1); border-left: 3px solid #4FD1C5; }
    .description { font-size: 0.95em; color: #E0E0E0; margin: 10px 0 20px 0; line-height: 1.6; white-space: pre-wrap; }
    .description strong { color: #4FD1C5; }
    .description em { color: #E0E0E0; font-style: italic; }
    .budget-edit { margin: 10px 0; }
    .budget-edit label { display: block; margin: 8px 0; }
    .budget-edit label span { display: inline-block; min-width: 100px; color: #708090; }
    .budget-edit input {
      background: #0D0D0D;
      border: 1px solid #708090;
      color: #4FD1C5;
      font-family: 'IBM Plex Mono', monospace;
      padding: 8px 12px;
      font-size: 1em;
      width: 150px;
    }
    .budget-edit input:focus { outline: none; border-color: #4FD1C5; }
    .ttl-hint { color: #708090; font-size: 0.85em; margin-left: 10px; }
    .api-option { display: block; margin: 10px 0; cursor: pointer; }
    .api-option input[type="checkbox"] { display: none; }
    .api-card { 
      display: flex; 
      align-items: center; 
      gap: 12px;
      padding: 12px; 
      margin: 4px 0; 
      border: 1px solid #708090; 
      background: transparent;
      transition: border-color 0.2s, background 0.2s;
    }
    .api-option input[type="checkbox"]:checked + .api-card {
      border-color: #4FD1C5;
      background: rgba(79, 209, 197, 0.05);
    }
    .api-method { 
      background: #708090; 
      color: #0D0D0D; 
      padding: 4px 8px; 
      font-family: 'IBM Plex Mono', monospace; 
      font-size: 0.75em; 
      font-weight: 600;
      min-width: 60px;
      text-align: center;
    }
    .api-option input[type="checkbox"]:checked + .api-card .api-method {
      background: #4FD1C5;
    }
    .api-path { 
      font-family: 'IBM Plex Mono', monospace; 
      color: #E0E0E0; 
      flex: 1;
    }
    .api-domain {
      font-family: 'IBM Plex Mono', monospace;
      color: #4FD1C5;
      font-size: 0.85em;
      font-weight: 500;
    }
    }
    .api-description {
      font-size: 0.8em;
      color: #708090;
      margin-top: 4px;
      width: 100%;
    }
    .api-info { font-size: 0.8em; color: #708090; margin-bottom: 10px; }
  </style>
</head>
<body>
  <h1>APPROVE SCOPED ACCESS REQUEST</h1>
  <div class="divider"></div>
  <p class="authenticated">AUTHENTICATED AS ${authenticatedUser!.email}</p>
  <p class="only-way">THIS PAGE IS THE ONLY WAY TO APPROVE THIS SCOPED ACCESS REQUEST. NO SESSION IS CREATED UNTIL YOU CLICK APPROVE BELOW.</p>
  <p><strong>AGENT:</strong> <span class="mono">${pending.agent_id || "UNKNOWN"}</span></p>

  ${pending.policy.summary ? `<p class="summary">${pending.policy.summary}</p>` : ''}
  ${pending.policy.description ? `<p class="description">${pending.policy.description}</p>` : ''}

  ${hasAllowedApis ? `
  <h2>SELECT APIS TO ALLOW</h2>
  <p class="api-info">Choose one or more APIs the agent can access. All are selected by default.</p>
  <form method="POST" action="/approval/${rid}/approve" onsubmit="return convertBudget(this)">
    ${apisHtml}
    
    <h2 style="margin-top: 25px;">BUDGET (editable)</h2>
    <p class="api-info">Pre-filled with the agent's suggested budget. You can change it.</p>
    <div class="budget-edit">
      <label><span>MAX TOTAL:</span> <input type="number" name="max_total_spend_usd" value="${maxTotalUSD}" step="any" min="0" inputmode="decimal"> USDC</label>
      <label><span>MAX PER TX:</span> <input type="number" name="max_per_tx_usd" value="${maxPerTxUSD}" step="any" min="0" inputmode="decimal"> USDC</label>
    </div>
    
    <h2>DURATION (editable)</h2>
    <div class="budget-edit">
      <label><span>TTL:</span> <input type="number" name="ttl_seconds" value="${pending.policy.ttl_seconds}" step="60" min="60"> seconds</label>
      <span class="ttl-hint">(${Math.floor(pending.policy.ttl_seconds / 3600)}h ${Math.floor((pending.policy.ttl_seconds % 3600) / 60)}m)</span>
    </div>
    
    <div class="buttons">
      <button type="submit" class="approve">APPROVE</button>
    </div>
    ${process.env.DEMO_MODE === "true" ? `<div style="margin-top:20px; padding:15px; background:#1a3a3a; border:1px solid #4FD1C5;"><p style="color:#4FD1C5; margin:0 0 10px;">DEMO MODE - No passkey required</p><a href="/approval/${rid}/demo-approve" style="display:inline-block; padding:10px 20px; background:#4FD1C5; color:#0D0D0D; text-decoration:none; font-weight:600;">AUTO-APPROVE (Demo)</a></div>` : ''}
  </form>
  <form method="POST" action="/approval/${rid}/deny" style="margin-top: 15px;">
    <button type="submit" class="deny">DENY</button>
  </form>
  ` : `
  <h2>BUDGET (editable)</h2>
  <p class="api-info">Pre-filled with the agent's suggested budget. You can change it.</p>
  <div class="budget-edit">
    <form method="POST" action="/approval/${rid}/approve" onsubmit="return convertBudget(this)">
      <label><span>MAX TOTAL:</span> <input type="number" name="max_total_spend_usd" value="${maxTotalUSD}" step="any" min="0" inputmode="decimal"> USDC</label>
      <label><span>MAX PER TX:</span> <input type="number" name="max_per_tx_usd" value="${maxPerTxUSD}" step="any" min="0" inputmode="decimal"> USDC</label>

      <h2>DURATION (editable)</h2>
      <div class="budget-edit">
        <label><span>TTL:</span> <input type="number" name="ttl_seconds" value="${pending.policy.ttl_seconds}" step="60" min="60"> seconds</span></label>
        <span class="ttl-hint">(${Math.floor(pending.policy.ttl_seconds / 3600)}h ${Math.floor((pending.policy.ttl_seconds % 3600) / 60)}m)</span>
      </div>

      <h2>ALLOWED DOMAINS</h2>
      ${pending.policy.allowed_domains.map((d: string) => `<div class="domain">${d}</div>`).join("")}

      <div class="buttons">
        <button type="submit" class="approve">APPROVE</button>
      </div>
    </form>
    <form method="POST" action="/approval/${rid}/deny" style="margin-top: 15px;">
      <button type="submit" class="deny">DENY</button>
    </form>
  `}
  <script>
    var ATOMIC_UNITS = ${ATOMIC_UNITS};
    function usdToAtomic(usd) { return Math.round(Number(usd) * ATOMIC_UNITS); }
    function convertBudget(form) {
      var usdTotal = form.querySelector('input[name="max_total_spend_usd"]');
      var usdPerTx = form.querySelector('input[name="max_per_tx_usd"]');
      if (usdTotal && usdPerTx) {
        var atomicTotal = usdToAtomic(usdTotal.value || 0);
        var atomicPerTx = usdToAtomic(usdPerTx.value || 0);
        var hTotal = form.querySelector('input[name="max_total_spend"]');
        var hPerTx = form.querySelector('input[name="max_per_tx"]');
        if (!hTotal) { hTotal = document.createElement('input'); hTotal.type = 'hidden'; hTotal.name = 'max_total_spend'; form.appendChild(hTotal); }
        if (!hPerTx) { hPerTx = document.createElement('input'); hPerTx.type = 'hidden'; hPerTx.name = 'max_per_tx'; form.appendChild(hPerTx); }
        hTotal.value = String(atomicTotal >= 0 ? atomicTotal : 0);
        hPerTx.value = String(atomicPerTx >= 0 ? atomicPerTx : 0);
      }
      return true;
    }
  </script>
</body>
</html>
  `);
});

// Store pending requests (in-memory for MVP; use DB in production)
const pendingRequests = new Map<
  string,
  {
    agent_id: string | null;
    user_id: string | null;
    policy: any;
    resolve: (result: { status: string; session_handle?: string; reason?: string }) => void;
  }
>();

// Store resolved results temporarily
const resolvedRequests = new Map<
  string,
  { status: string; session_handle?: string; reason?: string }
>();

// Per-delegation passkey authentication (rid -> user_id).
// Every delegation requires a fresh passkey authentication; browser sessions
// are NOT sufficient for approvals.
const approvalAuth = new Map<string, string>();

// Ephemeral WebAuthn challenge storage (challenge_id -> metadata)
const webauthnChallenges = new Map<
  string,
  { challenge: string; userId?: string; type: "register" | "auth"; createdAt: number }
>();

setInterval(() => {
  const cutoff = Date.now() - 5 * 60 * 1000;
  for (const [key, val] of webauthnChallenges) {
    if (val.createdAt < cutoff) webauthnChallenges.delete(key);
  }
}, 60 * 1000);

const PORT = Number(process.env.PORT ?? 4020);
const RP_NAME = "Agent Watchdog";

// Helper to get RP_ID and origin from request
function getRelyingPartyInfo(req: Request): { rpID: string; origin: string } {
  const host = req.headers.host || `localhost:${PORT}`;
  const hostname = host.split(':')[0] || "localhost";
  const origin = `http://${host}`;
  
  // For WebAuthn: RP_ID must match the origin's hostname
  // However, IP addresses (127.0.0.1) are not valid RP_IDs per WebAuthn spec
  // So we normalize 127.0.0.1 to localhost for RP_ID, but keep the actual origin
  // Note: This means users should access via localhost, not 127.0.0.1, for WebAuthn to work
  const rpID = hostname === "127.0.0.1" ? "localhost" : hostname;
  
  return { rpID, origin };
}

// --- Passkey API Endpoints ---

// Get current user info (requires awal authentication)
app.get("/api/user", async (_req: Request, res: Response) => {
  try {
    const walletInfo = await awalAdapter.getWalletInfo();
    if (!walletInfo.authenticated || !walletInfo.email) {
      return res.status(401).json({ error: "wallet_not_authenticated" });
    }
    const user = findOrCreateUserByEmail(walletInfo.email);
    const passkeys = getPasskeyCredentialsByUserId(user.user_id).map((c) => ({
      credential_id: c.credential_id,
      device_name: c.device_name,
      created_at: c.created_at,
    }));
    return res.json({ user_id: user.user_id, email: user.email, passkeys });
  } catch (e) {
    return res.status(500).json({ error: (e as Error).message });
  }
});

// Generate WebAuthn registration challenge (for /account page)
app.post("/api/passkey/register-challenge", async (req: Request, res: Response) => {
  try {
    const walletInfo = await awalAdapter.getWalletInfo();
    if (!walletInfo.authenticated || !walletInfo.email) {
      return res.status(401).json({ error: "wallet_not_authenticated" });
    }

    const user = findOrCreateUserByEmail(walletInfo.email);
    const existingCreds = getPasskeyCredentialsByUserId(user.user_id);
    const { rpID, origin } = getRelyingPartyInfo(req);

    const opts: GenerateRegistrationOptionsOpts = {
      rpName: RP_NAME,
      rpID,
      userName: user.email,
      timeout: 60000,
      attestationType: "none",
      excludeCredentials: existingCreds.map((c) => ({
        id: c.credential_id,
        transports: c.transports ? JSON.parse(c.transports) : undefined,
      })),
      authenticatorSelection: {
        userVerification: "preferred",
        authenticatorAttachment: "platform",
        residentKey: "preferred",
      },
      supportedAlgorithmIDs: [-7, -257],
    };

    const options = await generateRegistrationOptions(opts);
    const challengeId = crypto.randomUUID();
    webauthnChallenges.set(challengeId, {
      challenge: options.challenge,
      userId: user.user_id,
      type: "register",
      createdAt: Date.now(),
    });

    return res.json({ options, challenge_id: challengeId });
  } catch (e) {
    return res.status(500).json({ error: "challenge_failed", message: (e as Error).message });
  }
});

// Verify WebAuthn registration (for /account page)
app.post("/api/passkey/register-verify", async (req: Request, res: Response) => {
  try {
    const { challenge_id, credential, device_name } = req.body;
    const stored = webauthnChallenges.get(challenge_id);
    if (!stored || stored.type !== "register") {
      return res.status(400).json({ error: "no_challenge" });
    }

    const { rpID, origin } = getRelyingPartyInfo(req);

    const verification = await verifyRegistrationResponse({
      response: credential as any,
      expectedChallenge: stored.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: false,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ verified: false, error: "verification_failed" });
    }

    const cred = verification.registrationInfo.credential;
    addPasskeyCredential(
      stored.userId!,
      cred.id,
      Buffer.from(cred.publicKey),
      cred.counter,
      credential.response?.transports,
      device_name
    );

    webauthnChallenges.delete(challenge_id);

    // Create browser session so user is logged in after registration
    const sessionToken = createBrowserSession(stored.userId!);
    setSessionCookie(res, sessionToken);

    return res.json({ verified: true });
  } catch (e) {
    const error = e as Error;
    console.error("Passkey registration error:", error.message);
    return res.status(400).json({ verified: false, error: "verification_error", message: error.message });
  }
});

// Generate WebAuthn authentication challenge (for login)
app.post("/api/passkey/auth-challenge", async (req: Request, res: Response) => {
  try {
    const allCreds = getAllPasskeyCredentials();
    if (allCreds.length === 0) {
      return res.status(404).json({ error: "no_passkeys", message: "No passkeys registered. Set up your account first." });
    }

    const { rpID } = getRelyingPartyInfo(req);

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: allCreds.map((c) => ({
        id: c.credential_id,
        transports: c.transports ? JSON.parse(c.transports) : undefined,
      })),
      userVerification: "preferred",
      timeout: 60000,
    });

    const challengeId = crypto.randomUUID();
    webauthnChallenges.set(challengeId, {
      challenge: options.challenge,
      type: "auth",
      createdAt: Date.now(),
    });

    return res.json({ options, challenge_id: challengeId });
  } catch (e) {
    return res.status(500).json({ error: "challenge_failed", message: (e as Error).message });
  }
});

// Verify WebAuthn authentication assertion (for login and delegation approval)
// When `approval_rid` is provided, this also marks that specific delegation
// request as authenticated (per-delegation auth, not session-based).
app.post("/api/passkey/auth-verify", async (req: Request, res: Response) => {
  try {
    const { challenge_id, credential, approval_rid } = req.body;
    const stored = webauthnChallenges.get(challenge_id);
    if (!stored || stored.type !== "auth") {
      return res.status(400).json({ error: "no_challenge" });
    }

    const credentialId = credential.id;
    const dbCred = getPasskeyCredentialById(credentialId);
    if (!dbCred) {
      return res.status(400).json({ error: "unknown_credential" });
    }

    const { rpID, origin } = getRelyingPartyInfo(req);

    const verification = await verifyAuthenticationResponse({
      response: credential as any,
      expectedChallenge: stored.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: dbCred.credential_id,
        publicKey: new Uint8Array(dbCred.public_key),
        counter: dbCred.counter,
      },
      requireUserVerification: false,
    });

    if (!verification.verified) {
      return res.status(400).json({ verified: false, error: "verification_failed" });
    }

    updatePasskeyCounter(dbCred.credential_id, verification.authenticationInfo.newCounter);
    webauthnChallenges.delete(challenge_id);

    // If this auth is for a specific delegation approval, mark it
    if (typeof approval_rid === "string" && approval_rid) {
      approvalAuth.set(approval_rid, dbCred.user_id);
    }

    // Always create a browser session (useful for /account, /dashboard)
    const sessionToken = createBrowserSession(dbCred.user_id);
    setSessionCookie(res, sessionToken);

    return res.json({ verified: true, user_id: dbCred.user_id });
  } catch (e) {
    const error = e as Error;
    console.error("Passkey auth error:", error.message);
    return res.status(400).json({ verified: false, error: "verification_error", message: error.message });
  }
});

// Remove a passkey (requires active browser session)
app.delete("/api/passkey/:credential_id", (req: Request, res: Response) => {
  const user = getSessionUser(req);
  if (!user) {
    return res.status(401).json({ error: "not_authenticated" });
  }

  const credId = String(req.params.credential_id ?? "");
  const cred = getPasskeyCredentialById(credId);
  if (!cred || cred.user_id !== user.user_id) {
    return res.status(404).json({ error: "not_found" });
  }

  const remaining = getPasskeyCredentialsByUserId(user.user_id);
  if (remaining.length <= 1) {
    return res.status(400).json({ error: "cannot_remove_last", message: "Cannot remove your only passkey." });
  }

  deletePasskeyCredential(credId);
  return res.json({ success: true });
});

// Logout (clear browser session)
app.post("/api/logout", (req: Request, res: Response) => {
  const cookies = parseCookies(req);
  const token = cookies["portal_session"];
  if (token) {
    deleteBrowserSession(token);
  }
  clearSessionCookie(res);
  return res.json({ success: true });
});

// Check status of a pending scoped-access request
app.get("/request-scoped-access/:request_id", (req: Request, res: Response) => {
  const rid = String(req.params.request_id ?? "");
  const resolved = resolvedRequests.get(rid);
  if (resolved) {
    return res.json(resolved);
  }
  const pending = pendingRequests.get(rid);
  if (pending) {
    return res.json({ status: "pending" });
  }
  return res.status(404).json({ error: "not_found" });
});

// Backing scoped-access request (formerly request_delegation(policy)) – creates pending request, returns approval URL
app.post("/request-scoped-access", (req: Request, res: Response) => {
  const { policy, agent_id, user_id } = req.body ?? {};
  if (!policy || !Array.isArray(policy.allowed_domains)) {
    return res
      .status(400)
      .json({ error: "bad_request", message: "invalid policy" });
  }

  // Validate allowed_apis if provided
  if (policy.allowed_apis !== undefined) {
    if (!Array.isArray(policy.allowed_apis)) {
      return res
        .status(400)
        .json({ error: "bad_request", message: "allowed_apis must be an array" });
    }
    for (const api of policy.allowed_apis) {
      if (!api.domain || !api.path || !api.method) {
        return res
          .status(400)
          .json({ error: "bad_request", message: "each allowed_api must have domain, path, and method" });
      }
    }
  }

  // Validate optional summary and description
  if (policy.summary !== undefined && typeof policy.summary !== "string") {
    return res
      .status(400)
      .json({ error: "bad_request", message: "summary must be a string" });
  }
  if (policy.description !== undefined && typeof policy.description !== "string") {
    return res
      .status(400)
      .json({ error: "bad_request", message: "description must be a string" });
  }

  const requestId = crypto.randomUUID();
  // Approval URL: use PUBLIC_BASE_URL when set (e.g. deployed on Render) so the link works when opened from any machine; else derive from Host; fallback to localhost for local dev.
  const baseUrl =
    process.env.PUBLIC_BASE_URL ||
    (req.headers.host ? `http://${req.headers.host}` : `http://localhost:${PORT}`);
  const approvalUrl = `${baseUrl.replace(/\/$/, "")}/approval/${requestId}`;

  // Create a promise that will resolve when user approves/denies
  const promise = new Promise<{
    status: string;
    session_handle?: string;
    reason?: string;
  }>((resolve) => {
    pendingRequests.set(requestId, {
      agent_id: agent_id ?? null,
      user_id: user_id ?? null,
      policy,
      resolve,
    });
  });

  // Return immediately with approval URL and request_id for polling
  return res.json({
    status: "pending",
    request_id: requestId,
    approval_url: approvalUrl,
    message: "User approval required. Open the approval_url in a browser, then poll /request-scoped-access/:request_id for result.",
  });
});

// Handle approve action
app.post("/approval/:request_id/approve", (req: Request, res: Response) => {
  const rid = String(req.params.request_id ?? "");
  const pending = pendingRequests.get(rid);
  if (!pending) {
    return res.status(404).send("Request not found or already processed");
  }

  const authenticatedUserId = approvalAuth.get(rid);
  // Demo bypass: if DEMO_MODE env is set, auto-approve for demo user
  const isDemoMode = process.env.DEMO_MODE === "true";
  const demoUserId = "demo-user";
  if (isDemoMode && !authenticatedUserId) {
    // Auto-approve for demo
    pendingRequests.delete(rid);
    approvalAuth.delete(rid);
    const sessionHandle = crypto.randomUUID();
    return res.redirect(`/approval/${rid}/approved?session=${sessionHandle}&user=${demoUserId}`);
  }
  if (!authenticatedUserId) {
    return res.status(403).send(`
<!DOCTYPE html>
<html>
<head>
  <title>Agent Watchdog - Authentication Required</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
    * { box-sizing: border-box; }
    body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; font-size: 0.9em; max-width: 600px; margin: 40px auto; padding: 20px; background: #0D0D0D; color: #E0E0E0; line-height: 1.6; }
    h1 { font-size: 1.5em; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; margin: 0 0 20px 0; border-bottom: 1px solid #708090; padding-bottom: 10px; }
    .error { color: #8B0000; font-family: 'IBM Plex Mono', monospace; font-size: 0.9em; margin: 20px 0; }
    a { color: #4FD1C5; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .divider { border-top: 1px solid #708090; margin: 20px 0; }
  </style>
</head>
<body>
  <h1>AUTHENTICATION REQUIRED FOR SCOPED ACCESS</h1>
  <div class="divider"></div>
  <p class="error">YOU MUST AUTHENTICATE WITH PASSKEY BEFORE APPROVING THIS SCOPED ACCESS REQUEST.</p>
  <p><a href="/approval/${rid}">GO BACK TO AUTHENTICATION</a></p>
</body>
</html>
    `);
  }

  // If allowed_apis was provided and user selected some, extract them
  let finalPolicy = { ...pending.policy };
  
  // Handle editable budget and duration fields
  if (req.body.max_total_spend !== undefined) {
    const parsed = parseInt(req.body.max_total_spend, 10);
    if (!isNaN(parsed) && parsed >= 0) {
      finalPolicy.max_total_spend = parsed;
    }
  }
  if (req.body.max_per_tx !== undefined) {
    const parsed = parseInt(req.body.max_per_tx, 10);
    if (!isNaN(parsed) && parsed >= 0) {
      finalPolicy.max_per_tx = parsed;
    }
  }
  if (req.body.ttl_seconds !== undefined) {
    const parsed = parseInt(req.body.ttl_seconds, 10);
    if (!isNaN(parsed) && parsed >= 60) {
      finalPolicy.ttl_seconds = parsed;
    }
  }

  // Handle selected APIs
  if (pending.policy.allowed_apis && pending.policy.allowed_apis.length > 0) {
    const selectedApisRaw = req.body.selected_apis;
    let selectedIndices: number[] = [];

    if (Array.isArray(selectedApisRaw)) {
      selectedIndices = selectedApisRaw.map((v: string) => parseInt(v, 10)).filter((v: number) => !isNaN(v));
    } else if (selectedApisRaw !== undefined) {
      // Single value (if only one checkbox was checked)
      const parsed = parseInt(selectedApisRaw, 10);
      if (!isNaN(parsed)) {
        selectedIndices = [parsed];
      }
    }

    // Filter to only valid indices
    const selectedApis = selectedIndices
      .filter((idx: number) => pending.policy.allowed_apis[idx])
      .map((idx: number) => pending.policy.allowed_apis[idx]);

    if (selectedApis.length > 0) {
      finalPolicy.allowed_apis = selectedApis;
    }
  }

  // Use the per-delegation authenticated user's ID for the delegation session
  const result = createDelegationSession(
    pending.agent_id,
    authenticatedUserId,
    finalPolicy
  );

  const resolved = {
    status: "approved" as const,
    session_handle: result.session_handle,
  };
  pending.resolve(resolved);
  resolvedRequests.set(rid, resolved);
  pendingRequests.delete(rid);
  approvalAuth.delete(rid);

  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Agent Watchdog - Access Approved</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
    * { box-sizing: border-box; }
    body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; font-size: 0.9em; max-width: 600px; margin: 40px auto; padding: 20px; background: #0D0D0D; color: #E0E0E0; line-height: 1.6; }
    h1 { font-family: 'Inter', sans-serif; font-size: 1.5em; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; margin: 0 0 20px 0; color: #E0E0E0; border-bottom: 1px solid #708090; padding-bottom: 10px; }
    .success { color: #4FD1C5; font-size: 1em; margin: 20px 0; font-family: 'IBM Plex Mono', monospace; }
    p {
      color: #708090;
      margin: 10px 0;
    }
    .divider {
      border-top: 1px solid #708090;
      margin: 20px 0;
      height: 0;
    }
  </style>
</head>
<body>
  <h1>SCOPED ACCESS APPROVED</h1>
  <div class="divider"></div>
  <p class="success">SCOPED ACCESS SESSION CREATED: ${result.session_handle}</p>
  <p>YOU CAN CLOSE THIS WINDOW.</p>
</body>
</html>
  `);
});

// Demo approve - bypass passkey (only works when DEMO_MODE=true)
app.get("/approval/:request_id/demo-approve", (req: Request, res: Response) => {
  if (process.env.DEMO_MODE !== "true") {
    return res.status(403).send("Demo mode not enabled");
  }
  const rid = String(req.params.request_id ?? "");
  const pending = pendingRequests.get(rid);
  if (!pending) {
    return res.status(404).send("Request not found or already processed");
  }
  pendingRequests.delete(rid);
  approvalAuth.delete(rid);
  const sessionHandle = crypto.randomUUID();
  res.redirect(`/approval/${rid}/approved?session=${sessionHandle}&user=demo`);
});

// Handle deny action
app.post("/approval/:request_id/deny", (req: Request, res: Response) => {
  const rid = String(req.params.request_id ?? "");
  const pending = pendingRequests.get(rid);
  if (!pending) {
    return res.status(404).send("Request not found or already processed");
  }

  const resolved = {
    status: "denied" as const,
    reason: "User declined",
  };
  pending.resolve(resolved);
  resolvedRequests.set(rid, resolved);
  pendingRequests.delete(rid);
  approvalAuth.delete(rid);

  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Agent Watchdog - Access Denied</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
    * { box-sizing: border-box; }
    body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; font-size: 0.9em; max-width: 600px; margin: 40px auto; padding: 20px; background: #0D0D0D; color: #E0E0E0; line-height: 1.6; }
    h1 { font-family: 'Inter', sans-serif; font-size: 1.5em; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; margin: 0 0 20px 0; color: #8B0000; border-bottom: 1px solid #708090; padding-bottom: 10px; }
    p {
      color: #708090;
      margin: 10px 0;
    }
    .divider {
      border-top: 1px solid #708090;
      margin: 20px 0;
      height: 0;
    }
  </style>
</head>
<body>
  <h1>SCOPED ACCESS DENIED</h1>
  <div class="divider"></div>
  <p>YOU CAN CLOSE THIS WINDOW.</p>
</body>
</html>
  `);
});

// Backing x402_request(session_handle, url, ...)
// HMAC is required: only a caller that knows LOCAL_PORTAL_SHARED_SECRET can invoke /execute.
// The agent should obtain the passphrase from the user (e.g. prompt once) so the user only holds one secret.
app.post("/execute", async (req: Request, res: Response) => {
  const signature = req.headers["x-local-portal-signature"];
  if (!hmacValid(req.body, typeof signature === "string" ? signature : undefined)) {
    return res.status(401).json({ error: "unauthorized" });
  }

  const { session_handle, operation, params, counter, idempotency_key } = req.body ?? {};
  if (!session_handle || operation !== "x402_request" || !params?.url) {
    return res.status(400).json({ error: "bad_request" });
  }

  const session = getSession(session_handle);
  if (!session) {
    return res.status(403).json({ error: "no_session", message: "Unknown session_handle" });
  }

  // Extract path and method from the URL
  let requestPath = "/";
  let requestMethod = "GET";
  try {
    const url = new URL(params.url);
    requestPath = url.pathname;
    requestMethod = params.method || "GET";
  } catch (e) {
    // If URL parsing fails, use the path from params if provided
    requestPath = params.path || "/";
    requestMethod = params.method || "GET";
  }

  // Check policy before executing
  const domain = (() => {
    try {
      return new URL(params.url).hostname;
    } catch {
      return "";
    }
  })();

  // Build policy check input - amountAtomic will be checked after x402 response
  const policyCheckInput: {
    session: typeof session;
    domain: string;
    path: string;
    method: string;
  } = {
    session,
    domain,
    path: requestPath,
    method: requestMethod,
  };

  const policyCheck = checkPolicy(policyCheckInput);

  if (policyCheck.decision === "DENY") {
    return res.status(403).json({
      error: "policy_denied",
      deny_code: policyCheck.deny_code,
      message: `Request denied: ${policyCheck.deny_code}`,
    });
  }

  if (typeof counter !== "number" || counter <= session.last_counter) {
    return res.status(409).json({ error: "replay", message: "Non-monotonic counter" });
  }

  // Log Local_API_Requests row (for forensics).
  const requestId = crypto.randomUUID();
  const now = Date.now();
  const paramsHash = crypto
    .createHash("sha256")
    .update(JSON.stringify(params))
    .digest("hex");

  db.prepare(
    `INSERT INTO Local_API_Requests (
       request_id, session_id, operation,
       params_hash, auth_valid, counter, ip, created_at
     ) VALUES (
       @request_id, @session_id, @operation,
       @params_hash, @auth_valid, @counter, @ip, @created_at
     )`
  ).run({
    request_id: requestId,
    session_id: session.session_id,
    operation,
    params_hash: paramsHash,
    auth_valid: 1,
    counter,
    ip: req.ip,
    created_at: now,
  });

  let result;
  try {
    result = await handleX402Request(session, {
      url: params.url,
      method: params.method,
      headers: params.headers,
      body: params.body,
    });
  } catch (e) {
    const msg = (e as Error).message || "";
    if (msg.includes("not authenticated") || msg.includes("Wallet not authenticated")) {
      return res.status(503).json({
        error: "wallet_not_authenticated",
        message: "Wallet is not authenticated. Ask the user to run 'npx awal@latest status' and sign in, then retry.",
      });
    }
    throw e;
  }

  updateLastCounter(session.session_id, counter);

  // Log transaction when payment succeeded (settlement_proof.success).
  // Use expected_amount_atomic as the spent amount when settlement succeeded.
  const settlementProof = result.metadata.settlement_proof;
  const expectedAmount = result.metadata.expected_amount_atomic ?? 0;
  const spentAtomic = settlementProof?.success ? expectedAmount : 0;

  if (result.metadata.x402_paid) {
    if (spentAtomic > 0) {
      addSpentAtomic(session.session_id, spentAtomic);
    }

    const txId = crypto.randomUUID();
    const domain = new URL(params.url).hostname;
    db.prepare(
      `INSERT INTO Transaction_Logs (
         tx_id, session_id, operation, amount,
         recipient, domain, api_path, method, decision, deny_code,
         counter, idempotency_key, http_402_proof_hash,
         tx_hash, network, created_at
       ) VALUES (
         @tx_id, @session_id, @operation, @amount,
         @recipient, @domain, @api_path, @method, @decision, @deny_code,
         @counter, @idempotency_key, @http_402_proof_hash,
         @tx_hash, @network, @created_at
       )`
    ).run({
      tx_id: txId,
      session_id: session.session_id,
      operation,
      amount: String(spentAtomic),
      recipient: settlementProof?.payer ?? "",
      domain,
      api_path: requestPath,
      method: requestMethod,
      decision: settlementProof?.success ? "APPROVED" : "DENIED",
      deny_code: null,
      counter,
      idempotency_key,
      http_402_proof_hash: null,
      tx_hash: settlementProof?.transaction ?? null,
      network: settlementProof?.network ?? null,
      created_at: now,
    });
  }

  return res.status(result.status).json({
    status: result.status,
    headers: result.headers,
    body: result.body,
    metadata: result.metadata,
    idempotency_key,
  });
});

// CLI execution entrypoint for Scoped Access grants.
// Evaluates the command against the grant's CLI capabilities (commands_allow + TTL)
// and, if allowed, executes it locally and returns stdout/stderr/exit_code.
app.post("/cmd/execute", async (req: Request, res: Response) => {
  const { session_handle, command, cwd, timeout_ms } = req.body ?? {};

  if (typeof session_handle !== "string" || !session_handle.trim()) {
    return res.status(400).json({
      allowed: false,
      stdout: "",
      stderr: "Missing session_handle",
      exit_code: null,
      reason: "bad_request",
    });
  }

  if (typeof command !== "string" || !command.trim()) {
    return res.status(400).json({
      allowed: false,
      stdout: "",
      stderr: "Missing command",
      exit_code: null,
      reason: "bad_request",
      grant_id: session_handle,
    });
  }

  const session = getSession(session_handle);
  if (!session) {
    return res.status(403).json({
      allowed: false,
      stdout: "",
      stderr: "Unknown session_handle",
      exit_code: null,
      reason: "no_session",
      grant_id: session_handle,
    });
  }

  const now = Date.now();
  if (session.revoked_at || session.expires_at <= now) {
    return res.status(403).json({
      allowed: false,
      stdout: "",
      stderr: "Scoped Access grant expired or revoked",
      exit_code: null,
      reason: "grant_expired",
      grant_id: session.session_id,
    });
  }

  const capabilities = (session.capabilities || {}) as GrantCapabilities;
  const cliCaps = capabilities.cli || {};
  const allowedCommands = cliCaps.commands_allow || [];

  const trimmedCommand = command.trim();
  const isAllowed =
    allowedCommands.length > 0 &&
    allowedCommands.some((pattern) => {
      const p = pattern.trim();
      return p.length > 0 && trimmedCommand.startsWith(p);
    });

  if (!isAllowed) {
    return res.status(403).json({
      allowed: false,
      stdout: "",
      stderr: "Command not allowed by Scoped Access grant (cli.commands_allow)",
      exit_code: null,
      reason: "command_not_allowed",
      grant_id: session.session_id,
    });
  }

  const execCwd =
    typeof cwd === "string" && cwd.trim().length > 0 ? cwd : process.cwd();
  const timeout =
    typeof timeout_ms === "number" && timeout_ms > 0 ? timeout_ms : 30000;

  exec(
    trimmedCommand,
    {
      cwd: execCwd,
      timeout,
      maxBuffer: 1024 * 1024,
    },
    (error, stdout, stderr) => {
      const exitCode =
        error && typeof (error as any).code === "number"
          ? (error as any).code
          : 0;

      const allowed = !error || exitCode === 0;

      return res.status(allowed ? 200 : 500).json({
        allowed,
        stdout,
        stderr: stderr || (error ? String(error) : ""),
        exit_code: exitCode,
        reason: allowed ? undefined : "command_failed",
        grant_id: session.session_id,
      });
    }
  );
});

// Dashboard API endpoints

// Get wallet info (account, address, balances)
app.get("/api/wallet", async (_req: Request, res: Response) => {
  try {
    const walletInfo = await awalAdapter.getWalletInfo();
    return res.json(walletInfo);
  } catch (e) {
    return res.status(500).json({
      authenticated: false,
      error: (e as Error).message,
    });
  }
});

// List scoped-access sessions (grants)
app.get("/api/scoped-access", (req: Request, res: Response) => {
  try {
    const activeOnly = req.query.active_only === "true";
    const sessions = listSessions(activeOnly);
    const now = Date.now();
    
    const result = sessions.map((session) => {
      const isActive = !session.revoked_at && session.expires_at > now;
      const ttlRemaining = Math.max(0, Math.floor((session.expires_at - now) / 1000));
      
      // Calculate created_at from expires_at and ttl_seconds if not present
      const created_at = (session as any).created_at ?? (session.expires_at - session.ttl_seconds * 1000);
      
      return {
        session_id: session.session_id,
        agent_id: session.agent_id,
        user_id: session.user_id,
        allowed_domains: session.allowed_domains,
        allowed_apis: session.allowed_apis,
        summary: session.summary,
        description: session.description,
        max_total_spend: session.max_total_spend,
        max_per_tx: session.max_per_tx,
        total_spent_atomic: session.total_spent_atomic,
        ttl_seconds: session.ttl_seconds,
        ttl_remaining_seconds: ttlRemaining,
        expires_at: session.expires_at,
        created_at: created_at,
        is_active: isActive,
        last_counter: session.last_counter,
        revoked_at: session.revoked_at,
      };
    });
    
    return res.json(result);
  } catch (e) {
    return res.status(500).json({ error: (e as Error).message });
  }
});

// List transactions
app.get("/api/transactions", (req: Request, res: Response) => {
  try {
    const sessionIdParam = req.query.session_id;
    const sessionId = typeof sessionIdParam === "string" ? sessionIdParam : undefined;
    const limitParam = req.query.limit;
    const limit = parseInt(typeof limitParam === "string" ? limitParam : "100", 10);
    
    let query = `
      SELECT t.tx_id, t.session_id, t.operation, t.amount, t.recipient, t.domain,
             t.api_path, t.method, t.decision, t.deny_code, t.counter, t.idempotency_key,
             t.http_402_proof_hash, t.tx_hash, t.network, t.created_at,
             d.agent_id
      FROM Transaction_Logs t
      LEFT JOIN Delegation_Sessions d ON t.session_id = d.session_id
    `;
    
    const params: Record<string, any> = {};
    if (sessionId) {
      query += ` WHERE t.session_id = @session_id`;
      params.session_id = sessionId;
    }
    
    query += ` ORDER BY t.created_at DESC LIMIT @limit`;
    params.limit = limit;
    
    const rows = db.prepare(query).all(params) as Array<{
      tx_id: string;
      session_id: string;
      operation: string;
      amount: string;
      recipient: string;
      domain: string;
      decision: string;
      deny_code: string | null;
      counter: number;
      idempotency_key: string;
      http_402_proof_hash: string | null;
      tx_hash: string | null;
      network: string | null;
      created_at: number;
      agent_id: string | null;
    }>;
    
    return res.json(rows);
  } catch (e) {
    return res.status(500).json({ error: (e as Error).message });
  }
});

// Revoke a scoped-access session (grant)
app.post("/api/scoped-access/:session_id/revoke", (req: Request, res: Response) => {
  try {
    const sessionIdParam = req.params.session_id;
    const sessionId = typeof sessionIdParam === "string" ? sessionIdParam : String(sessionIdParam?.[0] || "");
    if (!sessionId) {
      return res.status(400).json({ error: "Invalid session_id" });
    }
    const reason = (req.body as { reason?: string })?.reason;
    
    const session = getSession(sessionId);
    if (!session) {
      return res.status(404).json({ error: "Session not found" });
    }
    
    if (session.revoked_at) {
      return res.status(400).json({ error: "Session already revoked" });
    }
    
    revokeSession(sessionId, reason);
    
    return res.json({
      success: true,
      session_id: sessionId,
      revoked_at: Date.now(),
    });
  } catch (e) {
    return res.status(500).json({ error: (e as Error).message });
  }
});

// ============================================================
// Watchdog-Lite API (PID tracking + command blocking for macOS)
// ============================================================

app.post("/api/watchdog/register-pid", (req: Request, res: Response) => {
  const { name, pid } = req.body as { name?: string; pid?: number };
  if (!name || !pid || !["cursor", "pulse"].includes(name)) {
    return res.status(400).json({ error: "name (cursor|pulse) and pid are required" });
  }
  const entry = registerPid(name as PidSetName, pid);
  return res.json({ ok: true, ...entry });
});

app.get("/api/watchdog/pid-sets", (_req: Request, res: Response) => {
  return res.json(getPidSets());
});

app.delete("/api/watchdog/register-pid/:name", (req: Request, res: Response) => {
  const name = String(req.params.name ?? "");
  if (!["cursor", "pulse"].includes(name)) {
    return res.status(400).json({ error: "Invalid pid set name" });
  }
  const removed = unregisterPid(name as PidSetName);
  return res.json({ ok: removed });
});

app.post("/api/watchdog/events", (req: Request, res: Response) => {
  const body = req.body as {
    type?: string;
    pid?: number;
    ppid?: number;
    command?: string;
    args?: string[];
    source_pid_set?: string;
    detail?: string;
  };
  if (!body.type || body.pid === undefined) {
    return res.status(400).json({ error: "type and pid are required" });
  }
  const event = addEvent({
    type: body.type as any,
    pid: body.pid,
    ppid: body.ppid ?? 0,
    command: body.command ?? "",
    args: body.args ?? [],
    source_pid_set: (body.source_pid_set as PidSetName) ?? "unknown",
    detail: body.detail ?? "",
  });
  return res.json(event);
});

app.get("/api/watchdog/events", (req: Request, res: Response) => {
  const type = req.query.type as string | undefined;
  const source = req.query.source as string | undefined;
  const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 100;
  const sinceVal = req.query.since ? parseInt(req.query.since as string, 10) : undefined;
  const opts: Parameters<typeof getEvents>[0] = { type: type as any, source: source as any, limit };
  if (sinceVal !== undefined) opts!.since = sinceVal;
  const events = getEvents(opts);
  return res.json(events);
});

app.post("/api/watchdog/events/:id/dismiss", (req: Request, res: Response) => {
  const id = String(req.params.id ?? "");
  const ok = dismissEvent(id);
  return res.json({ ok });
});

app.get("/api/watchdog/stats", (_req: Request, res: Response) => {
  return res.json(getWatchdogStats());
});

app.post("/api/watchdog/auto-detect-cursor", (_req: Request, res: Response) => {
  const pid = autoDetectCursorPid();
  if (pid) {
    const entry = registerPid("cursor", pid);
    return res.json({ ok: true, detected: true, ...entry });
  }
  return res.json({ ok: false, detected: false, message: "Cursor process not found" });
});

// Account page — manage passkeys and view wallet connection
app.get("/account", async (req: Request, res: Response) => {
  // Redirect 127.0.0.1 to localhost for WebAuthn
  const host = req.headers.host || "";
  if (host.startsWith("127.0.0.1:")) {
    const port = host.split(":")[1] || PORT.toString();
    return res.redirect(`http://localhost:${port}/account`);
  }

  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Agent Watchdog - Account</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

    * { box-sizing: border-box; }
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 0.9em;
      max-width: 800px;
      margin: 0 auto;
      padding: 40px 20px;
      background: #0D0D0D;
      color: #E0E0E0;
      line-height: 1.6;
    }
    h1, h2 {
      font-family: 'Inter', sans-serif;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      font-weight: 600;
      margin: 0 0 20px 0;
      color: #E0E0E0;
    }
    h1 { font-size: 1.5em; border-bottom: 1px solid #708090; padding-bottom: 10px; }
    h2 { font-size: 1em; }
    .panel {
      background: #0D0D0D;
      border: 1px solid #708090;
      padding: 20px;
      margin: 30px 0;
      overflow-x: auto;
    }
    .panel h2 {
      margin-top: 0;
      margin-bottom: 15px;
      padding-bottom: 10px;
      border-bottom: 1px solid #708090;
    }
    .divider { border-top: 1px solid #708090; margin: 20px 0; }
    p { margin: 8px 0; }
    strong {
      text-transform: uppercase;
      font-size: 0.75em;
      letter-spacing: 0.05em;
      color: #708090;
      display: block;
      margin-bottom: 4px;
    }
    .mono {
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.9em;
      color: #4FD1C5;
    }
    .badge {
      padding: 3px 8px;
      font-size: 0.75em;
      display: inline-block;
      border: 1px solid;
      font-family: 'IBM Plex Mono', monospace;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge-ok { color: #4FD1C5; border-color: #4FD1C5; }
    .badge-warn { color: #8B0000; border-color: #8B0000; }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 15px;
      font-size: 0.9em;
    }
    th, td {
      padding: 12px 10px;
      text-align: left;
      border-bottom: 1px solid #708090;
      word-break: break-word;
    }
    th {
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.75em;
      letter-spacing: 0.05em;
      color: #708090;
      font-family: 'Inter', sans-serif;
    }
    td { color: #E0E0E0; font-family: 'Inter', sans-serif; }
    button {
      padding: 10px 20px;
      font-size: 0.85em;
      border: 1px solid #708090;
      cursor: pointer;
      background: #0D0D0D;
      color: #E0E0E0;
      font-family: 'Inter', sans-serif;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      transition: border-color 0.2s;
    }
    button:hover { border-color: #4FD1C5; color: #4FD1C5; }
    button:disabled { opacity: 0.5; cursor: not-allowed; border-color: #708090; color: #708090; }
    button.danger { border-color: #8B0000; color: #8B0000; }
    button.danger:hover { background: rgba(139, 0, 0, 0.1); }
    button.small { padding: 4px 10px; font-size: 0.75em; }
    .status { margin: 15px 0; color: #708090; font-family: 'IBM Plex Mono', monospace; font-size: 0.85em; }
    .error { color: #8B0000; font-family: 'IBM Plex Mono', monospace; }
    a { color: #4FD1C5; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .nav { margin-bottom: 20px; font-size: 0.85em; }
    .hidden { display: none; }
    .top-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid #708090;
    }
    .top-bar .nav-links {
      display: flex;
      align-items: center;
      gap: 20px;
      font-size: 0.9em;
    }
    .top-bar .nav-links a {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: #E0E0E0;
      text-decoration: none;
      padding: 8px 12px;
      border: 1px solid transparent;
      border-radius: 0;
    }
    .top-bar .nav-links a:hover {
      border-color: #4FD1C5;
      color: #4FD1C5;
      text-decoration: none;
    }
    .top-bar .nav-links a svg {
      width: 18px;
      height: 18px;
      flex-shrink: 0;
    }
  </style>
</head>
<body>
  <div class="top-bar">
    <h1 style="margin:0; border:0; padding:0; font-size:1.5em;">ACCOUNT</h1>
    <nav class="nav-links">
      <a href="/account" title="Account – passkeys and wallet">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        Account
      </a>
      <a href="/dashboard" title="Dashboard">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/></svg>
        Dashboard
      </a>
    </nav>
  </div>

  <div class="panel">
    <h2>WALLET CONNECTION</h2>
    <div id="wallet-status"><div class="status">CHECKING WALLET...</div></div>
  </div>

  <div class="panel" id="passkey-panel" class="hidden">
    <h2>PASSKEYS</h2>
    <div id="passkey-list"><div class="status">LOADING...</div></div>
    <div style="margin-top: 20px;">
      <button id="register-btn" onclick="registerPasskey()" disabled>REGISTER NEW PASSKEY</button>
    </div>
    <div id="register-status" class="status"></div>
  </div>

  <div class="panel" id="session-panel">
    <h2>SESSION</h2>
    <div id="session-info"></div>
  </div>

  <script>
    function bufferToBase64URL(buffer) {
      const bytes = new Uint8Array(buffer);
      let str = '';
      for (const b of bytes) str += String.fromCharCode(b);
      return btoa(str).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
    }

    function base64URLToBuffer(b64url) {
      const base64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes.buffer;
    }

    let currentUser = null;

    async function loadAccount() {
      const walletEl = document.getElementById('wallet-status');
      const passkeyPanel = document.getElementById('passkey-panel');
      const registerBtn = document.getElementById('register-btn');

      try {
        const res = await fetch('/api/user');
        if (res.status === 401) {
          walletEl.innerHTML = '<p class="error">WALLET NOT AUTHENTICATED</p><p style="color:#708090;">Authenticate your agentic wallet first:</p><p><span class="mono">npx awal@latest status</span></p><button onclick="loadAccount()" style="margin-top:10px;">CHECK AGAIN</button>';
          passkeyPanel.classList.add('hidden');
          return;
        }
        const data = await res.json();
        currentUser = data;
        walletEl.innerHTML = '<p><strong>EMAIL</strong><span class="mono">' + data.email + '</span></p><p><span class="badge badge-ok">CONNECTED</span></p>';
        passkeyPanel.classList.remove('hidden');
        registerBtn.disabled = false;
        renderPasskeys(data.passkeys);
      } catch (e) {
        walletEl.innerHTML = '<p class="error">ERROR: ' + e.message + '</p>';
      }

      updateSessionInfo();
    }

    function renderPasskeys(passkeys) {
      const el = document.getElementById('passkey-list');
      if (!passkeys || passkeys.length === 0) {
        el.innerHTML = '<p style="color:#708090;">NO PASSKEYS REGISTERED. Register one below to enable delegation approval.</p>';
        return;
      }
      el.innerHTML = '<table><thead><tr><th>DEVICE</th><th>CREDENTIAL ID</th><th>REGISTERED</th><th>ACTIONS</th></tr></thead><tbody>' +
        passkeys.map(function(p) {
          return '<tr><td><span class="mono">' + (p.device_name || 'Unnamed') + '</span></td>' +
            '<td><span class="mono">' + p.credential_id.slice(0, 16) + '...</span></td>' +
            '<td><span class="mono">' + new Date(p.created_at).toLocaleDateString() + '</span></td>' +
            '<td><button class="danger small" onclick="removePasskey(\\'' + p.credential_id + '\\')">REMOVE</button></td></tr>';
        }).join('') +
        '</tbody></table>';
    }

    async function registerPasskey() {
      const btn = document.getElementById('register-btn');
      const status = document.getElementById('register-status');
      btn.disabled = true;
      status.textContent = 'REQUESTING CHALLENGE...';
      status.className = 'status';

      try {
        const challengeRes = await fetch('/api/passkey/register-challenge', { method: 'POST' });
        if (!challengeRes.ok) throw new Error('FAILED TO GET CHALLENGE');
        const { options, challenge_id } = await challengeRes.json();

        const publicKeyOptions = {
          ...options,
          challenge: base64URLToBuffer(options.challenge),
          user: { ...options.user, id: base64URLToBuffer(options.user.id) }
        };
        if (options.excludeCredentials) {
          publicKeyOptions.excludeCredentials = options.excludeCredentials.map(function(c) {
            return { ...c, id: base64URLToBuffer(c.id) };
          });
        }

        status.textContent = 'CREATING PASSKEY...';
        const credential = await navigator.credentials.create({ publicKey: publicKeyOptions });
        if (!credential) throw new Error('NO CREDENTIAL RETURNED');

        status.textContent = 'VERIFYING...';
        const verifyRes = await fetch('/api/passkey/register-verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            challenge_id: challenge_id,
            credential: {
              id: credential.id,
              rawId: bufferToBase64URL(credential.rawId),
              response: {
                attestationObject: bufferToBase64URL(credential.response.attestationObject),
                clientDataJSON: bufferToBase64URL(credential.response.clientDataJSON),
                transports: credential.response.getTransports ? credential.response.getTransports() : undefined
              },
              type: credential.type,
              clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {}
            },
            device_name: navigator.platform || 'Unknown Device'
          })
        });

        const verifyData = await verifyRes.json();
        if (verifyData.verified) {
          status.textContent = 'PASSKEY REGISTERED SUCCESSFULLY.';
          loadAccount();
        } else {
          throw new Error(verifyData.message || verifyData.error || 'REGISTRATION FAILED');
        }
      } catch (e) {
        status.textContent = 'ERROR: ' + (e.message || 'UNKNOWN').toUpperCase();
        status.className = 'status error';
        btn.disabled = false;
      }
    }

    async function removePasskey(credId) {
      if (!confirm('REMOVE THIS PASSKEY?')) return;
      try {
        const res = await fetch('/api/passkey/' + encodeURIComponent(credId), { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
          loadAccount();
        } else {
          alert('ERROR: ' + (data.message || data.error || 'UNKNOWN'));
        }
      } catch (e) {
        alert('ERROR: ' + e.message);
      }
    }

    function updateSessionInfo() {
      const el = document.getElementById('session-info');
      const user = currentUser;
      if (user) {
        el.innerHTML = '<p><strong>LOGGED IN AS</strong><span class="mono">' + user.email + '</span></p>' +
          '<button onclick="logout()" style="margin-top:10px;">SIGN OUT</button>';
      } else {
        el.innerHTML = '<p style="color:#708090;">NOT LOGGED IN</p>';
      }
    }

    async function logout() {
      await fetch('/api/logout', { method: 'POST' });
      window.location.reload();
    }

    loadAccount();
  </script>
</body>
</html>
  `);
});

// Dashboard HTML page
app.get("/delegation/:session_id", (req: Request, res: Response) => {
  const sessionId = req.params.session_id as string | undefined;
  if (!sessionId) {
    return res.status(400).send("Missing session_id");
  }
  const session = getSession(sessionId);
  if (!session) {
    return res.status(404).send("Delegation not found");
  }

  const now = Date.now();
  const isActive = !session.revoked_at && session.expires_at > now;
  const ttlRemaining = Math.max(0, Math.floor((session.expires_at - now) / 1000));
  const ttlHours = Math.floor(ttlRemaining / 3600);
  const ttlMinutes = Math.floor((ttlRemaining % 3600) / 60);
  // Use 6 decimals so small budgets (e.g. 0.005, 0.0045) display correctly; coerce in case DB returns string
  const maxTotalAtomic = Number(session.max_total_spend) || 0;
  const maxPerTxAtomic = Number(session.max_per_tx) || 0;
  const spentAtomic = Number(session.total_spent_atomic) || 0;
  const formatUSDAmount = (atomic: number) => {
    const s = atomicToUSD(atomic);
    return s.replace(/\.?0+$/, "") || s;
  };
  const maxTotalUSD = formatUSDAmount(maxTotalAtomic);
  const maxPerTxUSD = formatUSDAmount(maxPerTxAtomic);
  const totalSpentUSD = formatUSDAmount(spentAtomic);
  
  const hasAllowedApis = session.allowed_apis && session.allowed_apis.length > 0;
  
  let apisHtml = "";
  if (hasAllowedApis) {
    apisHtml = session.allowed_apis.map((api: any) => `
      <div class="api-card">
        <div class="api-method">${api.method}</div>
        <div class="api-path">${api.path}</div>
        <div class="api-domain">${api.domain}</div>
        ${api.description ? `<div class="api-description">${api.description}</div>` : ''}
      </div>
    `).join("");
  }

  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Agent Watchdog - Delegation Details</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
    * { box-sizing: border-box; }
    body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; font-size: 0.9em; max-width: 700px; margin: 40px auto; padding: 20px; background: #0D0D0D; color: #E0E0E0; line-height: 1.6; }
    h1, h2 { font-family: 'Inter', sans-serif; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; margin: 0 0 15px 0; color: #E0E0E0; }
    h1 { font-size: 1.5em; border-bottom: 1px solid #708090; padding-bottom: 10px; }
    h2 { font-size: 1em; margin-top: 25px; padding-bottom: 8px; border-bottom: 1px solid #708090; }
    .divider { border-top: 1px solid #708090; margin: 20px 0; }
    p { margin: 10px 0; color: #E0E0E0; }
    .mono { font-family: 'IBM Plex Mono', monospace; color: #4FD1C5; }
    strong { text-transform: uppercase; font-size: 0.75em; letter-spacing: 0.05em; color: #708090; font-weight: 600; }
    .summary { font-size: 1.1em; font-weight: 600; color: #E0E0E0; margin: 15px 0; padding: 12px; background: rgba(79, 209, 197, 0.1); border-left: 3px solid #4FD1C5; }
    .description { font-size: 0.95em; color: #E0E0E0; margin: 10px 0 20px 0; line-height: 1.6; white-space: pre-wrap; }
    .api-card { display: flex; align-items: center; gap: 12px; padding: 12px; margin: 4px 0; border: 1px solid #708090; background: transparent; }
    .api-method { background: #708090; color: #0D0D0D; padding: 4px 8px; font-family: 'IBM Plex Mono', monospace; font-size: 0.75em; font-weight: 600; min-width: 60px; text-align: center; }
    .api-path { font-family: 'IBM Plex Mono', monospace; color: #E0E0E0; flex: 1; }
    .api-domain { font-family: 'IBM Plex Mono', monospace; color: #4FD1C5; font-size: 0.85em; font-weight: 500; }
    .api-description { font-size: 0.8em; color: #708090; margin-top: 4px; width: 100%; }
    .budget { font-size: 1.15em; font-weight: 600; color: #4FD1C5; font-family: 'IBM Plex Mono', monospace; margin: 8px 0; }
    .badge { padding: 3px 8px; font-size: 0.75em; display: inline-block; border: 1px solid; font-family: 'IBM Plex Mono', monospace; text-transform: uppercase; letter-spacing: 0.05em; }
    .badge-active { color: #39FF14; border-color: #39FF14; }
    .badge-expired { color: #708090; border-color: #708090; }
    .badge-revoked { color: #8B0000; border-color: #8B0000; }
    .back-link { display: inline-block; margin-bottom: 20px; color: #4FD1C5; text-decoration: none; }
    .back-link:hover { text-decoration: underline; }
    .transactions-btn { display: inline-block; margin-top: 10px; padding: 8px 16px; border: 1px solid #708090; background: #0D0D0D; color: #E0E0E0; font-family: 'Inter', sans-serif; text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.85em; cursor: pointer; text-decoration: none; }
    .transactions-btn:hover { border-color: #4FD1C5; color: #4FD1C5; }
  </style>
</head>
<body>
  <a href="/dashboard" class="back-link">← Back to Dashboard</a>
  <h1>DELEGATION DETAILS</h1>
  <div class="divider"></div>
  
  <p><strong>STATUS:</strong> <span class="badge ${isActive ? 'badge-active' : (session.revoked_at ? 'badge-revoked' : 'badge-expired')}">${isActive ? 'ACTIVE' : (session.revoked_at ? 'REVOKED' : 'EXPIRED')}</span></p>
  <p><strong>SESSION ID:</strong> <span class="mono">${session.session_id}</span></p>
  <p><strong>AGENT ID:</strong> <span class="mono">${session.agent_id ?? "—"}</span></p>
  <p><strong>APPROVED:</strong> <span class="mono">${session.created_at ? new Date(session.created_at).toLocaleString() : "—"}</span></p>
  
  ${session.summary ? `<p class="summary">${session.summary}</p>` : ''}
  ${session.description ? `<p class="description">${session.description}</p>` : ''}
  
  <h2>ALLOWED APIS</h2>
  ${hasAllowedApis ? apisHtml : (session.allowed_domains || []).map((d: string) => `<div class="api-card"><span class="mono">${d}</span></div>`).join("")}
  
  <h2>BUDGET (USDC)</h2>
  <div class="budget">MAX TOTAL: $${maxTotalUSD}</div>
  <div class="budget">MAX PER TX: $${maxPerTxUSD}</div>
  <div class="budget">SPENT: $${totalSpentUSD}</div>
  
  <h2>DURATION</h2>
  <p><span class="mono">${ttlHours}h ${ttlMinutes}m remaining</span> <span style="color: #708090;">(${ttlRemaining} seconds)</span></p>
  
  <a href="/dashboard?session_id=${session.session_id}" class="transactions-btn">VIEW TRANSACTIONS</a>
</body>
</html>
  `);
});

app.get("/dashboard", async (_req: Request, res: Response) => {
  res.send(getDashboardHtml());
});

// Legacy dashboard route preserved for reference — will be removed.
app.get("/dashboard-legacy", async (_req: Request, res: Response) => {
  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Agent Watchdog Dashboard</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
    
    * { box-sizing: border-box; }
    body { 
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; 
      font-size: 0.9em;
      max-width: 1400px; 
      margin: 0 auto; 
      padding: 40px 20px; 
      background: #0D0D0D; 
      color: #E0E0E0; 
      line-height: 1.6;
    }
    h1, h2 { 
      font-family: 'Inter', sans-serif; 
      text-transform: uppercase; 
      letter-spacing: 0.05em; 
      font-weight: 600; 
      margin: 0 0 20px 0;
      color: #E0E0E0;
    }
    h1 { font-size: 1.5em; border-bottom: 1px solid #708090; padding-bottom: 10px; }
    h2 { font-size: 1em; }
    .panel { 
      background: #0D0D0D; 
      border: 1px solid #708090; 
      border-radius: 0px; 
      padding: 20px; 
      margin: 30px 0; 
    }
    .panel h2 { 
      margin-top: 0; 
      margin-bottom: 15px; 
      padding-bottom: 10px; 
      border-bottom: 1px solid #708090; 
    }
    .divider { 
      border-top: 1px solid #708090; 
      margin: 20px 0; 
      height: 0; 
    }
    table { 
      width: 100%; 
      border-collapse: collapse; 
      margin-top: 15px; 
      font-size: 0.9em;
      table-layout: fixed;
    }
    th, td { 
      padding: 12px 10px; 
      text-align: left; 
      border-bottom: 1px solid #708090; 
      border-right: none;
      word-break: break-word;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 200px;
    }
    th { 
      background: #0D0D0D; 
      font-weight: 600; 
      text-transform: uppercase; 
      font-size: 0.75em; 
      letter-spacing: 0.05em; 
      color: #708090;
      font-family: 'Inter', sans-serif;
    }
    td { 
      color: #E0E0E0; 
      font-family: 'Inter', sans-serif;
    }
    tr:hover { background: rgba(112, 128, 144, 0.05); }
    .badge { 
      padding: 3px 8px; 
      border-radius: 0px; 
      font-size: 0.75em; 
      display: inline-block; 
      border: 1px solid;
      font-family: 'IBM Plex Mono', monospace;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge-active { 
      background: transparent; 
      color: #4FD1C5; 
      border-color: #4FD1C5; 
    }
    .badge-expired { 
      background: transparent; 
      color: #708090; 
      border-color: #708090; 
    }
    .badge-revoked { 
      background: transparent; 
      color: #8B0000; 
      border-color: #8B0000; 
    }
    .badge-approved { 
      background: transparent; 
      color: #4FD1C5; 
      border-color: #4FD1C5; 
    }
    .badge-denied { 
      background: transparent; 
      color: #8B0000; 
      border-color: #8B0000; 
    }
    button { 
      padding: 8px 16px; 
      border: 1px solid #708090; 
      border-radius: 0px; 
      cursor: pointer; 
      background: #0D0D0D; 
      color: #E0E0E0; 
      font-size: 0.85em; 
      font-family: 'Inter', sans-serif;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      transition: border-color 0.2s;
    }
    button:hover { 
      border-color: #4FD1C5; 
      color: #4FD1C5; 
    }
    button.danger { 
      border-color: #8B0000; 
      color: #8B0000; 
    }
    button.danger:hover { 
      border-color: #8B0000; 
      background: rgba(139, 0, 0, 0.1); 
    }
    button.small { 
      padding: 4px 10px; 
      font-size: 0.75em; 
    }
    select {
      padding: 6px 10px;
      border: 1px solid #708090;
      border-radius: 0px;
      background: #0D0D0D;
      color: #E0E0E0;
      font-family: 'Inter', sans-serif;
      font-size: 0.85em;
    }
    select:focus {
      outline: none;
      border-color: #4FD1C5;
    }
    label {
      font-family: 'Inter', sans-serif;
      font-size: 0.85em;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #708090;
      margin-right: 10px;
    }
    .address, .delegation-id, .mono { 
      font-family: 'IBM Plex Mono', monospace; 
      font-size: 0.9em; 
      color: #4FD1C5; 
    }
    .collapsible { 
      cursor: pointer; 
      user-select: none; 
    }
    .collapsible:hover {
      color: #4FD1C5;
    }
    .clickable-row {
      cursor: pointer;
    }
    .clickable-row:hover {
      background: rgba(79, 209, 197, 0.05);
    }
    .collapsible-content {
      display: none; 
    }
    .collapsible-content.expanded { 
      display: block; 
    }
    .loading { 
      color: #708090; 
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.85em;
    }
    a { 
      color: #4FD1C5; 
      text-decoration: none; 
    }
    a:hover { 
      text-decoration: underline; 
      color: #4FD1C5;
    }
    .nav { margin-bottom: 20px; font-size: 0.85em; }
    .wallet-grid { 
      display: grid; 
      grid-template-columns: 1fr 1fr; 
      gap: 40px; 
      align-items: start; 
    }
    .wallet-left p { 
      margin: 12px 0; 
      font-size: 0.9em;
    }
    .wallet-left strong {
      text-transform: uppercase;
      font-size: 0.75em;
      letter-spacing: 0.05em;
      color: #708090;
      display: block;
      margin-bottom: 4px;
    }
    .wallet-right { 
      text-align: left; 
    }
    .balance-usdc { 
      font-size: 3em; 
      font-weight: 700; 
      color: #4FD1C5; 
      line-height: 1.2; 
      font-family: 'IBM Plex Mono', monospace;
      margin: 10px 0;
    }
    .balance-secondary { 
      font-size: 0.9em; 
      color: #708090; 
      margin: 6px 0; 
      font-family: 'IBM Plex Mono', monospace;
    }
    .balance-label { 
      font-size: 0.7em; 
      text-transform: uppercase; 
      letter-spacing: 0.1em; 
      color: #708090; 
      margin-bottom: 8px; 
      font-family: 'Inter', sans-serif;
    }
    .error { color: #8B0000; font-family: 'IBM Plex Mono', monospace; }
    p { margin: 8px 0; }
    .expand-control {
      margin-top: 15px;
      text-align: left;
    }
    .expand-btn {
      padding: 6px 12px;
      font-size: 0.75em;
      border: 1px solid #708090;
      background: #0D0D0D;
      color: #708090;
      cursor: pointer;
      font-family: 'Inter', sans-serif;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .expand-btn:hover {
      border-color: #4FD1C5;
      color: #4FD1C5;
    }
    .hidden-row {
      display: none;
    }
    .top-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 24px;
      padding: 12px 0 16px 0;
      border-bottom: 1px solid #708090;
      position: sticky;
      top: 0;
      background: #0D0D0D;
      z-index: 100;
    }
    .top-bar .nav-links {
      display: flex;
      align-items: center;
      gap: 16px;
      font-size: 0.9em;
      flex-shrink: 0;
    }
    .top-bar .nav-links a {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: #E0E0E0;
      text-decoration: none;
      padding: 10px 14px;
      border: 1px solid #708090;
      border-radius: 0;
    }
    .top-bar .nav-links a:hover {
      border-color: #4FD1C5;
      color: #4FD1C5;
      text-decoration: none;
    }
    .top-bar .nav-links a svg {
      width: 18px;
      height: 18px;
      flex-shrink: 0;
    }
    .top-bar .nav-links a.account-link {
      border-color: #4FD1C5;
      color: #4FD1C5;
    }
  </style>
</head>
<body>
  <div class="top-bar">
    <h1 style="margin:0; border:0; padding:0; font-size:1.5em;">AGENT WATCHDOG</h1>
    <nav class="nav-links" aria-label="Main navigation">
      <a href="#" id="nav-activity" class="account-link" onclick="setSection('activity'); return false;">
        AGENT ACTIVITY
      </a>
      <a href="#" id="nav-audit" onclick="setSection('audit'); return false;">
        AUDIT LOG
      </a>
      <a href="#" id="nav-policies" onclick="setSection('policies'); return false;">
        POLICIES &amp; RESOURCES
      </a>
      <a href="/account" title="Account – passkeys and wallet">
        Account
      </a>
    </nav>
  </div>

  <!-- SECTION: Agent Activity (default) -->
  <div id="section-activity">
    <div style="display:flex; gap:24px; align-items:flex-start;">
      <!-- Left: Agent Activities (Firewall) -->
      <div style="flex:1; min-width:0;">
        <div class="panel">
          <h2>AGENT ACTIVITY</h2>
          <div class="divider"></div>
          <div id="firewall-stats" class="loading">LOADING FIREWALL STATS...</div>
          <div class="divider"></div>
          <div id="firewall-alerts">
            <div class="loading">LOADING FIREWALL ALERTS...</div>
          </div>
        </div>
      </div>

      <!-- Right: Scoped Access (Active & Past) -->
      <div style="flex:1; min-width:0; display:flex; flex-direction:column; gap:24px;">
        <div class="panel">
          <h2>SCOPED ACCESS – ACTIVE GRANTS</h2>
          <div id="active-delegations">
            <div class="loading">LOADING...</div>
          </div>
        </div>
        <div class="panel">
          <h2>SCOPED ACCESS – PAST GRANTS</h2>
          <div id="past-delegations">
            <div class="loading">LOADING...</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- SECTION: Audit Log -->
  <div id="section-audit" style="display:none;">
    <div style="display:flex; gap:24px; align-items:flex-start;">
      <div style="flex:1; min-width:0;">
        <div class="panel">
          <h2>AUDIT LOG – FIREWALL EVENTS</h2>
          <div class="divider"></div>
          <div id="audit-firewall-events">
            <div class="loading">LOADING...</div>
          </div>
        </div>
      </div>
      <div style="flex:1; min-width:0;">
        <div class="panel">
          <h2>AUDIT LOG – SCOPED ACCESS</h2>
          <div style="margin-bottom: 15px;">
            <label>FILTER BY GRANT:</label>
            <select id="delegation-filter" onchange="loadTransactions()" style="min-width: 300px; margin-right: 10px;">
              <option value="">ALL GRANTS</option>
            </select>
            <button class="small" onclick="document.getElementById('delegation-filter').value=''; loadTransactions();">CLEAR</button>
          </div>
          <div class="divider"></div>
          <div id="transactions-list">
            <div class="loading">LOADING...</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- SECTION: Policies & Resources -->
  <div id="section-policies" style="display:none;">
    <div class="panel">
      <h2>POLICIES</h2>
      <div class="divider"></div>
      <div id="policy-config" class="loading">LOADING POLICIES...</div>
    </div>
    <div class="panel">
      <h2>RESOURCES – WALLET <button class="small" onclick="refreshWallet()">REFRESH</button></h2>
      <div class="divider"></div>
      <div id="wallet">
        <div class="loading">LOADING WALLET INFO...</div>
      </div>
    </div>
  </div>
  
  <script>
    const WATCHDOG_BASE = "/watchdog";

    // Truncate path keeping filename: /very/long/path/filename.js -> /very/.../filename.js
    function truncatePath(path, maxLen) {
      if (!path || path.length <= maxLen) return path;
      const parts = path.split('/');
      const filename = parts.pop();
      if (filename.length >= maxLen - 3) return '...' + filename.slice(-(maxLen - 3));
      let result = filename;
      for (let i = parts.length - 1; i >= 0; i--) {
        const next = '/' + parts[i] + result;
        if (next.length > maxLen - 3) break;
        result = next;
      }
      return '...' + result;
    }

    const ATOMIC_UNITS = ${ATOMIC_UNITS};
    function formatUSDC(atomic) {
      return (Number(atomic) / ATOMIC_UNITS).toFixed(6);
    }

    function setSection(section) {
      const ids = ["activity", "audit", "policies"];
      ids.forEach((s) => {
        const el = document.getElementById("section-" + s);
        if (!el) return;
        el.style.display = s === section ? "block" : "none";
      });

      const navIds = {
        activity: "nav-activity",
        audit: "nav-audit",
        policies: "nav-policies",
      };
      Object.keys(navIds).forEach(function (key) {
        const id = navIds[key];
        const el = document.getElementById(id);
        if (!el) return;
        if (key === section) {
          el.classList.add("account-link");
        } else {
          el.classList.remove("account-link");
        }
      });
    }

    // Track expanded/collapsed state for tables with SHOW MORE/LESS
    const expandedState = {
      "active-delegations": false,
      "past-delegations": false,
    };

    function toggleExpand(tableId) {
      expandedState[tableId] = !expandedState[tableId];
      const rows = document.querySelectorAll('#' + tableId + ' tbody tr');
      const expandBtn = document.getElementById(tableId + '-expand-btn');

      rows.forEach((row, index) => {
        if (index >= 5) {
          if (expandedState[tableId]) {
            row.classList.remove("hidden-row");
          } else {
            row.classList.add("hidden-row");
          }
        }
      });

      if (expandBtn) {
        expandBtn.textContent = expandedState[tableId] ? "SHOW LESS" : "SHOW MORE";
      }
    }

    // Generate block explorer URL from network. Supports "eip155:chainId" or name (e.g. "base-sepolia").
    function getExplorerUrl(txHash, network) {
      if (!txHash) return null;
      const chainId = network?.split(':')[1]; // eip155:84532 -> 84532
      const byChainId = {
        '8453': 'https://basescan.org/tx/',      // Base mainnet
        '84532': 'https://sepolia.basescan.org/tx/', // Base Sepolia
        '1': 'https://etherscan.io/tx/',         // Ethereum mainnet
        '11155111': 'https://sepolia.etherscan.io/tx/', // Ethereum Sepolia
        '137': 'https://polygonscan.com/tx/',    // Polygon mainnet
        '80002': 'https://amoy.polygonscan.com/tx/', // Polygon Amoy
      };
      const byName = {
        'base': 'https://basescan.org/tx/',
        'base-sepolia': 'https://sepolia.basescan.org/tx/',
        'base-mainnet': 'https://basescan.org/tx/',
        'ethereum': 'https://etherscan.io/tx/',
        'sepolia': 'https://sepolia.etherscan.io/tx/',
      };
      const baseUrl = byChainId[chainId] || byName[network] || byName[String(network).toLowerCase()] || 'https://basescan.org/tx/';
      return baseUrl + txHash;
    }

    function formatTime(timestamp) {
      return new Date(timestamp).toLocaleString();
    }

    function relativeTime(timestamp) {
      const now = Date.now();
      const diff = now - new Date(timestamp).getTime();
      const seconds = Math.floor(diff / 1000);
      const minutes = Math.floor(seconds / 60);
      const hours = Math.floor(minutes / 60);
      const days = Math.floor(hours / 24);

      if (days > 0) return days + 'd ago';
      if (hours > 0) return hours + 'h ago';
      if (minutes > 0) return minutes + 'm ago';
      return 'now';
    }

    function truncateAddress(addr) {
      if (!addr) return '';
      return addr.slice(0, 6) + '...' + addr.slice(-4);
    }
    
    function renderAllowedApis(allowed_apis, allowed_domains) {
      if (allowed_apis && allowed_apis.length > 0) {
        return allowed_apis.map(function(api) {
          return api.method + ' ' + api.path;
        }).join('<br>');
      }
      if (allowed_domains && allowed_domains.length > 0) {
        return allowed_domains.join(', ');
      }
      return 'N/A';
    }
    
    function renderAllowedApisShort(allowed_apis, allowed_domains) {
      if (allowed_apis && allowed_apis.length > 0) {
        if (allowed_apis.length === 1) {
          return allowed_apis[0].method + ':' + allowed_apis[0].path;
        }
        return allowed_apis.length + ' APIs';
      }
      if (allowed_domains && allowed_domains.length > 0) {
        return allowed_domains.join(', ');
      }
      return 'N/A';
    }

    function renderSummaryShort(text) {
      if (!text) return '-';
      if (text.length <= 48) return text;
      return text.slice(0, 45) + '...';
    }

    function renderCapabilitiesShort(capabilities, allowed_apis) {
      // For the main screen, only show a compact HTTP POST summary.
      if (allowed_apis && allowed_apis.length > 0) {
        const posts = allowed_apis.filter(function(api) {
          return String(api.method || '').toUpperCase() === 'POST';
        });
        if (posts.length === 1) {
          return 'HTTP:POST ' + posts[0].path;
        }
        if (posts.length > 1) {
          return 'HTTP:POST x' + posts.length;
        }
      }
      return 'N/A';
    }

    async function refreshWallet() {
      const el = document.getElementById('wallet');
      el.innerHTML = '<div class="loading">LOADING...</div>';
      try {
        const res = await fetch('/api/wallet');
        const data = await res.json();
        if (!data.authenticated) {
          el.innerHTML = '<p class="error">WALLET NOT AUTHENTICATED</p>';
          return;
        }
        el.innerHTML = \`
          <div class="wallet-grid">
            <div class="wallet-left">
              <p><strong>EMAIL</strong><span class="mono">\${data.email || 'N/A'}</span></p>
              <p><strong>ADDRESS</strong><br>
                <span class="address">\${data.address || 'N/A'}</span>
                \${data.address ? ' <button class="small" onclick="navigator.clipboard.writeText(\\'' + data.address + '\\')">COPY</button>' : ''}
              </p>
              <p style="color: #708090; font-size: 0.8em; margin-top: 15px;">NETWORK: <span class="mono">BASE-SEPOLIA</span></p>
            </div>
            <div class="wallet-right">
              <div class="balance-label">USDC BALANCE</div>
              <div class="balance-usdc">$\${data.balances?.USDC || '0.00'}</div>
              <div class="balance-secondary">ETH: \${data.balances?.ETH || '0.00'}</div>
              <div class="balance-secondary">WETH: \${data.balances?.WETH || '0.00'}</div>
            </div>
          </div>
        \`;
      } catch (e) {
        el.innerHTML = '<p class="error">ERROR: ' + e.message + '</p>';
      }
    }

    const SENSITIVE_FILE_RULES = [
      { pattern: '.env', severity: 'HIGH', state: 'ENABLED', action: 'BLOCK', description: 'Environment variable config file' },
      { pattern: 'id_rsa', severity: 'HIGH', state: 'ENABLED', action: 'BLOCK', description: 'SSH private key file' },
      { pattern: 'shadow', severity: 'HIGH', state: 'ENABLED', action: 'BLOCK', description: 'System password file' },
      { pattern: 'credentials', severity: 'HIGH', state: 'ENABLED', action: 'BLOCK', description: 'Credential file (e.g. cloud keys)' },
      { pattern: '.pem', severity: 'HIGH', state: 'ENABLED', action: 'BLOCK', description: 'Certificate private key file' },
      { pattern: 'config.json', severity: 'MEDIUM', state: 'ENABLED', action: 'BLOCK', description: 'Configuration file with secrets' },
      { pattern: 'secret', severity: 'HIGH', state: 'ENABLED', action: 'BLOCK', description: 'Generic secret-related file' },
    ];

    async function loadPolicies() {
      const el = document.getElementById('policy-config');
      if (!el) return;
      el.innerHTML = '<div class="loading">LOADING...</div>';
      try {
        const res = await fetch(WATCHDOG_BASE + '/api/config');
        if (!res.ok) {
          throw new Error('Failed to fetch firewall policies: ' + res.status);
        }
        const cfg = await res.json();
        const rulesHtml = SENSITIVE_FILE_RULES.map(function (r) {
          return (
            '<tr>' +
              '<td><span class="mono">' + r.pattern + '</span></td>' +
              '<td><span class="badge ' + (r.severity === 'HIGH' ? 'badge-denied' : 'badge-active') + '">' + r.severity + '</span></td>' +
              '<td><span class="badge ' + (r.state === 'ENABLED' ? 'badge-active' : 'badge-expired') + '">' + r.state + '</span></td>' +
              '<td><span class="mono">' + r.action + '</span></td>' +
              '<td>' + r.description + '</td>' +
            '</tr>'
          );
        }).join('');
        el.innerHTML = \`
          <p><strong>DRY RUN</strong><span class="mono">\${cfg.dry_run ? 'ON' : 'OFF'}</span></p>
          <p><strong>WHITELISTED PROCESSES</strong><span class="mono">\${(cfg.whitelist_processes || []).join(', ') || '—'}</span></p>
          <p><strong>WHITELISTED PATHS</strong><span class="mono">\${(cfg.whitelist_paths || []).join(', ') || '—'}</span></p>
          <div style="margin-top:16px;">
            <h3 style="margin:0 0 8px 0; font-size:0.8em; text-transform:uppercase; letter-spacing:0.08em; color:#708090;">
              SENSITIVE FILE RULES (WATCHDOG)
            </h3>
            <table>
              <thead>
                <tr>
                  <th>PATTERN</th>
                  <th>SEVERITY</th>
                  <th>STATE</th>
                  <th>ACTION</th>
                  <th>DESCRIPTION</th>
                </tr>
              </thead>
              <tbody>
                \${rulesHtml}
              </tbody>
            </table>
          </div>
        \`;
      } catch (e) {
        el.innerHTML = '<p class="error">POLICY ERROR: ' + e.message + '</p>';
      }
    }

    async function loadFirewallStats() {
      const el = document.getElementById('firewall-stats');
      if (!el) return;
      el.innerHTML = '<div class="loading">LOADING...</div>';
      try {
        const res = await fetch(WATCHDOG_BASE + '/api/stats');
        if (!res.ok) {
          throw new Error('Failed to fetch firewall stats: ' + res.status);
        }
        const s = await res.json();
        el.innerHTML = \`
          <p><strong>TODAY ALERTS</strong><span class="mono">\${s.today_alerts}</span></p>
          <p><strong>ACTIVE ALERTS</strong><span class="mono">\${s.active_alerts}</span></p>
          <p><strong>BLOCKED PROCESSES</strong><span class="mono">\${s.blocked_count}</span></p>
          <p><strong>IGNORED ALERTS</strong><span class="mono">\${s.ignored_count}</span></p>
          <p><strong>TOTAL EVENTS</strong><span class="mono">\${s.total_events}</span></p>
        \`;
      } catch (e) {
        el.innerHTML = '<p class="error">FIREWALL STATS ERROR: ' + e.message + '</p>';
      }
    }

    async function loadFirewallAlerts() {
      const el = document.getElementById('firewall-alerts');
      if (!el) return;
      el.innerHTML = '<div class="loading">LOADING...</div>';
      try {
        const res = await fetch(WATCHDOG_BASE + '/api/alerts');
        if (!res.ok) {
          throw new Error('Failed to fetch firewall alerts: ' + res.status);
        }
        const alerts = await res.json();
        if (!Array.isArray(alerts) || alerts.length === 0) {
          el.innerHTML = '<p style="color: #708090;">NO ACTIVE ALERTS</p>';
          return;
        }
        el.innerHTML = \`
          <table>
            <thead>
              <tr>
                <th>TIME</th>
                <th>PROCESS</th>
                <th>PID</th>
                <th>FILE</th>
                <th>SEVERITY</th>
                <th>STATUS</th>
                <th>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              \${alerts.map(function(a) {
                return \`
                  <tr>
                    <td><span class="mono">\${new Date(a.timestamp).toLocaleTimeString()}</span></td>
                    <td><span class="mono">\${a.comm}</span></td>
                    <td><span class="mono">\${a.pid}</span></td>
                    <td><span class="mono" title="\${a.filename}">\${truncatePath(a.filename, 40)}</span></td>
                    <td><span class="badge badge-\${a.severity === 'high' ? 'denied' : 'active'}">\${a.severity.toUpperCase()}</span></td>
                    <td><span class="badge \${a.status === 'active' ? 'badge-active' : (a.status === 'blocked' ? 'badge-revoked' : 'badge-expired')}">\${a.status.toUpperCase()}</span></td>
                    <td>
                      <button class="small danger" onclick="blockFirewallEvent('\${a.id}')">BLOCK</button>
                      <button class="small" onclick="ignoreFirewallEvent('\${a.id}')">IGNORE</button>
                    </td>
                  </tr>
                \`;
              }).join('')}
            </tbody>
          </table>
        \`;
      } catch (e) {
        el.innerHTML = '<p class="error">FIREWALL ALERTS ERROR: ' + e.message + '</p>';
      }
    }

    async function loadFirewallAudit() {
      const el = document.getElementById('audit-firewall-events');
      if (!el) return;
      el.innerHTML = '<div class="loading">LOADING...</div>';
      try {
        const res = await fetch(WATCHDOG_BASE + '/api/alerts');
        if (!res.ok) {
          throw new Error('Failed to fetch firewall alerts: ' + res.status);
        }
        const alerts = await res.json();
        if (!Array.isArray(alerts) || alerts.length === 0) {
          el.innerHTML = '<p style="color: #708090;">NO RECENT EVENTS</p>';
          return;
        }
        el.innerHTML = \`
          <table>
            <thead>
              <tr>
                <th>TIME</th>
                <th>PROCESS</th>
                <th>PID</th>
                <th>FILE</th>
                <th>SEVERITY</th>
                <th>STATUS</th>
              </tr>
            </thead>
            <tbody>
              \${alerts.map(function(a) {
                return \`
                  <tr>
                    <td><span class="mono">\${new Date(a.timestamp).toLocaleTimeString()}</span></td>
                    <td><span class="mono">\${a.comm}</span></td>
                    <td><span class="mono">\${a.pid}</span></td>
                    <td><span class="mono" title="\${a.filename}">\${truncatePath(a.filename, 40)}</span></td>
                    <td><span class="badge badge-\${a.severity === 'high' ? 'denied' : 'active'}">\${a.severity.toUpperCase()}</span></td>
                    <td><span class="badge \${a.status === 'active' ? 'badge-active' : (a.status === 'blocked' ? 'badge-revoked' : 'badge-expired')}">\${a.status.toUpperCase()}</span></td>
                  </tr>
                \`;
              }).join('')}
            </tbody>
          </table>
        \`;
      } catch (e) {
        el.innerHTML = '<p class="error">FIREWALL EVENTS ERROR: ' + e.message + '</p>';
      }
    }

    async function blockFirewallEvent(id) {
      try {
        await fetch(WATCHDOG_BASE + '/api/events/' + encodeURIComponent(id) + '/block', { method: 'POST' });
      } catch (e) {
        console.error('Failed to block firewall event', e);
      } finally {
        loadFirewallAlerts();
        loadFirewallStats();
      }
    }

    async function ignoreFirewallEvent(id) {
      try {
        await fetch(WATCHDOG_BASE + '/api/events/' + encodeURIComponent(id) + '/ignore', { method: 'POST' });
      } catch (e) {
        console.error('Failed to ignore firewall event', e);
      } finally {
        loadFirewallAlerts();
        loadFirewallStats();
      }
    }
    
    async function loadDelegations() {
      const activeEl = document.getElementById('active-delegations');
      const pastEl = document.getElementById('past-delegations');
      
      try {
        const res = await fetch('/api/scoped-access');
        if (!res.ok) {
          throw new Error('Failed to fetch delegations: ' + res.status);
        }
        const sessions = await res.json();
        
        if (!Array.isArray(sessions)) {
          throw new Error('Invalid response format');
        }
        
        const active = sessions.filter(s => s.is_active === true);
        const past = sessions.filter(s => s.is_active !== true);
        
        console.log('Delegations loaded:', { total: sessions.length, active: active.length, past: past.length });
        
        const renderActiveTable = (items, expanded) => {
          const hasMore = items.length > 5;
          return \`
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>AGENT</th>
                  <th>SUMMARY</th>
                  <th>CAPABILITIES</th>
                  <th>TTL REMAINING</th>
                  <th>STATUS</th>
                  <th>ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                \${items.map((s, index) => {
                  const hidden = index >= 5 && !expanded;
                  return \`
                  <tr class="clickable-row \${hidden ? 'hidden-row' : ''}" onclick="viewDelegation('\${s.session_id}')">
                      <td><span class="delegation-id" title="\${s.session_id}">\${s.session_id.slice(0, 8)}...</span></td>
                      <td><span class="mono">\${s.agent_id || '-'}</span></td>
                      <td><span class="mono">\${renderSummaryShort(s.summary || '')}</span></td>
                      <td><span class="mono">\${renderCapabilitiesShort(s.capabilities, s.allowed_apis)}</span></td>
                      <td><span class="mono">\${Math.floor(s.ttl_remaining_seconds / 60)}m \${s.ttl_remaining_seconds % 60}s</span></td>
                      <td><span class="badge badge-active">ACTIVE</span></td>
                      <td onclick="event.stopPropagation()">
                        <button class="small" onclick="event.stopPropagation(); filterByDelegation('\${s.session_id}')">TXs</button>
                        <button class="danger small" onclick="event.stopPropagation(); revokeSession('\${s.session_id}')">REVOKE</button>
                      </td>
                  </tr>
                \`;}).join('')}
              </tbody>
            </table>
            \${hasMore ? \`<div class="expand-control"><button id="active-delegations-expand-btn" class="expand-btn" onclick="toggleExpand('active-delegations')">\${expanded ? 'SHOW LESS' : 'SHOW MORE'}</button></div>\` : ''}
          \`;
        };
        
        const renderPastTable = (items, expanded) => {
          const hasMore = items.length > 5;
          return \`
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>AGENT</th>
                  <th>SUMMARY</th>
                  <th>CAPABILITIES</th>
                  <th>STATUS</th>
                  <th>ACTIONS</th>
                  <th>CREATED</th>
                </tr>
              </thead>
              <tbody>
                \${items.map((s, index) => {
                  try {
                    const hidden = index >= 5 && !expanded;
                    return \`
                      <tr class="clickable-row \${hidden ? 'hidden-row' : ''}" onclick="viewDelegation('\${s.session_id}')">
                          <td><span class="delegation-id" title="\${s.session_id}">\${s.session_id.slice(0, 8)}...</span></td>
                          <td><span class="mono">\${s.agent_id || '-'}</span></td>
                          <td><span class="mono">\${renderSummaryShort(s.summary || '')}</span></td>
                          <td><span class="mono">\${renderCapabilitiesShort(s.capabilities, s.allowed_apis)}</span></td>
                          <td>
                            <span class="badge \${s.revoked_at ? 'badge-revoked' : 'badge-expired'}">
                              \${s.revoked_at ? 'REVOKED' : 'EXPIRED'}
                            </span>
                          </td>
                          <td onclick="event.stopPropagation()">
                            <button class="small" onclick="event.stopPropagation(); filterByDelegation('\${s.session_id}')">TXs</button>
                          </td>
                          <td><span class="mono">\${relativeTime(s.created_at || (s.expires_at - s.ttl_seconds * 1000))}</span></td>
                      </tr>
                    \`;
                  } catch (err) {
                    console.error('Error rendering delegation:', s, err);
                    return '<tr><td colspan="8" class="error">ERROR RENDERING DELEGATION</td></tr>';
                  }
                }).join('')}
              </tbody>
            </table>
            \${hasMore ? \`<div class="expand-control"><button id="past-delegations-expand-btn" class="expand-btn" onclick="toggleExpand('past-delegations')">\${expanded ? 'SHOW LESS' : 'SHOW MORE'}</button></div>\` : ''}
          \`;
        };
        
        activeEl.innerHTML = active.length === 0 ? '<p style="color: #708090;">NO ACTIVE GRANTS</p>' : renderActiveTable(active, expandedState['active-delegations']);
        pastEl.innerHTML = past.length === 0 ? '<p style="color: #708090;">NO PAST GRANTS</p>' : renderPastTable(past, expandedState['past-delegations']);
      } catch (e) {
        console.error('Error loading delegations:', e);
        activeEl.innerHTML = '<p class="error">ERROR: ' + e.message + '</p>';
        pastEl.innerHTML = '<p class="error">ERROR: ' + e.message + '</p>';
      }
    }
    
    async function loadTransactions() {
      const el = document.getElementById('transactions-list');
      const filterEl = document.getElementById('delegation-filter');
      const sessionId = filterEl ? filterEl.value : '';
      
      if (el) el.innerHTML = '<div class="loading">LOADING...</div>';
      
      try {
        const url = '/api/transactions' + (sessionId ? '?session_id=' + encodeURIComponent(sessionId) : '');
        const res = await fetch(url);
        const transactions = await res.json();
        
        if (transactions.length === 0) {
          if (el) el.innerHTML = '<p style="color: #708090;">NO TRANSACTIONS</p>';
          return;
        }
        
        const expanded = expandedState['transactions'];
        const hasMore = transactions.length > 5;
        
        if (el) el.innerHTML = \`
          <table>
            <thead>
              <tr>
                <th>TIME</th>
                <th>AGENT ID</th>
                <th>ACTION</th>
                <th>STATUS</th>
                <th>GRANT</th>
              </tr>
            </thead>
            <tbody>
              \${transactions.map((tx, index) => \`
                <tr \${index >= 5 && !expanded ? 'class="hidden-row"' : ''}>
                  <td><span class="mono">\${relativeTime(tx.created_at)}</span></td>
                  <td><span class="mono">\${tx.agent_id || '-'}</span></td>
                  <td><span class="mono">\${tx.method || ''} \${tx.api_path || tx.domain || 'N/A'}</span></td>
                  <td>
                    <span class="badge \${tx.decision === 'APPROVED' ? 'badge-approved' : (tx.decision === 'PENDING' ? 'badge-active' : 'badge-denied')}">
                      \${tx.decision === 'APPROVED' ? 'DONE' : (tx.decision === 'DENIED' ? 'BLOCKED' : (tx.decision || 'PENDING'))}
                    </span>
                  </td>
                  <td>
                    <a href="#" onclick="viewDelegation('\${tx.session_id}'); return false;" class="delegation-id" title="\${tx.session_id}">
                      \${tx.session_id.slice(0, 8)}...
                    </a>
                  </td>
                </tr>
              \`).join('')}
            </tbody>
          </table>
          \${hasMore ? \`<div class="expand-control"><button id="transactions-expand-btn" class="expand-btn" onclick="toggleExpand('transactions')">\${expanded ? 'SHOW LESS' : 'SHOW MORE'}</button></div>\` : ''}
        \`;
      } catch (e) {
        if (el) el.innerHTML = '<p class="error">ERROR: ' + e.message + '</p>';
      }
    }
    
    async function loadDelegationFilter() {
      try {
        const select = document.getElementById('delegation-filter');
        if (!select) return;
        const res = await fetch('/api/scoped-access');
        const sessions = await res.json();
        while (select.children.length > 1) {
          select.removeChild(select.lastChild);
        }
        sessions.forEach(s => {
          const opt = document.createElement('option');
          opt.value = s.session_id;
          const apisText = renderAllowedApisShort(s.allowed_apis, s.allowed_domains);
          opt.textContent = s.session_id.slice(0, 8) + ' - ' + (s.agent_id || 'Unknown') + ' - ' + apisText;
          select.appendChild(opt);
        });
      } catch (e) {
        console.error('Failed to load delegations for filter:', e);
      }
    }
    
    function viewDelegation(sessionId) {
      window.location.href = '/delegation/' + sessionId;
    }
    
    function filterByDelegation(sessionId) {
      const select = document.getElementById('delegation-filter');
      if (!select) return;
      select.value = sessionId;
      expandedState['transactions'] = false; // Reset expanded state when filtering
      setSection('audit');
      loadTransactions();
      const txSection = document.getElementById('transactions');
      if (!txSection.classList.contains('expanded')) {
        txSection.classList.add('expanded');
      }
      txSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
    
    async function revokeSession(sessionId) {
      if (!confirm('REVOKE DELEGATION?')) return;
      
      try {
        const res = await fetch('/api/scoped-access/' + sessionId + '/revoke', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        });
        const data = await res.json();
        if (data.success) {
          alert('DELEGATION REVOKED');
          loadDelegations();
        } else {
          alert('ERROR: ' + (data.error || 'UNKNOWN ERROR'));
        }
      } catch (e) {
        alert('ERROR: ' + e.message);
      }
    }
    
    // Load all data on page load
    setSection('activity');
    loadFirewallStats();
    loadFirewallAlerts();
    loadDelegations();
    loadTransactions();
    loadFirewallAudit();
    loadPolicies();
    refreshWallet();
    loadDelegationFilter().then(function() {
      const urlParams = new URLSearchParams(window.location.search);
      const sessionIdFromUrl = urlParams.get('session_id');
      if (sessionIdFromUrl) {
        filterByDelegation(sessionIdFromUrl);
      }
    });

    // Periodically refresh firewall alerts
    setInterval(loadFirewallAlerts, 5000);
  </script>
</body>
</html>
  `);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Pulse listening on http://0.0.0.0:${PORT}`);

  // Auto-register Pulse's own PID so the awal wrapper whitelists it.
  registerPid("pulse", process.pid);
  console.log(`Watchdog-Lite: registered Pulse PID ${process.pid}`);

  // Try to auto-detect Cursor and register it for monitoring.
  const cursorPid = autoDetectCursorPid();
  if (cursorPid) {
    registerPid("cursor", cursorPid);
    console.log(`Watchdog-Lite: auto-detected Cursor PID ${cursorPid}`);
  } else {
    console.log(
      "Watchdog-Lite: Cursor not detected. Register manually via POST /api/watchdog/register-pid or POST /api/watchdog/auto-detect-cursor"
    );
  }
});

