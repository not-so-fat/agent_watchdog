import { db } from "./db";

export interface AllowedApi {
  domain: string;
  path: string;
  method: string;
  description?: string;
}

export interface CliCapabilities {
  commands_allow?: string[];
  commands_deny?: string[];
  cwd_allow?: string[];
}

export interface GrantCapabilities {
  cli?: CliCapabilities;
  // Future: net, payment, etc.
  // net?: { domains_allow?: string[] };
  // payment?: { max_total_usdc?: number; max_tx_usdc?: number };
}

export interface DelegationSession {
  session_id: string;
  user_id: string | null;
  agent_id: string | null;
  max_total_spend: number;
  max_per_tx: number;
  total_spent_atomic: number;
  allowed_domains: string[];
  allowed_apis: AllowedApi[];
  summary: string | null;
  description: string | null;
  ttl_seconds: number;
  expires_at: number;
  last_counter: number;
  created_at: number | null;
  revoked_at: number | null;
  capabilities: GrantCapabilities | undefined;
}

export function getSession(sessionHandle: string): DelegationSession | null {
  const row = db
    .prepare(
      `SELECT session_id, user_id, agent_id,
              max_total_spend, max_per_tx, total_spent_atomic,
              allowed_domains, allowed_apis, ttl_seconds, expires_at,
              last_counter, revoked_at, created_at, summary, description, capabilities
       FROM Delegation_Sessions
       WHERE session_id = ?`
    )
    .get(sessionHandle) as
    | {
        session_id: string;
        user_id: string | null;
        agent_id: string | null;
        max_total_spend: number;
        max_per_tx: number;
        total_spent_atomic: number;
        allowed_domains: string;
        allowed_apis: string;
        ttl_seconds: number;
        expires_at: number;
        last_counter: number;
        created_at: number | null;
        revoked_at: number | null;
        summary: string | null;
        description: string | null;
        capabilities?: string | null;
      }
    | undefined;

  if (!row) return null;

  return {
    session_id: row.session_id,
    user_id: row.user_id,
    agent_id: row.agent_id,
    max_total_spend: Number(row.max_total_spend) || 0,
    max_per_tx: Number(row.max_per_tx) || 0,
    total_spent_atomic: Number(row.total_spent_atomic) || 0,
    allowed_domains: JSON.parse(row.allowed_domains || "[]"),
    allowed_apis: JSON.parse(row.allowed_apis || "[]"),
    summary: row.summary,
    description: row.description,
    ttl_seconds: row.ttl_seconds,
    expires_at: row.expires_at,
    last_counter: row.last_counter,
    created_at: row.created_at,
    revoked_at: row.revoked_at,
    capabilities: row.capabilities
      ? (JSON.parse(row.capabilities) as GrantCapabilities)
      : undefined,
  };
}

export function updateLastCounter(
  session_id: string,
  counter: number
): void {
  db.prepare(
    `UPDATE Delegation_Sessions
     SET last_counter = @counter
     WHERE session_id = @session_id`
  ).run({ session_id, counter });
}

export function addSpentAtomic(
  session_id: string,
  amountAtomic: number
): void {
  db.prepare(
    `UPDATE Delegation_Sessions
     SET total_spent_atomic = total_spent_atomic + @amount
     WHERE session_id = @session_id`
  ).run({ session_id, amount: amountAtomic });
}

export function listSessions(activeOnly: boolean = false): DelegationSession[] {
  const now = Date.now();
  
  let rows: Array<{
    session_id: string;
    user_id: string | null;
    agent_id: string | null;
    max_total_spend: number;
    max_per_tx: number;
    total_spent_atomic: number;
    allowed_domains: string;
    allowed_apis: string;
    ttl_seconds: number;
    expires_at: number;
    last_counter: number;
    revoked_at: number | null;
    created_at: number;
    summary: string | null;
    description: string | null;
    capabilities?: string | null;
  }>;

  if (activeOnly) {
    rows = db
      .prepare(
        `SELECT session_id, user_id, agent_id,
                max_total_spend, max_per_tx, total_spent_atomic,
                allowed_domains, allowed_apis, ttl_seconds, expires_at,
                last_counter, revoked_at, created_at, summary, description, capabilities
         FROM Delegation_Sessions
         WHERE revoked_at IS NULL AND expires_at > @now
         ORDER BY created_at DESC`
      )
      .all({ now }) as typeof rows;
  } else {
    rows = db
      .prepare(
        `SELECT session_id, user_id, agent_id,
                max_total_spend, max_per_tx, total_spent_atomic,
                allowed_domains, allowed_apis, ttl_seconds, expires_at,
                last_counter, revoked_at, created_at, summary, description, capabilities
         FROM Delegation_Sessions
         ORDER BY created_at DESC`
      )
      .all() as typeof rows;
  }

  return rows.map((row) => ({
    session_id: row.session_id,
    user_id: row.user_id,
    agent_id: row.agent_id,
    max_total_spend: Number(row.max_total_spend) || 0,
    max_per_tx: Number(row.max_per_tx) || 0,
    total_spent_atomic: Number(row.total_spent_atomic) || 0,
    allowed_domains: JSON.parse(row.allowed_domains || "[]"),
    allowed_apis: JSON.parse(row.allowed_apis || "[]"),
    summary: row.summary,
    description: row.description,
    ttl_seconds: row.ttl_seconds,
    expires_at: row.expires_at,
    last_counter: row.last_counter,
    created_at: row.created_at,
    revoked_at: row.revoked_at,
    capabilities: row.capabilities
      ? (JSON.parse(row.capabilities) as GrantCapabilities)
      : undefined,
  }));
}

export function revokeSession(session_id: string, reason?: string): void {
  const now = Date.now();
  db.prepare(
    `UPDATE Delegation_Sessions
     SET revoked_at = @revoked_at, revoked_reason = @reason
     WHERE session_id = @session_id`
  ).run({
    session_id,
    revoked_at: now,
    reason: reason || "Revoked via dashboard",
  });
}


