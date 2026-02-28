import type { DelegationSession, AllowedApi } from "./sessionManager";

export type PolicyDenyCode =
  | "DOMAIN_NOT_ALLOWED"
  | "API_NOT_ALLOWED"
  | "BUDGET_EXCEEDED"
  | "PER_TX_EXCEEDED"
  | "SESSION_EXPIRED";

export interface PolicyCheckInput {
  session: DelegationSession;
  domain: string;
  path: string;
  method: string;
  amountAtomic?: number;
}

export type PolicyCheckResult =
  | { decision: "ALLOW" }
  | { decision: "DENY"; deny_code: PolicyDenyCode };

export function checkPolicy(input: PolicyCheckInput): PolicyCheckResult {
  const { session, domain, path, method, amountAtomic } = input;

  const now = Date.now();
  if (session.expires_at <= now || session.revoked_at) {
    return { decision: "DENY", deny_code: "SESSION_EXPIRED" };
  }

  const normalizedDomain = domain.toLowerCase();
  const allowed = session.allowed_domains.some((d) => {
    const normalizedAllowed = d.toLowerCase();
    if (normalizedDomain.endsWith(normalizedAllowed)) return true;
    // Allow hostname to match "hostname:port" (URL hostname has no port)
    if (normalizedAllowed.includes(":")) {
      const allowedHost = normalizedAllowed.split(":")[0];
      if (normalizedDomain === allowedHost) return true;
    }
    return false;
  });
  if (!allowed) {
    return { decision: "DENY", deny_code: "DOMAIN_NOT_ALLOWED" };
  }

  // Check if API is allowed (if allowed_apis is defined)
  if (session.allowed_apis && session.allowed_apis.length > 0) {
    const apiAllowed = session.allowed_apis.some((api: AllowedApi) => {
      const normalizedApiDomain = api.domain.toLowerCase();
      let domainMatches = normalizedDomain.endsWith(normalizedApiDomain);
      if (!domainMatches && normalizedApiDomain.includes(":")) {
        const allowedHost = normalizedApiDomain.split(":")[0];
        domainMatches = normalizedDomain === allowedHost;
      }
      const methodMatches = api.method === "*" || api.method.toUpperCase() === method.toUpperCase();
      const pathMatches = matchPath(api.path, path);
      return domainMatches && methodMatches && pathMatches;
    });
    if (!apiAllowed) {
      return { decision: "DENY", deny_code: "API_NOT_ALLOWED" };
    }
  }

  if (typeof amountAtomic === "number") {
    const remaining = session.max_total_spend - session.total_spent_atomic;
    if (remaining <= 0) {
      return { decision: "DENY", deny_code: "BUDGET_EXCEEDED" };
    }
    if (amountAtomic > session.max_per_tx) {
      return { decision: "DENY", deny_code: "PER_TX_EXCEEDED" };
    }
    if (amountAtomic > remaining) {
      return { decision: "DENY", deny_code: "BUDGET_EXCEEDED" };
    }
  }

  return { decision: "ALLOW" };
}

// Match a glob-like pattern (e.g., "/api/*/book/*" matches "/api/united/book/123")
function matchPath(pattern: string, path: string): boolean {
  // Convert glob pattern to regex
  const regexPattern = pattern
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  const regex = new RegExp(`^${regexPattern}$`);
  return regex.test(path);
}

