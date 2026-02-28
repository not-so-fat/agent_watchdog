import { createTool } from "@mastra/core/tools";
import { z } from "zod";

const PULSE_BASE = process.env.PULSE_BASE_URL || "http://localhost:4020";

const requestScopedAccessSchema = z.object({
  summary: z.string().describe("Short title for the approval screen (~40 chars)"),
  description: z.string().describe("Detailed explanation: what the task is, why access is needed"),
  allowed_domains: z.array(z.string()).describe("Domains the agent will call (e.g. api.tavily.com, *.neo4j.io)"),
  ttl_seconds: z.number().default(600).describe("Grant TTL in seconds"),
  poll_until_approved: z.boolean().default(true).describe("If true, poll until user approves or denies"),
});

export const requestScopedAccessTool = createTool({
  id: "request_scoped_access",
  description:
    "Request Scoped Access (user approval) from the Pulse portal before calling external APIs. Call this first when the task needs Tavily, Neo4j, or other sponsor APIs. Returns approval_url for the user to open; if poll_until_approved is true, waits until approved and returns session_handle.",
  inputSchema: requestScopedAccessSchema,
  outputSchema: z.object({
    status: z.enum(["pending", "approved", "denied", "error"]),
    approval_url: z.string().optional(),
    request_id: z.string().optional(),
    session_handle: z.string().optional(),
    message: z.string().optional(),
  }),
  execute: async (inputData) => {
    const input = inputData as z.infer<typeof requestScopedAccessSchema>;
    const policy = {
      allowed_domains: input.allowed_domains,
      allowed_apis: input.allowed_domains.map((d) => ({
        domain: d,
        path: "*",
        method: "*",
        description: `Access ${d}`,
      })),
      summary: input.summary,
      description: input.description,
      max_total_spend: 0,
      max_per_tx: 0,
      ttl_seconds: input.ttl_seconds,
    };

    const res = await fetch(`${PULSE_BASE}/request-scoped-access`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agent_id: "hackathon-agent",
        user_id: "user-001",
        policy,
      }),
    });

    if (!res.ok) {
      const err = await res.text();
      return {
        status: "error" as const,
        message: `Pulse request failed: ${res.status} ${err}`,
      };
    }

    const data = (await res.json()) as {
      status: string;
      request_id: string;
      approval_url: string;
      message?: string;
    };

    if (data.status !== "pending" || !data.request_id || !data.approval_url) {
      return {
        status: (data.status as "approved" | "denied") || "error",
        approval_url: data.approval_url,
        request_id: data.request_id,
        message: data.message,
      };
    }

    if (!input.poll_until_approved) {
      console.log(`\n=== APPROVAL REQUIRED ===\nOpen in browser: ${data.approval_url}\n===========================\n`);
      return {
        status: "pending" as const,
        approval_url: data.approval_url,
        request_id: data.request_id,
        message: "User must open approval_url in a browser and approve. Then poll GET /request-scoped-access/" + data.request_id,
      };
    }

    console.log(`\n=== APPROVAL REQUIRED ===\nOpen in browser: ${data.approval_url}\n===========================\n`);

    const deadline = Date.now() + 5 * 60 * 1000;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 2000));
      const pollRes = await fetch(`${PULSE_BASE}/request-scoped-access/${data.request_id}`);
      if (!pollRes.ok) continue;
      const poll = (await pollRes.json()) as { status: string; session_handle?: string; reason?: string };
      if (poll.status === "approved" && poll.session_handle) {
        return {
          status: "approved" as const,
          approval_url: data.approval_url,
          request_id: data.request_id,
          session_handle: poll.session_handle,
          message: "Scoped Access granted.",
        };
      }
      if (poll.status === "denied") {
        return {
          status: "denied" as const,
          approval_url: data.approval_url,
          request_id: data.request_id,
          message: poll.reason || "User denied the request.",
        };
      }
    }

    return {
      status: "error" as const,
      approval_url: data.approval_url,
      request_id: data.request_id,
      message: "Timed out waiting for approval. Ask the user to open the approval URL and approve.",
    };
  },
});
