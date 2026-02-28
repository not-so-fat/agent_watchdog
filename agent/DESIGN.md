# Autonomous Agent — Design (Hackathon)

## 1. Vision & Fit

**Our story:** Agent Control Plane = **safe autonomy**. Watchdog enforces runtime safety (file/syscall monitoring); Pulse grants **Scoped Access** (time-bounded, capability-limited permissions) and provides a single dashboard for activity, audit, and policies.

This agent is the **first autonomous agent that runs under that control plane**: it requests Scoped Access, performs real work using sponsor APIs, and all of its actions and API usage appear in the same dashboard (Agent Activity, Audit Log, Scoped Access). The demo shows **autonomy + control** in one place.

**Hackathon criteria addressed:**
- **Autonomy** — Agent acts on real-time data (user intent, search results, stored context) without manual steps after approval.
- **Idea** — Real-world value: safe, auditable AI agents that need web knowledge and memory.
- **Technical implementation** — Agent process on same server; uses Local Portal for grants and audit; Watchdog can monitor local tool use.
- **Tool use** — **3+ sponsor tools** (see below).
- **Presentation** — One dashboard: trigger agent → see Scoped Access → see it use Tavily/Neo4j → see audit trail.

---

## 1b. Agent Framework Choice

We use **Mastra** as the agent runtime. Comparison:

| Framework | Pros | Cons |
|-----------|------|------|
| **Mastra** | TypeScript-native, **MCP client** (sponsor tools as MCP or native tools), **streaming events** (plan + progress for GUI), **human-in-the-loop** (suspend for approval), 40+ LLM providers, workflows, actively maintained (Gatsby team) | Newer than LangChain |
| mcp-use | Strong MCP conformance, multi-LLM | Focused on MCP only; less built-in streaming/UI story |
| LangChain.js | Mature, many integrations | Heavier; MCP support added later; less “agent + streaming” out of the box |
| Vercel AI SDK | Great for chat UI, streaming | Not an agent framework; no built-in tools/MCP orchestration |

**Why Mastra:** Fits our stack (Node/TS, same as Pulse), gives us **agent.stream()** with `step-start`, `tool-call`, `tool-result`, `text-delta`, `finish` so we can drive a **GUI that shows “agent thinking”** (plan + progress). We can implement **Pulse approval** as a Mastra tool that suspends until the user approves (open approval URL → poll status). Sponsor tools (Tavily, Neo4j, Reka) can be **Mastra tools** (or MCP tools via Mastra’s MCPClient). **Demo scenario skills** can be additional Mastra tools or a small “scenario” plugin that injects instructions/tools per demo.

---

## 2. Sponsor Tools (≥ 3)

| Sponsor | Use in agent | Why |
|--------|----------------|-----|
| **Tavily** | Web search / research | Agent’s primary “sensor”: real-time web context for questions. Fits autonomy (no manual copy-paste). |
| **Neo4j** | Knowledge graph | Agent stores **findings** and **sources** as a graph (Topic → Finding → Source). Gives the agent memory and showcases graph + retrieval. |
| **Reka Vision** (optional 4th) | Image understanding | If we add “analyze screenshot” or “describe image” step (e.g. dashboard screenshot → summary). Strengthens “Most Innovative Use of Reka Vision”. |
| **Render** | Hosting | Run the agent (or entire stack) on Render for the demo so judges see a live URL; fits “Best Use of Render”. |

**Minimum viable:** Tavily + Neo4j + one more (Reka Vision **or** Render deployment). Prefer **Tavily + Neo4j + Render** for simplicity (no image pipeline needed for MVP).

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  User / Judge (browser)                                          │
│  • Opens dashboard (Pulse :4020)                                 │
│  • Approves Scoped Access for "hackathon-agent"                  │
│  • Sees Agent Activity (Watchdog) + Audit (Pulse)                │
└───────────────────────────┬─────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│  Same server (or Render)                                          │
│  ┌─────────────────────┐  ┌─────────────────────┐                 │
│  │  Pulse (Local Portal)│  │  Watchdog           │                 │
│  │  :4020               │  │  :3000 (eBPF+API)  │                 │
│  │  • Scoped Access     │  │  • File/syscall     │                 │
│  │  • Audit / Dashboard│  │    alerts           │                 │
│  └──────────┬───────────┘  └──────────┬──────────┘                 │
│             │                         │                            │
│             │  request grant          │  (optional: monitor       │
│             │  report actions         │   agent process)           │
│             ▼                         ▼                            │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  Hackathon Agent (this repo)                                  │ │
│  │  • Reads user goal (CLI arg or simple UI)                    │ │
│  │  • Requests Scoped Access via Pulse (HMAC)                     │ │
│  │  • Loop: Tavily search → Neo4j store → decide next step       │ │
│  │  • Reports each action to Pulse (audit trail)                 │ │
│  │  • Uses Reka Vision if we add image step                      │ │
│  └─────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────┘
                             │
                             │  HTTPS
┌────────────────────────────▼────────────────────────────────────┐
│  Sponsor APIs (external)                                         │
│  • Tavily (search / research)                                   │
│  • Neo4j (Aura or self‑hosted graph)                             │
│  • Reka (vision) — optional                                       │
└──────────────────────────────────────────────────────────────────┘
```

**Data flow (high level):**
1. User starts the agent with a **goal** (e.g. “Research the top 3 sponsor APIs for AI agents”).
2. Agent calls Pulse `POST /request-scoped-access` with a small policy (e.g. `allowed_domains: ["api.tavily.com", "*.neo4j.io"]`, TTL 10 min). User approves in dashboard.
3. Agent receives `session_handle` and uses it for any outbound API calls (or we log actions to Pulse for audit).
4. Agent loop: **Tavily search** → parse results → **Neo4j** (create/merge nodes: Topic, Finding, Source) → repeat or summarize.
5. Each “action” (search query, Neo4j write) is sent to Pulse as an audit event (or we use existing transaction log).
6. Dashboard shows: Active grant for “hackathon-agent”, Audit log entries (e.g. “Tavily search: …”, “Neo4j merge: …”), and Watchdog alerts if the agent process touches sensitive files.

---

## 3b. GUI: Agent Thinking (Plan + Progress)

We want a **GUI to access the agent** and see **agent thinking** — plan and progress — in real time.

**Mechanics:**
- The agent runs on Mastra with **streaming** enabled. The server (or a small agent API in Pulse) exposes a stream of events: `start`, `step-start`, `step-finish`, `tool-call`, `tool-result`, `text-delta`, `finish`.
- A **web UI** (new tab in the dashboard or a dedicated `/agent` page in the Local Portal) connects to this stream (SSE or WebSocket) and displays:
  - **Plan:** high-level steps (e.g. "Request Scoped Access", "Search with Tavily", "Store in Neo4j", "Summarize") — derived from agent instructions or from the first `step-start` / tool names.
  - **Progress:** live updates as events arrive: current step, last tool called (e.g. `tavily_search`), tool args/result summary, and streaming text deltas.
- User can **start a run** from the GUI (goal input) and **approve Scoped Access** when the agent calls the Pulse approval tool (approval URL shown in the same UI, or open in same tab).

**Implementation options:**
- **Option A:** Add an "Agent" tab to the existing Pulse dashboard; embed an iframe or a panel that hits `GET /agent/stream` (or `POST /agent/run` with SSE) on the agent service; render events as a timeline.
- **Option B:** Standalone agent UI (e.g. Next.js or a simple HTML+JS page) that talks to the agent API; deploy alongside Pulse on the same host so one URL gives dashboard + agent UI.

**Minimum for demo:** Single page that shows (1) input for goal, (2) "Run" button, (3) live log of events (plan step, tool name, short result) and (4) link to approval URL when "request_scoped_access" is called.

---

## 4. Agent Behavior (MVP)

**Input:** One-shot goal from CLI or a minimal “task” API, e.g.:
```bash
node agent/run.js "What are the top 3 sponsor tools for AI agents at this hackathon?"
```

**Autonomous loop (simplified):**
1. **Request Scoped Access** (Pulse) — scope includes Tavily and Neo4j domains; store `session_handle`.
2. **Plan** (internal or 1 LLM call): break goal into 2–4 search queries.
3. **For each query:**
   - Call **Tavily** search (or research) API.
   - Parse results; extract “findings” and “sources”.
   - **Neo4j**: merge nodes (e.g. `(Topic)-[:HAS_FINDING]->(Finding)-[:FROM_SOURCE]->(Source)`).
4. **Summarize:** read from Neo4j (Cypher or vector/similarity if available), generate short report.
5. **Report to audit:** optional — send each action (query, Neo4j op) to Pulse so it appears in the dashboard Audit Log.

**Output:** Printed report + graph in Neo4j visible in Neo4j browser (or we export a simple summary from Neo4j for the demo).

**No previous projects:** This agent is new; the Control Plane (Watchdog + Pulse) is the existing stack we’re extending.

---

## 4b. Pulse Skills (agent-pulse): Approval & Base URL

The agent must **ask the user for approval** via Scoped Access. Today this is documented in **agent-pulse-delegation** (Cursor skill under `pulse/.cursor/skills/`): the agent calls `POST /request-scoped-access` and gets back an `approval_url`; the user opens it to approve.

**Requirements:**
- **Configurable base URL:** When the portal is not on localhost (e.g. deployed on Render or accessed via a shared URL), `approval_url` must point to that host so the judge/user can open it. So:
  - Pulse server: build `approval_url` from **`PUBLIC_BASE_URL`** (env) when set, otherwise from `Host` header, and only fall back to `http://localhost:PORT` when both are missing or for local dev.
  - agent-pulse-delegation skill: document that the agent should use **`PULSE_BASE_URL`** (or the same env) for all Pulse calls (`/request-scoped-access`, `/api/scoped-access`, etc.); the approval URL in the response will then work when opened from any machine.
- **Skill location:** Keep and extend the existing **agent-pulse-delegation** skill so the Mastra agent can use it as the single "request approval" flow: (1) call Pulse with policy, (2) present approval URL to the user (e.g. in the agent GUI), (3) poll until approved/denied, (4) continue with `session_handle` or stop.

No change to the *contract* of the API; only URL construction and skill docs so the agent works in non-localhost environments.

---

## 4c. Sponsor Tools as MCP/Skills; Demo Scenario Skills

**Sponsor tools as Mastra tools or MCP:**
- **Tavily** — Implement as a Mastra tool (e.g. `tavily_search` / `tavily_research`) that calls the Tavily API; optionally also expose via a small MCP server so other clients can use it. The agent uses it for web search/research.
- **Neo4j** — Implement as Mastra tools: e.g. `neo4j_store_finding`, `neo4j_query` (read back topics/findings/sources). Optionally wrap in an MCP server for reuse.
- **Reka Vision** (optional) — Mastra tool `reka_describe_image` that calls Reka's vision API; agent can use it when the scenario includes image input.

We **equip** these so the Mastra agent discovers and uses them (either as native tools or via Mastra's MCPClient connecting to our MCP servers).

**Demo scenario skills:**
- To **control behavior** for the 3-minute demo, add **demo scenario skills**: e.g. a tool or a small "scenario" config that:
  - Sets a **predefined goal** (e.g. "Research top 3 sponsor tools for AI agents") and/or
  - Injects **instructions** (e.g. "Always request Scoped Access first", "Use at most 3 Tavily queries", "Summarize from Neo4j at the end") and/or
  - **Enables/disables** certain tools or steps (e.g. "hackathon-demo" mode: Tavily + Neo4j only, no Reka).
- Implementation: a Mastra tool like `set_demo_scenario(name: "hackathon-demo")` that updates agent context/instructions, or a separate "scenario" loader that configures the agent before run. This keeps the main agent generic while making the demo reproducible.

---

## 5. Implementation Phases

| Phase | What | Time (rough) |
|-------|------|----------------|
| **1. Skeleton** | `agent/` dir: Node or Python runner; read goal from CLI; env vars for API keys (Tavily, Neo4j, Reka, Pulse base URL + secret). | 30 min |
| **2. Pulse integration** | Call `POST /request-scoped-access` with a minimal policy; parse `session_handle`; (optional) call `POST /api/transactions` or a small “audit” endpoint to log actions. | 45 min |
| **3. Tavily** | One Tavily search call; parse response; print titles/snippets. | 30 min |
| **4. Neo4j** | Create AuraDB free instance; connect; run one Cypher `MERGE` for Topic/Finding/Source; read back. | 45 min |
| **5. Loop** | Combine: multiple Tavily queries → Neo4j writes → summarize from graph. | 45 min |
| **6. Audit trail** | Ensure each Tavily/Neo4j action is logged (e.g. via Pulse or local log that we can point to in the demo). | 30 min |
| **7. Reka (optional)** | If time: one “describe image” or “summarize screenshot” call; add result to Neo4j or report. | 30 min |
| **8. Render** | Deploy agent (or full stack) on Render; document URL for submission. | 30 min |

Total MVP (without Reka): ~4 h. With Reka + buffer: fits 11:00–16:30.

---

## 6. Demo Script (3 minutes)

1. **Show dashboard** (0:00–0:30)  
   One tab: Agent Activity (Watchdog) + Scoped Access (Pulse). “This is our Agent Control Plane: every agent action can be seen and controlled here.”

2. **Start agent** (0:30–1:00)  
   Run: “Research top 3 sponsor tools for AI agents.” Agent requests Scoped Access; show approval in dashboard; grant appears under Active Grants.

3. **Autonomy** (1:00–2:00)  
   Agent uses Tavily (show logs or a simple “last query” in UI); writes to Neo4j; show Neo4j browser with the graph (Topic → Finding → Source). “The agent is acting on its own within the scope we approved.”

4. **Audit** (2:00–2:30)  
   Switch to Audit Log: show entries for “Tavily search” and “Neo4j” actions. “Every action is recorded; we can revoke the grant anytime.”

5. **Wrap** (2:30–3:00)  
   “We used Tavily for search, Neo4j for knowledge graph, and [Render for hosting]. The agent runs under Scoped Access so it’s autonomous but safe and auditable.”

---

## 7. Repo Layout (proposed)

```
agent/
├── DESIGN.md           # This file
├── README.md           # How to run; env vars; 3 sponsor tools
├── package.json        # Mastra, tools, optional MCP deps
├── src/
│   ├── index.ts        # Mastra agent entry; stream endpoint for GUI
│   ├── agent.ts        # createAgent with tools + instructions
│   ├── tools/
│   │   ├── pulse-approval.ts   # Request Scoped Access (uses PULSE_BASE_URL)
│   │   ├── tavily.ts          # Tavily search / research
│   │   ├── neo4j.ts          # neo4j_store_finding, neo4j_query
│   │   ├── reka.ts            # (Optional) Reka Vision
│   │   └── demo-scenario.ts   # set_demo_scenario for controlled demo
│   └── server.ts       # Optional: SSE/API for agent GUI (or mount in Pulse)
├── .env.example        # TAVILY_API_KEY, NEO4J_URI, NEO4J_AUTH, PULSE_BASE_URL, PUBLIC_BASE_URL, PULSE_SECRET, REKA_API_KEY
└── run.js              # CLI entry; invokes agent with goal
```

**Pulse (agent-pulse):**
- `pulse/.cursor/skills/agent-pulse-delegation/SKILL.md` — Update to document `PULSE_BASE_URL` / `PUBLIC_BASE_URL` for non-localhost.
- `pulse/local-portal/src/server.ts` — Build `approval_url` from `PUBLIC_BASE_URL` or `Host` when not localhost (see 4b).

---

## 8. Success Criteria

- [ ] Agent runs on the same server (or on Render) and requests Scoped Access from Pulse.
- [ ] Agent uses **Tavily** for at least one search/research call.
- [ ] Agent uses **Neo4j** to store and read back structured findings (graph).
- [ ] At least one more sponsor (Reka Vision **or** Render deployment).
- [ ] Dashboard shows the grant and (if implemented) audit entries for the agent’s actions.
- [ ] 3-minute demo is repeatable and shows autonomy + control in one place.

---

## 9. Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Pulse grant flow too heavy for demo | Pre-approve a long-lived grant before the demo; agent only uses it. |
| Neo4j Aura signup slow | Use Neo4j Desktop or Docker Neo4j locally; document Aura for “real” deploy. |
| Tavily rate limit | Cache one search result for the demo; run loop once. |
| Judge’s machine can’t reach server | Deploy on Render and use public URL; or record a 3-min video as backup. |

---

*Next step: implement Phase 1 (skeleton) in `agent/` and wire env vars + Pulse base URL.*
