# Hackathon Agent

Autonomous agent that runs under the [Agent Control Plane](../dev/agent-control-spec.md): uses **Scoped Access** (Pulse), appears in the same dashboard (Agent Activity + Audit), and uses **3+ sponsor tools**. Built with **Mastra**; includes a **GUI** for agent thinking (plan + progress) and **Pulse skills** for approval (configurable base URL for non-localhost).

See **[DESIGN.md](./DESIGN.md)** for full design, framework choice (Mastra), architecture, GUI (agent thinking), Pulse skills/approval URL, sponsor tools as MCP/skills, demo scenario skills, and implementation phases.

## Sponsor tools (MVP)

| Sponsor | Role |
|--------|------|
| **Tavily** | Web search — agent uses it to research security vulnerabilities, CVEs, and best practices BEFORE writing code |
| **Neo4j** | Knowledge graph (optional) — store security findings |
| **Render** | Hosting for demo (optional) |

## Demo scenario

**Security-first coding agent:** Before writing any code, the agent researches common vulnerabilities (OWASP, CVEs), latest security best practices, and real-time advisories using Tavily. This grounds the agent in real-time security knowledge and produces more secure code.

## Quick start

```bash
cd agent
cp .env.example .env   # Set GROQ_API_KEY (or OPENAI_API_KEY), TAVILY_API_KEY, NEO4J_*, PULSE_BASE_URL, etc.
npm install
npm run build
node dist/index.js "Write a secure authentication module in JavaScript. Research common vulnerabilities first."
# Or with a goal as first argument:
node dist/index.js "Your goal here"
```

### Chat UI (browser)

A simple chat interface with **plan / progress** is included. It streams agent output and shows tool calls in a side panel.

```bash
npm run build
npm run start:ui
# Or: node dist/server.js
```

Then open **http://localhost:4021** (or set `AGENT_UI_PORT`). Enter a goal and click Send; the right panel shows tool calls (e.g. `request_scoped_access`, `tavily_search`, `neo4j_store_finding`) as they run, and the main area streams the assistant reply.

**Required for a full run:** One of `GROQ_API_KEY` or `OPENAI_API_KEY` (agent uses Groq if `GROQ_API_KEY` is set, else OpenAI). Optional: `TAVILY_API_KEY`, `NEO4J_URI`/`NEO4J_PASSWORD`, `PULSE_BASE_URL` (default `http://localhost:4020`). Without Tavily/Neo4j the agent will still run but those tools will return "not configured".

**Groq API:** Default model is `groq/llama-3.1-8b-instant` (fewer rate-limit issues). To use the 70B model set `GROQ_MODEL=groq/llama-3.3-70b-versatile` in `.env`. If you see rate limit or timeout errors, keep the default or switch to OpenAI.

### Access from another computer (hostname configuration)

To open the **dashboard** and **approval links** from a different machine (e.g. judge’s laptop):

1. **On the server** where the portal runs:
   - Portal already listens on `0.0.0.0:4020`, so it accepts connections from other hosts.
   - Set **`PUBLIC_BASE_URL`** to the URL that the other computer will use:
     - Same network: `http://YOUR_IP:4020` (e.g. `http://192.168.1.100:4020`) or `http://YOUR_HOSTNAME:4020`
     - Over the internet: use a tunnel (e.g. ngrok, Cloudflare Tunnel) and set `PUBLIC_BASE_URL=https://your-tunnel-url`
   - Example: `PUBLIC_BASE_URL=http://192.168.1.100:4020` then start the portal.

2. **On the agent** (if it runs on the same server):
   - Set **`PULSE_BASE_URL`** to that same URL so the agent talks to the portal and the approval URL in the response is openable from the other computer.
   - Example: `PULSE_BASE_URL=http://192.168.1.100:4020`

3. **On the other computer:** Open `http://YOUR_IP:4020/dashboard` (or your tunnel URL). Approval links in Scoped Access will use `PUBLIC_BASE_URL`, so they will work when clicked.

**Summary:** Set `PUBLIC_BASE_URL` (portal) and `PULSE_BASE_URL` (agent) to the same hostname/IP (and port) that the other computer uses to reach the server.
