import { Agent } from "@mastra/core/agent";
import { requestScopedAccessTool } from "./tools/pulse-approval";
import { tavilySearchTool } from "./tools/tavily";
import { neo4jStoreFindingTool, neo4jQueryTool } from "./tools/neo4j";
import { setDemoScenarioTool } from "./tools/demo-scenario";

const tools = {
  request_scoped_access: requestScopedAccessTool,
  tavily_search: tavilySearchTool,
  neo4j_store_finding: neo4jStoreFindingTool,
  neo4j_query: neo4jQueryTool,
  set_demo_scenario: setDemoScenarioTool,
};

const defaultInstructions = `You are an autonomous code-writing agent that grounds its work in real-time security research. Before writing code, you MUST research vulnerabilities, best practices, and latest docs using Tavily.

You have access to:
- request_scoped_access: Request user approval (Scoped Access) from the Pulse portal before calling external APIs. Call this FIRST when you need Tavily. Use allowed_domains: ["api.tavily.com"]. Wait for approval (poll_until_approved: true).
- tavily_search: Search the web for security vulnerabilities, CVEs, best practices, library docs, and real-time technical information. Use BEFORE writing code.
- neo4j_store_finding: DISABLED. Do NOT use. (Neo4j is not configured)
- neo4j_query: DISABLED. Do NOT use. (Neo4j is not configured)
- set_demo_scenario: Load a predefined scenario for consistent demos.

Workflow: (1) Understand the user's coding task; (2) Request Scoped Access if not already approved; (3) Use tavily_search to research: CVEs for libraries, security best practices, recent bugs, official docs; (4) Summarize findings and cite sources; (5) Write secure code. NEVER call neo4j tools.`;

// Groq: use GROQ_MODEL to override. Default 70b can hit rate limits; llama-3.1-8b-instant is more forgiving.
const groqModel = process.env.GROQ_MODEL || "groq/llama-3.1-8b-instant";
const openaiModel = "openai/gpt-4o-mini";
const model = process.env.GROQ_API_KEY ? groqModel : openaiModel;

export function createAgent(instructions?: string) {
  return new Agent({
    id: "hackathon-agent",
    name: "hackathon-agent",
    instructions: instructions || defaultInstructions,
    model,
    tools,
  });
}
