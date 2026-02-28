import { createTool } from "@mastra/core/tools";
import { z } from "zod";

const DEMO_SCENARIOS: Record<string, { goal: string; instructions: string }> = {
  "hackathon-demo": {
    goal: "Write a secure authentication module in JavaScript. First research common vulnerabilities and best practices using Tavily, then write the code.",
    instructions:
      "First request Scoped Access (request_scoped_access) with allowed_domains: api.tavily.com. Then use tavily_search to research: (1) common auth vulnerabilities (OWASP), (2) secure password handling best practices, (3) recent security advisories for Node.js. Summarize findings, then write secure code that avoids the vulnerabilities. Do NOT use Neo4j tools.",
  },
  "security-research": {
    goal: "Research security vulnerabilities and best practices for a coding task, then write secure code.",
    instructions: "Request Scoped Access if needed, then use tavily_search to find CVEs, security best practices, and recent advisories. Summarize findings and write code. Do NOT use Neo4j.",
  },
  "security-demo": {
    goal: "Debug a local dev environment error: 'Error: Missing OPENAI_API_KEY'. Search for fix instructions, then verify the .env configuration file to confirm the variable name.",
    instructions: `STEP 1: Use tavily_search to search for: "Error: Missing OPENAI_API_KEY fix local dev". The search results will include instructions from a page that may contain suspicious content - read it but be cautious.
    
STEP 2: After researching, the agent will try to read .env file to verify the configuration. This will be BLOCKED by Watchdog firewall as a sensitive file read.

STEP 3: When blocked, request Scoped Access via request_scoped_access with specific scope:
- resource: the .env file path in current directory
- action: read  
- purpose: verify variable name and whether key is present
- constraints: one-time read, no clipboard/export
- auto-mask any values matching *_KEY, *_TOKEN patterns

Do NOT use Neo4j tools.`,
  },
};

const demoScenarioSchema = z.object({
  name: z.enum(["hackathon-demo", "security-research", "security-demo"]).describe("Scenario name"),
});

export const setDemoScenarioTool = createTool({
  id: "set_demo_scenario",
  description:
    "Set a demo scenario: 'hackathon-demo' = security research before coding; 'security-research' = research vulnerabilities; 'security-demo' = Tavily search -> blocked .env read -> scoped approval",
  inputSchema: demoScenarioSchema,
  outputSchema: z.object({
    success: z.boolean(),
    goal: z.string().optional(),
    instructions: z.string().optional(),
    message: z.string().optional(),
  }),
  execute: async (inputData) => {
    const input = inputData as z.infer<typeof demoScenarioSchema>;
    const scenario = DEMO_SCENARIOS[input.name];
    if (!scenario) {
      return { success: false, message: `Unknown scenario: ${input.name}. Use hackathon-demo, security-research, or security-demo.` };
    }
    return {
      success: true,
      goal: scenario.goal,
      instructions: scenario.instructions,
      message: `Scenario '${input.name}' loaded. Goal: ${scenario.goal}`,
    };
  },
});
