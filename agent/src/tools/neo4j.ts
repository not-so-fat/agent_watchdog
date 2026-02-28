import { createTool } from "@mastra/core/tools";
import { z } from "zod";
import neo4j, { Driver } from "neo4j-driver";

let driver: Driver | null = null;

function getDriver(): Driver | null {
  if (driver) return driver;
  const uri = process.env.NEO4J_URI;
  const user = process.env.NEO4J_USER || "neo4j";
  const password = process.env.NEO4J_PASSWORD;
  if (!uri || !password) return null;
  driver = neo4j.driver(uri, neo4j.auth.basic(user, password));
  return driver;
}

const storeFindingSchema = z.object({
  topic: z.string().describe("Topic or research question"),
  finding: z.string().describe("One finding or summary sentence"),
  source_url: z.string().optional().describe("Source URL"),
  source_title: z.string().optional().describe("Source title"),
});

export const neo4jStoreFindingTool = createTool({
  id: "neo4j_store_finding",
  description:
    "Store a research finding in the Neo4j knowledge graph. Creates or merges nodes: Topic, Finding, and optional Source. Use after Tavily search to persist what you learned.",
  inputSchema: storeFindingSchema,
  outputSchema: z.object({
    success: z.boolean(),
    message: z.string().optional(),
  }),
  execute: async (inputData) => {
    const input = inputData as z.infer<typeof storeFindingSchema>;
    const d = getDriver();
    if (!d) {
      return { success: false, message: "Neo4j not configured (NEO4J_URI, NEO4J_PASSWORD)." };
    }

    try {
      const session = d.session();
      try {
        await session.run(
          `
          MERGE (t:Topic { name: $topic })
          CREATE (f:Finding { text: $finding, created_at: datetime() })
          MERGE (t)-[:HAS_FINDING]->(f)
          RETURN 1
          `,
          {
            topic: input.topic,
            finding: input.finding,
          }
        );
        if (input.source_url) {
          await session.run(
            `
            MATCH (t:Topic { name: $topic })-[:HAS_FINDING]->(f:Finding { text: $finding })
            WITH f ORDER BY f.created_at DESC LIMIT 1
            MERGE (s:Source { url: $source_url })
            ON CREATE SET s.title = $source_title
            MERGE (f)-[:FROM_SOURCE]->(s)
            RETURN 1
            `,
            {
              topic: input.topic,
              finding: input.finding,
              source_url: input.source_url,
              source_title: input.source_title || null,
            }
          );
        }
      } finally {
        await session.close();
      }
      return { success: true, message: "Stored finding in Neo4j." };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return { success: false, message: `Neo4j error: ${msg}` };
    }
  },
});

const querySchema = z.object({
  topic: z.string().optional().describe("Filter by topic name; if omitted return all topics and their findings"),
  limit: z.number().default(20),
});

export const neo4jQueryTool = createTool({
  id: "neo4j_query",
  description:
    "Query the Neo4j knowledge graph for topics and findings. Use to summarize what was stored after research.",
  inputSchema: querySchema,
  outputSchema: z.object({
    success: z.boolean(),
    topics: z.array(
      z.object({
        name: z.string(),
        findings: z.array(z.string()),
        sources: z.array(z.object({ url: z.string(), title: z.string().optional() })),
      })
    ),
    message: z.string().optional(),
  }),
  execute: async (inputData) => {
    const input = inputData as z.infer<typeof querySchema>;
    const d = getDriver();
    if (!d) {
      return { success: false, topics: [], message: "Neo4j not configured." };
    }

    try {
      const session = d.session();
      let result;
      try {
        if (input.topic) {
          result = await session.run(
            `
            MATCH (t:Topic { name: $topic })-[:HAS_FINDING]->(f:Finding)
            OPTIONAL MATCH (f)-[:FROM_SOURCE]->(s:Source)
            RETURN t.name AS topic, collect(DISTINCT f.text) AS findings, collect(DISTINCT s { .url, .title }) AS sources
            LIMIT 1
            `,
            { topic: input.topic }
          );
        } else {
          result = await session.run(
            `
            MATCH (t:Topic)-[:HAS_FINDING]->(f:Finding)
            OPTIONAL MATCH (f)-[:FROM_SOURCE]->(s:Source)
            WITH t, collect(DISTINCT f.text)[..$limit] AS findings, collect(DISTINCT s { .url, .title })[..$limit] AS sources
            RETURN t.name AS topic, findings, sources
            LIMIT $limit
            `,
            { limit: input.limit }
          );
        }
      } finally {
        await session.close();
      }

      const topics = (result.records || []).map((r) => {
        const sources = (r.get("sources") as Array<{ url?: string; title?: string }> | undefined) || [];
        const dedup = sources.filter((s) => s && s.url);
        return {
          name: r.get("topic") as string,
          findings: (r.get("findings") as string[]) || [],
          sources: dedup.map((s) => ({ url: s.url!, title: s.title })),
        };
      });

      return { success: true, topics };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return { success: false, topics: [], message: `Neo4j error: ${msg}` };
    }
  },
});
