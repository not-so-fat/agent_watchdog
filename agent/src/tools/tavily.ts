import { createTool } from "@mastra/core/tools";
import { z } from "zod";

const TAVILY_API = "https://api.tavily.com/search";

const tavilySearchSchema = z.object({
  query: z.string().describe("Search query"),
  max_results: z.number().min(1).max(20).default(5),
  search_depth: z.enum(["basic", "advanced", "fast", "ultra-fast"]).default("basic"),
});

export const tavilySearchTool = createTool({
  id: "tavily_search",
  description:
    "Search the web using Tavily. Use this to find real-time information, sponsor tool docs, or research topics. Returns titles, URLs, and content snippets.",
  inputSchema: tavilySearchSchema,
  outputSchema: z.object({
    success: z.boolean(),
    results: z.array(
      z.object({
        title: z.string(),
        url: z.string(),
        content: z.string(),
      })
    ),
    message: z.string().optional(),
  }),
  execute: async (inputData) => {
    const input = inputData as z.infer<typeof tavilySearchSchema>;
    const apiKey = process.env.TAVILY_API_KEY;
    if (!apiKey) {
      return { success: false, results: [], message: "TAVILY_API_KEY is not set." };
    }

    const res = await fetch(TAVILY_API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        api_key: apiKey,
        query: input.query,
        max_results: input.max_results,
        search_depth: input.search_depth,
      }),
    });

    if (!res.ok) {
      const err = await res.text();
      return { success: false, results: [], message: `Tavily API error: ${res.status} ${err}` };
    }

    const data = (await res.json()) as { results?: Array<{ title?: string; url?: string; content?: string }> };
    const results = (data.results || []).map((r) => ({
      title: r.title || "",
      url: r.url || "",
      content: (r.content || "").slice(0, 500),
    }));

    return { success: true, results };
  },
});
