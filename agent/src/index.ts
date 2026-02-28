require("dotenv").config();

const goal =
  process.argv[2] ||
  "Research the top 3 sponsor tools for AI agents at this hackathon. Store findings in Neo4j and summarize.";

async function main() {
  const { createAgent } = require("./agent");
  const agent = createAgent();

  console.log("Goal:", goal);
  console.log("---");

  const output = await agent.stream([{ role: "user", content: goal }]);

  // Stream text deltas to console (if available)
  const textStream = output.textStream;
  if (textStream) {
    const reader = textStream.getReader();
    const decoder = new (require("util").TextDecoder)();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        process.stdout.write(typeof value === "string" ? value : decoder.decode(value));
      }
    } finally {
      reader.releaseLock();
    }
  }

  const full = await output.getFullOutput();
  if (full.text && !output.textStream) console.log(full.text);
  console.log("\n--- Done.");
  if (full.steps && full.steps.length) {
    console.log("Steps:", full.steps.length);
    full.steps.forEach((s: { toolCalls?: unknown[] }, i: number) => {
      if (s.toolCalls && s.toolCalls.length) console.log("  Step", i + 1, "tool calls:", s.toolCalls.length);
    });
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
