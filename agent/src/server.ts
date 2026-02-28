require("dotenv").config();
import express, { Request, Response } from "express";
import { createAgent } from "./agent";

const app = express();
const PORT = Number(process.env.AGENT_UI_PORT) || 4021;

app.use(express.json());

// Inline chat UI: standard chat + plan/progress panel (matches Pulse dashboard style)
const CHAT_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Agent Watchdog</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
    * { box-sizing: border-box; }
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      margin: 0;
      background: #0D0D0D;
      color: #E0E0E0;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    .top-bar {
      padding: 12px 20px;
      border-bottom: 1px solid #708090;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .top-bar h1 { margin: 0; font-size: 1.25em; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
    .container { display: flex; flex: 1; min-height: 0; overflow: hidden; }
    .chat-col { flex: 1; display: flex; flex-direction: column; border-right: 1px solid #708090; min-width: 0; overflow: hidden; }
    .progress-col { width: 380px; flex-shrink: 0; display: flex; flex-direction: column; background: rgba(0,0,0,0.2); overflow: hidden; }
    .progress-col h2 {
      margin: 0; padding: 12px 16px; font-size: 0.75em; font-weight: 600;
      text-transform: uppercase; letter-spacing: 0.08em; color: #708090;
      border-bottom: 1px solid #708090;
    }
    #progress-list {
      flex: 1; overflow-y: auto; padding: 12px; font-size: 0.85em;
      font-family: 'IBM Plex Mono', monospace;
    }
    .progress-item { margin-bottom: 10px; padding: 8px 10px; border: 1px solid #708090; overflow: hidden; word-break: break-word; }
    .progress-item.tool-call { border-left: 3px solid #4FD1C5; }
    .progress-item.tool-result { border-left: 3px solid #708090; color: #9ca3af; }
    .progress-item.error { border-left: 3px solid #8B0000; color: #8B0000; }
    .progress-item .name { font-weight: 600; color: #4FD1C5; }
    .progress-item .preview { margin-top: 4px; color: #9ca3af; font-size: 0.9em; max-height: 60px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    #messages {
      flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 16px;
    }
    .msg { max-width: 85%; }
    .msg.user { align-self: flex-end; background: #1a1a1a; border: 1px solid #708090; padding: 12px 16px; }
    .msg.assistant { align-self: flex-start; background: #111; border: 1px solid #374151; padding: 12px 16px; white-space: pre-wrap; word-break: break-word; }
    .msg .role { font-size: 0.7em; text-transform: uppercase; letter-spacing: 0.05em; color: #708090; margin-bottom: 6px; }
    .input-row {
      padding: 16px 20px; border-top: 1px solid #708090;
      display: flex; gap: 12px; align-items: flex-end;
    }
    #goal-input {
      flex: 1; min-height: 44px; max-height: 120px; padding: 10px 14px;
      background: #0D0D0D; border: 1px solid #708090; color: #E0E0E0;
      font-family: 'Inter', sans-serif; font-size: 0.95em; resize: none;
    }
    #goal-input:focus { outline: none; border-color: #4FD1C5; }
    #send-btn, #demo-btn, #demo2-btn {
      padding: 10px 20px; border: 1px solid #4FD1C5; background: #0D0D0D; color: #4FD1C5;
      font-family: 'Inter', sans-serif; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em;
      cursor: pointer;
    }
    #demo-btn, #demo2-btn { background: #1a3a3a; border-color: #4FD1C5; }
    #demo2-btn { background: #3a1a3a; }
    #send-btn:hover, #demo-btn:hover, #demo2-btn:hover { background: rgba(79, 209, 197, 0.1); }
    #send-btn:disabled, #demo-btn:disabled, #demo2-btn:disabled { opacity: 0.5; cursor: not-allowed; border-color: #708090; color: #708090; }
    .loading { color: #708090; }
    .error-msg { color: #8B0000; }
  </style>
</head>
<body>
  <div class="top-bar">
    <h1>Agent Watchdog</h1>
    <span style="font-size:0.8em; color:#708090;">
      <a href="http://localhost:4020" target="_blank" style="color:#4FD1C5;text-decoration:none;">Pulse Portal</a> &nbsp;|&nbsp; Plan & progress →
    </span>
  </div>
  <div class="container">
    <div class="chat-col">
      <div id="messages"></div>
      <div class="input-row">
        <textarea id="goal-input" rows="2" placeholder="Enter a coding task (e.g. Write a secure auth module in JavaScript)"></textarea>
        <button id="demo2-btn" type="button">Security Demo (File Access)</button>
        <button id="demo-btn" type="button">Security Research</button>
        <button id="send-btn" type="button">Send</button>
      </div>
    </div>
    <div class="progress-col">
      <h2>Plan / Progress</h2>
      <div id="progress-list">
        <div class="loading" id="progress-placeholder">Send a message to see steps and tool calls.</div>
      </div>
    </div>
  </div>
  <script>
    const messagesEl = document.getElementById('messages');
    const progressList = document.getElementById('progress-list');
    const progressPlaceholder = document.getElementById('progress-placeholder');
    const goalInput = document.getElementById('goal-input');
    const sendBtn = document.getElementById('send-btn');

    function addMessage(role, content) {
      const div = document.createElement('div');
      div.className = 'msg ' + role;
      div.innerHTML = '<div class="role">' + role + '</div><div class="content">' + escapeHtml(content) + '</div>';
      messagesEl.appendChild(div);
      messagesEl.scrollTop = messagesEl.scrollHeight;
      return div.querySelector('.content');
    }

    function escapeHtml(s) {
      const div = document.createElement('div');
      div.textContent = s;
      return div.innerHTML;
    }

    function addProgress(type, data) {
      progressPlaceholder.style.display = 'none';
      const div = document.createElement('div');
      div.className = 'progress-item ' + type;
      if (type === 'tool-call') {
        div.innerHTML = '<span class="name">' + escapeHtml(data.name || 'tool') + '</span>' +
          (data.args ? '<div class="preview">' + escapeHtml(JSON.stringify(data.args).slice(0, 120)) + '</div>' : '');
      } else if (type === 'tool-result') {
        const preview = typeof data.result === 'string' ? data.result.slice(0, 100) : JSON.stringify(data.result || {}).slice(0, 100);
        div.innerHTML = '<span class="name">' + escapeHtml(data.name || '') + '</span><div class="preview">' + escapeHtml(preview) + '</div>';
      } else if (type === 'error') {
        div.textContent = data.message || 'Error';
      }
      progressList.appendChild(div);
      progressList.scrollTop = progressList.scrollHeight;
    }

    async function send() {
      const goal = (goalInput.value || '').trim();
      if (!goal) return;
      sendBtn.disabled = true;
      progressList.innerHTML = '';
      progressPlaceholder.style.display = 'block';
      progressPlaceholder.textContent = 'Running...';
      addMessage('user', goal);
      const contentEl = addMessage('assistant', '');
      let fullText = '';

      try {
        const res = await fetch('/api/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ goal: goal })
        });
        if (!res.ok) throw new Error(res.status + ' ' + res.statusText);
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\\n');
          buffer = lines.pop() || '';
          for (const line of lines) {
            if (!line.trim()) continue;
            try {
              const ev = JSON.parse(line);
              if (ev.type === 'text') { fullText += ev.delta || ''; contentEl.textContent = fullText; messagesEl.scrollTop = messagesEl.scrollHeight; }
              else if (ev.type === 'tool_call') addProgress('tool-call', { name: ev.name, args: ev.args });
              else if (ev.type === 'tool_result') addProgress('tool-result', { name: ev.name, result: ev.result });
              else if (ev.type === 'error') addProgress('error', { message: ev.message });
              else if (ev.type === 'done') progressPlaceholder.textContent = 'Done.';
            } catch (_) {}
          }
        }
        if (buffer.trim()) {
          try {
            const ev = JSON.parse(buffer);
            if (ev.type === 'text') { fullText += ev.delta || ''; contentEl.textContent = fullText; }
            else if (ev.type === 'tool_call') addProgress('tool-call', { name: ev.name, args: ev.args });
            else if (ev.type === 'tool_result') addProgress('tool-result', { name: ev.name, result: ev.result });
            else if (ev.type === 'done') progressPlaceholder.textContent = 'Done.';
          } catch (_) {}
        }
      } catch (e) {
        contentEl.textContent = '';
        contentEl.classList.add('error-msg');
        contentEl.textContent = 'Error: ' + e.message;
        addProgress('error', { message: e.message });
      }
      progressPlaceholder.textContent = 'Send a message to see steps and tool calls.';
      sendBtn.disabled = false;
    }

    sendBtn.addEventListener('click', send);
    goalInput.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
    });

    // Demo buttons - auto-fill prompts
    const demoBtn = document.getElementById('demo-btn');
    const demo2Btn = document.getElementById('demo2-btn');
    const DEMO_PROMPT = "Write a secure authentication module in JavaScript. First research common vulnerabilities and best practices using Tavily, then write the code.";
    const DEMO2_PROMPT = "Debug a local dev environment error: 'Error: Missing OPENAI_API_KEY'. Search for fix instructions, then verify the .env configuration file to confirm the variable name.";
    demoBtn.addEventListener('click', function() {
      goalInput.value = DEMO_PROMPT;
      send();
    });
    demo2Btn.addEventListener('click', function() {
      goalInput.value = DEMO2_PROMPT;
      send();
    });
  </script>
</body>
</html>
`;

app.get("/", (_req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/html");
  res.send(CHAT_HTML);
});

app.post("/api/run", async (req: Request, res: Response) => {
  const goal = (req.body && req.body.goal) || "Hello, what can you do?";
  res.setHeader("Content-Type", "application/x-ndjson");
  res.setHeader("Transfer-Encoding", "chunked");
  res.setHeader("Cache-Control", "no-cache");
  res.flushHeaders();

  const send = (obj: Record<string, unknown>) => {
    res.write(JSON.stringify(obj) + "\n");
  };

  try {
    const agent = createAgent();
    const output = await agent.stream([{ role: "user", content: goal }]);
    const stream = output.fullStream;
    if (!stream) {
      const full = await output.getFullOutput();
      send({ type: "text", delta: full.text || "" });
      send({ type: "done" });
      res.end();
      return;
    }
    const reader = stream.getReader();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = value as { type?: string; payload?: Record<string, unknown> };
      if (!chunk) continue;
      const t = chunk.type;
      const p = (chunk.payload || chunk) as Record<string, unknown>;
      if (t === "text-delta" && p.text) {
        send({ type: "text", delta: p.text });
      } else if (t === "tool-call") {
        send({ type: "tool_call", name: p.toolName || p.name, args: p.args });
      } else if (t === "tool-result") {
        const result = p.result;
        const resultPreview =
          typeof result === "string" ? result.slice(0, 200) : JSON.stringify(result || {}).slice(0, 200);
        send({ type: "tool_result", name: p.toolName || p.name, result: resultPreview });
      } else if (t === "finish") {
        break;
      }
    }
    send({ type: "done" });
  } catch (err) {
    send({ type: "error", message: (err instanceof Error && err.message) || String(err) });
  }
  res.end();
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Agent UI: http://0.0.0.0:${PORT}`);
});
