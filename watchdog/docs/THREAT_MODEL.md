# Agent-WatchDog — Threat Model

> Version 1.0 | February 2026

---

## 1. Asset Inventory

| Asset | Value | Location |
|-------|-------|----------|
| **Tool execution capability** | HIGH — agent can read files, run commands, make HTTP calls | Agent runtime process |
| **User secrets** | CRITICAL — SSH keys, `.env`, AWS credentials, DB passwords | Filesystem, environment variables |
| **System integrity** | CRITICAL — filesystem, kernel, network config | Host OS |
| **Audit trail** | HIGH — forensic evidence of all decisions | In-memory (V1), persistent store (V2) |
| **Policy rules** | MEDIUM — defines enforcement behavior | `watchdog.toml` on disk |
| **Firewall availability** | HIGH — downtime = either fail-open or fail-closed | Agent-WatchDog process |

---

## 2. Adversary Model

### Adversary A: Prompt-Injected Agent (Primary)
- **Capability**: Full control of agent's tool-call sequence via injected prompt
- **Goal**: Exfiltrate secrets, destroy data, establish persistence
- **Skill**: Sophisticated — can chain tool calls, obfuscate arguments, use indirect paths
- **Cannot**: Modify the firewall binary, bypass kernel-level eBPF, or access the firewall's config file (different privilege boundary)

### Adversary B: Malicious Developer (Insider)
- **Capability**: Can write code that bypasses the SDK
- **Goal**: Execute tool calls without firewall approval
- **Skill**: Expert — understands the system architecture
- **Mitigation boundary**: Network-level enforcement (V2), eBPF-level enforcement (current for file access)

### Adversary C: Supply Chain Attack
- **Capability**: Compromised dependency calls tools directly
- **Goal**: Silent data exfiltration
- **Skill**: Hidden — operates within trusted process
- **Mitigation boundary**: eBPF layer catches file access regardless of caller

---

## 3. Attack Vectors

### V1: Direct Tool Execution Bypass
- **Vector**: Developer calls tool function directly, skipping the SDK wrapper
- **Impact**: Firewall is never consulted — tool runs unguarded
- **Current mitigation**: None at SDK level. SDK is opt-in.
- **V2 mitigation**: Network proxy mode — all outbound calls routed through firewall. Or Kubernetes admission controller.
- **eBPF backstop**: File access is ALWAYS caught at kernel level regardless of SDK usage.

### V2: Argument Obfuscation
- **Vector**: Agent encodes dangerous arguments (base64, hex, Unicode tricks) to evade string-matching rules
- **Example**: `"cGFzc3dk"` instead of `"passwd"`, or `"/etc/./shadow"` path traversal
- **Impact**: Rule conditions don't match → tool call allowed
- **Current mitigation**: `base64` is a flagged pattern in risk scoring (+20 points)
- **V2 mitigation**: Argument normalization layer (decode base64, resolve paths, strip Unicode)

### V3: Tool Name Aliasing
- **Vector**: Agent registers tool under a different name to dodge tool-name rules
- **Example**: Renaming `shell_exec` to `helper_run`
- **Impact**: Tool name rules don't match
- **Current mitigation**: Unknown tools get moderate risk (15/40 tool weight)
- **V2 mitigation**: Tool capability fingerprinting — classify by behavior, not name

### V4: Frequency-Based Evasion (Slow Drip)
- **Vector**: Agent exfiltrates data one line at a time, staying under burst threshold
- **Impact**: No frequency penalty triggered
- **Current mitigation**: 60-second sliding window, threshold 10
- **V2 mitigation**: Long-term behavioral baseline per agent (hours/days)

### V5: Replay Attack
- **Vector**: Attacker captures an allowed request and replays it
- **Impact**: Tool call executes multiple times
- **Current mitigation**: None — no request nonce or deduplication
- **V2 mitigation**: HMAC request signing with timestamp window, nonce tracking

### V6: Firewall Denial of Service
- **Vector**: Flood `/v1/intercept` with requests to exhaust resources
- **Impact**: Legitimate requests time out → fail-open allows dangerous calls
- **Current mitigation**: None — no rate limiting on the proxy endpoint
- **V2 mitigation**: Per-agent rate limiting, circuit breaker, connection pooling

### V7: Config Tampering
- **Vector**: Attacker modifies `watchdog.toml` to disable rules or set `dry_run = true`
- **Impact**: Firewall becomes a no-op
- **Current mitigation**: Config file requires root access (same as the daemon)
- **V2 mitigation**: Config signing, immutable config in container image, config change alerting

---

## 4. Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│                    HOST MACHINE (root)                    │
│                                                         │
│  ┌──────────────┐     ┌──────────────────────────────┐  │
│  │  eBPF        │     │  Agent-WatchDog Daemon       │  │
│  │  (kernel)    │────►│  ├─ Dashboard API (:3000)    │  │
│  │  MANDATORY   │     │  ├─ Firewall Proxy (:3001)   │  │
│  │  ENFORCEMENT │     │  ├─ PolicyEngine             │  │
│  └──────────────┘     │  ├─ RiskEngine               │  │
│         │             │  └─ AuditStore               │  │
│    ┌────┴────┐        └──────────────────────────────┘  │
│    │ KERNEL  │              ▲                            │
│    │ TRUST   │              │ HTTP (opt-in V1)           │
│    │ BOUNDARY│              │ MANDATORY (V2 proxy mode)  │
│    └─────────┘        ┌─────┴──────────┐                │
│                       │  AI Agent       │                │
│                       │  + SDK wrapper  │                │
│                       │  (user-space)   │                │
│                       └────────────────┘                │
└─────────────────────────────────────────────────────────┘
```

**Key insight**: The eBPF layer is MANDATORY — it operates at the kernel syscall level and cannot be bypassed by user-space code. The HTTP proxy layer (V1) is opt-in via SDK. This is a **defense-in-depth** model:

| Layer | Enforcement | Bypassable? |
|-------|-------------|-------------|
| eBPF tracepoint | Kernel-level file access monitoring | **No** — catches `openat()` regardless |
| HTTP Proxy (`/v1/intercept`) | Pre-execution tool-call gating | **Yes** in V1 (SDK opt-in) |
| Policy rules | Configurable allow/deny | Only by config tampering |
| Risk scoring | Heuristic auto-blocking | Only by obfuscation |

---

## 5. Failure Modes

| Failure | Impact | Mitigation |
|---------|--------|------------|
| Firewall process crashes | All tool calls bypass (if fail-open) or halt (if fail-closed) | Systemd restart, health checks |
| Audit store OOM | Oldest records evicted (ring buffer) | 50K cap, future: persist to disk |
| Config parse error | Daemon fails to start | Default config fallback, validation on load |
| eBPF program detach | File monitoring stops | Kernel auto-cleanup on process exit, systemd watchdog |
| Network partition (remote mode) | Agents can't reach firewall | `fail_open` / `fail_closed` per-agent config |

---

## 6. Honest Limitation Statement (V1)

1. **SDK enforcement is opt-in.** A developer can skip the SDK and call tools directly. This makes V1 an **SDK-first developer tool**, not a network-level firewall.

2. **Risk scoring is deterministic, not ML-based.** It uses weighted pattern matching. This is appropriate for V1 but should not be marketed as "AI security."

3. **Audit store is in-memory.** Process restart loses history. Enterprise deployment requires persistent storage (Postgres, SQLite, or append-only log file).

4. **No request authentication.** Any process that can reach port 3001 can send intercept requests. No mTLS, no API keys, no HMAC signing.

5. **Single-node architecture.** No HA, no clustering, no distributed audit aggregation.

---

## 7. V2 Roadmap (What Makes It Unbypassable)

| Feature | Effect |
|---------|--------|
| **iptables/nftables integration** | Route all agent outbound traffic through the proxy — network-level enforcement |
| **Kubernetes NetworkPolicy** | In k8s, agents can ONLY reach tools via the firewall sidecar |
| **mTLS + API key auth** | Only authenticated agents can use the intercept endpoint |
| **HMAC request signing** | Prevents replay attacks, ensures request integrity |
| **Persistent audit** | SQLite or append-only log for crash-resistant forensics |
| **Behavioral baselines** | Per-agent historical profiles for anomaly detection |
