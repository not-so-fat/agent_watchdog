# AGENT-WATCHDOG

AI AGENT RUNTIME SECURITY MONITOR — RUST + EBPF DEFENSIVE STACK

---

## OVERVIEW

**AGENT-WATCHDOG** is a runtime firewall for AI agents.  
It intercepts:

- **KERNEL-LEVEL FILE OPENS** via eBPF (`sys_enter_openat`) and
- **TOOL CALLS** via an HTTP firewall proxy

to protect secrets and infrastructure from prompt-injected or misbehaving agents.

Key properties:

- **ZERO-INSTRUMENTATION KERNEL MONITORING** — eBPF tracepoint on `sys_enter_openat`, no app changes required.
- **REAL-TIME ALERTING** — sensitive file access is streamed to a React dashboard via WebSocket.
- **PROCESS TERMINATION** — you can kill offending processes with a single API call.
- **AGENT FIREWALL** — a policy + risk engine that evaluates tool calls *before* they execute.

---

## ARCHITECTURE

```text
┌──────────────────────────────────────────────────┐
│                    LINUX KERNEL                  │
│  ┌────────────────────────────────────────────┐  │
│  │  EBPF PROGRAM (sys_enter_openat TRACEPOINT)│  │
│  │  CAPTURES ALL open()/openat() SYSCALLS     │  │
│  └──────────────┬─────────────────────────────┘  │
│                 │ PERF EVENT ARRAY               │
├─────────────────┼────────────────────────────────┤
│   USER SPACE    │                                │
│  ┌──────────────▼─────────────────────────────┐  │
│  │  RUST DAEMON (TOKIO + AYA + AXUM)          │  │
│  │  ├── SENSITIVE PATH MATCHING               │  │
│  │  ├── IN-MEMORY EVENT STORE                 │  │
│  │  └── HTTP + WEBSOCKET API (:3000 / :3001)  │  │
│  └──────────────┬─────────────────────────────┘  │
└─────────────────┼────────────────────────────────┘
                  │ REST + WEBSOCKET + FIREWALL
┌─────────────────▼────────────────────────────────┐
│  REACT DASHBOARD (VITE + TAILWIND + SHADCN/UI)   │
│  REAL-TIME ALERTS · EVENTS · PROCESSES · CONFIG  │
└──────────────────────────────────────────────────┘
```

---

## PROJECT STRUCTURE

```text
Agent-WatchDog/
├── agent-watchdog-common/   # Shared types (kernel + user space), #[repr(C)], no_std
├── agent-watchdog-ebpf/     # eBPF kernel program (bpfel-unknown-none)
├── agent-watchdog/          # User-space daemon (Tokio + Aya + Axum)
│   └── src/
│       ├── main.rs          # Entry point: eBPF load + event loop
│       ├── api.rs           # HTTP/WebSocket API routes
│       └── event_store.rs   # In-memory event storage
├── dashboard/               # React dashboard
│   └── src/app/
│       ├── api.ts           # API client (REST + WebSocket)
│       └── pages/           # Dashboard, Events, Processes, Configuration
└── xtask/                   # Build helper for cross-compiling eBPF
```

---

## SENSITIVE FILES (DEFAULT KEYWORDS)

The eBPF layer treats any `open()` whose resolved path contains one of the
following substrings (case-insensitive) as *sensitive*:

| KEYWORD | PURPOSE |
|---------|---------|
| `.env` | ENVIRONMENT / SECRET CONFIG |
| `id_rsa` / `id_ed25519` / `id_ecdsa` | SSH PRIVATE KEYS |
| `shadow` | SYSTEM PASSWORD FILE |
| `aws/credentials` | AWS CREDENTIALS |
| `.kube/config` | KUBERNETES CONFIG |
| `.docker/config.json` | DOCKER CREDENTIALS |
| `secrets.yaml` / `secrets.yml` | GENERIC SECRETS |
| `master.key` | RAILS MASTER KEY OR EQUIVALENT |
| `.pgpass` | POSTGRES PASSWORDS |
| `.netrc` | FTP/HTTP CREDENTIALS |
| `gcp/application_default_credentials.json` | GCP CREDENTIALS |

You can override this list via `sensitive_keywords` in `watchdog.toml`.

---

## REQUIREMENTS

### BACKEND (LINUX SERVER)

- LINUX KERNEL ≥ 5.4 WITH BTF SUPPORT (`ls /sys/kernel/btf/vmlinux`)
- ROOT PRIVILEGES (REQUIRED TO LOAD EBPF PROGRAMS)
- x86_64 ARCHITECTURE

### BUILD ENVIRONMENT (MACOS OR LINUX)

- RUST STABLE + NIGHTLY TOOLCHAINS:

```bash
rustup toolchain install nightly --component rust-src
```

- `bpf-linker`:

```bash
cargo install bpf-linker
```

- CROSS-COMPILER (WHEN BUILDING LINUX TARGETS FROM MACOS):

```bash
brew install x86_64-unknown-linux-gnu  # macOS
rustup target add x86_64-unknown-linux-gnu
```

### FRONTEND

- BUN ≥ 1.0 OR NODE.JS ≥ 18

---

## QUICK START

### 1. BUILD THE EBPF PROGRAM

```bash
# OPTION 1: USE XTASK (ON x86_64 LINUX HOST)
cargo xtask build-ebpf

# OPTION 2: MANUAL BUILD (RECOMMENDED FOR MACOS CROSS-COMPILE)
cd agent-watchdog-ebpf
CARGO_ENCODED_RUSTFLAGS='--cfg=bpf_target_arch="x86_64"' \
  cargo +nightly build \
  --target=bpfel-unknown-none \
  -Z build-std=core \
  --release
```

### 2. BUILD THE USER-SPACE DAEMON

```bash
# NATIVE LINUX
cargo build --release

# MACOS CROSS-COMPILE TO LINUX
cargo build --release --target x86_64-unknown-linux-gnu
```

### 3. DEPLOY TO SERVER

```bash
# UPLOAD BINARIES
scp target/x86_64-unknown-linux-gnu/release/agent-watchdog user@server:~/agent-watchdog/
scp agent-watchdog-ebpf/target/bpfel-unknown-none/release/agent-watchdog \
    user@server:~/agent-watchdog/target/bpfel-unknown-none/release/agent-watchdog
```

### 4. START BACKEND

On the target Linux server:

```bash
cd ~/agent-watchdog

# FOREGROUND (DEBUG)
RUST_LOG=info sudo -E ./agent-watchdog

# BACKGROUND (PRODUCTION)
nohup sudo -E env RUST_LOG=info ./agent-watchdog --port 3000 > /tmp/watchdog.log 2>&1 &
```

Expected startup:

```text
API SERVER LISTENING ON http://0.0.0.0:3000
STARTING EBPF EVENT READER ON N CPUS...
```

### 5. START DASHBOARD

```bash
cd dashboard

# INSTALL DEPENDENCIES
bun install        # OR: npm install

# CONFIGURE BACKEND ADDRESS IN vite.config.ts
#   '/api': { target: 'http://YOUR_SERVER_IP:3000' }
#   '/ws':  { target: 'ws://YOUR_SERVER_IP:3000' }

# START DEV SERVER
bun run dev        # OR: npm run dev
```

Open the dashboard at `http://localhost:5173`.

### 6. TRIGGER A TEST ALERT

On the Linux server:

```bash
cat /etc/shadow
cat ~/.ssh/id_rsa
cat ~/.aws/credentials
cat ~/.kube/config
touch /tmp/test.env && cat /tmp/test.env
```

You should see HIGH-RISK alerts appear in the dashboard in real time.

---

## API

Backend defaults to `http://SERVER_IP:3000`.

| METHOD | PATH | DESCRIPTION |
|--------|------|-------------|
| `GET` | `/api/health` | HEALTH CHECK |
| `GET` | `/api/stats` | DASHBOARD STATS |
| `GET` | `/api/events` | ALL EVENTS |
| `GET` | `/api/alerts` | ACTIVE ALERTS |
| `POST` | `/api/events/{id}/block` | TERMINATE PROCESS (SIGKILL) |
| `POST` | `/api/events/{id}/ignore` | MARK AS FALSE POSITIVE |
| `GET` | `/ws/events` | WEBSOCKET EVENT STREAM |

Example:

```bash
# HEALTH CHECK
curl http://localhost:3000/api/health

# STATS
curl http://localhost:3000/api/stats

# ACTIVE ALERTS
curl http://localhost:3000/api/alerts

# BLOCK A PROCESS
curl -X POST http://localhost:3000/api/events/{event_id}/block
```

---

## DEVELOPER NOTES

### ADDING NEW SENSITIVE KEYWORDS

Use either:

- `agent-watchdog/src/config.rs`: extend `DEFAULT_SENSITIVE_KEYWORDS`, or
- `watchdog.toml`: set `sensitive_keywords = ["my_secret_file", ...]`

Rebuild and redeploy to apply.

### ADDING NEW EVENT FIELDS

1. Extend `FileOpenEvent` in `agent-watchdog-common/src/lib.rs` (`#[repr(C)]`, fixed size).
2. Populate fields in `agent-watchdog-ebpf/src/main.rs` (respect 512-byte eBPF stack limit).
3. Read fields in the event loop in `agent-watchdog/src/main.rs`.
4. Update the dashboard client in `dashboard/src/app/api.ts`.

---

## WARNINGS

- EBPF PROGRAMS **MUST** BE BUILT WITH `--release` — debug builds are rejected by the kernel verifier.
- EBPF STACK IS LIMITED TO 512 BYTES — large structs must use `PerCpuArray` or other maps.
- USER-SPACE POINTERS **MUST NOT** BE DEREFERENCED DIRECTLY — always use `bpf_probe_read_user_str_bytes`.
- MACOS CANNOT RUN THE EBPF PROGRAM — only cross-compilation is supported there.
- BLOCKING AN EVENT VIA `/api/events/{id}/block` SENDS **SIGKILL** — use with care.

---

## LICENSE

MIT
