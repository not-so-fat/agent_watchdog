//! Agent-WatchDog — User-space daemon
//!
//! Loads the compiled eBPF object, attaches it to the
//! `syscalls/sys_enter_openat` tracepoint, and asynchronously polls
//! the `PerfEventArray` for `FileOpenEvent`s.
//!
//! Exposes an HTTP + WebSocket API (default port 3000) for the
//! React dashboard frontend.
//!
//! Supports:
//! - **Dry-run mode**: log alerts without killing processes
//! - **Whitelist**: skip trusted processes, PIDs, and path prefixes
//! - **CWD resolution**: resolve relative paths via `/proc/<pid>/cwd`

mod api;
mod antihijack;
mod audit;
mod config;
mod event_store;
mod path_resolver;
mod policy;
mod proxy;
mod risk;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::{
    maps::perf::PerfEventArray,
    maps::HashMap as BpfHashMap,
    programs::TracePoint,
    util::online_cpus,
    Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use chrono::Utc;
use clap::Parser;
use log::{debug, info, warn};
use tokio::signal;
use tokio::sync::broadcast;
use uuid::Uuid;

use agent_watchdog_common::FileOpenEvent;
use agent_watchdog_common::WATCHED_PIDS_MAP_NAME;
use antihijack::AntiHijackGateway;
use audit::AuditStore;
use config::Config;
use event_store::{AlertEvent, AlertStatus, EventStore, Severity};
use policy::PolicyEngine;
use proxy::ProxyState;
use risk::RiskEngine;

// ── CLI ──────────────────────────────────────────────────────────
#[derive(Debug, Parser)]
#[command(
    name = "agent-watchdog",
    about = "AI Agent runtime security monitor — eBPF-based sensitive-file access tracer"
)]
struct Opt {
    /// Path to the compiled eBPF ELF object.
    #[arg(
        short,
        long,
        default_value = "target/bpfel-unknown-none/release/agent-watchdog"
    )]
    bpf_path: String,

    /// Port for the HTTP/WebSocket API server.
    #[arg(short, long, default_value = "3000")]
    port: u16,

    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "watchdog.toml")]
    config: PathBuf,

    /// Enable dry-run mode (overrides config file).
    /// Alerts are logged but processes are NOT killed.
    #[arg(long)]
    dry_run: bool,
}

// ── Entry point ──────────────────────────────────────────────────
#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    env_logger::init();

    // ── 0. Load configuration ────────────────────────────────────
    let mut config = Config::load(&opt.config)?;

    // CLI --dry-run flag overrides the config file.
    if opt.dry_run {
        config.dry_run = true;
    }

    if config.dry_run {
        info!("⚠️   DRY-RUN mode enabled — alerts will be logged but processes will NOT be killed");
    }

    let config = Arc::new(config);

    // ── 1. Shared state ──────────────────────────────────────────
    let store = EventStore::shared();
    let (tx, _rx) = broadcast::channel::<AlertEvent>(1024);

    // ── 2. Bind API server socket (started after eBPF map is ready)
    let addr = format!("0.0.0.0:{}", opt.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind to {}", addr))?;
    info!("🌐  API server will listen on http://{}", addr);

    // ── 2b. Start Firewall Proxy server ──────────────────────────
    let policy_engine = PolicyEngine::new(
        config.build_policy_rules(),
        config.parsed_default_action(),
        config.risk_threshold,
        config.dry_run,
    );
    let risk_engine = RiskEngine::new();
    let audit_store = AuditStore::shared();
    let gateway = AntiHijackGateway::new(
        config.replay_window_seconds,
        config.kill_switch_enabled,
    );

    let proxy_state = Arc::new(ProxyState {
        policy: policy_engine,
        risk: risk_engine,
        audit: audit_store,
        gateway,
    });
    let proxy_router = proxy::create_proxy_router(proxy_state);

    let proxy_addr = format!("0.0.0.0:{}", config.firewall_port);
    let proxy_listener = tokio::net::TcpListener::bind(&proxy_addr)
        .await
        .with_context(|| format!("failed to bind firewall proxy to {}", proxy_addr))?;
    info!("🛡️  Firewall proxy listening on http://{}", proxy_addr);

    tokio::spawn(async move {
        if let Err(e) = axum::serve(proxy_listener, proxy_router).await {
            warn!("Firewall proxy error: {:#}", e);
        }
    });

    // ── 3. Load the eBPF object ──────────────────────────────────
    info!("Loading eBPF object from: {}", opt.bpf_path);
    let mut ebpf = Ebpf::load_file(&opt.bpf_path)
        .with_context(|| format!("failed to load eBPF object from '{}'", opt.bpf_path))?;

    // Forward aya-log messages (if the eBPF side uses `info!()` etc.)
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!(
            "aya-log init failed (non-fatal, eBPF-side logs disabled): {}",
            e
        );
    }

    // ── 4. Attach to the tracepoint ──────────────────────────────
    let program: &mut TracePoint = ebpf
        .program_mut("agent_watchdog")
        .context("eBPF program 'agent_watchdog' not found in object file")?
        .try_into()
        .context("program type mismatch — expected TracePoint")?;

    program
        .load()
        .context("failed to load tracepoint program into the kernel")?;
    program
        .attach("syscalls", "sys_enter_openat")
        .context("failed to attach to syscalls/sys_enter_openat")?;

    info!("✅  Attached to tracepoint: syscalls/sys_enter_openat");

    // ── 4b. Seed the WATCHED_PIDS eBPF map ──────────────────────
    //
    // The eBPF probe skips any PID not present in this map, so we
    // must populate it before events start flowing.
    let watched_pids: api::SharedWatchedPids = {
        let mut watched: BpfHashMap<_, u32, u8> = BpfHashMap::try_from(
            ebpf.take_map(WATCHED_PIDS_MAP_NAME)
                .context("WATCHED_PIDS map not found in the eBPF object")?,
        )
        .context("failed to create HashMap from WATCHED_PIDS map")?;

        for &pid in &config.target_pids {
            watched
                .insert(pid, 1u8, 0)
                .with_context(|| format!("failed to insert PID {} into WATCHED_PIDS", pid))?;
            info!("📌  Watching PID {} (from config target_pids)", pid);
        }

        if config.target_pids.is_empty() {
            info!("⚠️   No target_pids configured — eBPF probe will not monitor any process");
            info!("     Add PIDs via watchdog.toml or POST /api/config/watch-pid");
        } else {
            info!(
                "📌  Seeded {} PID(s) into WATCHED_PIDS eBPF map",
                config.target_pids.len()
            );
        }

        Arc::new(tokio::sync::Mutex::new(watched))
    };

    // ── 4c. Start API server (needs watched_pids handle) ─────────
    let api_state = api::AppState {
        store: store.clone(),
        tx: tx.clone(),
        config: config.clone(),
        watched_pids: watched_pids.clone(),
    };
    let router = api::create_router(api_state);

    info!("🌐  API server listening on http://{}", addr);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            warn!("API server error: {:#}", e);
        }
    });

    info!("🔍  Monitoring sensitive file access… Press Ctrl-C to stop.\n");

    // ── 5. Open PerfEventArray and spawn per-CPU readers ─────────
    let mut perf_array = PerfEventArray::try_from(
        ebpf.take_map("EVENTS")
            .context("EVENTS map not found in the eBPF object")?,
    )
    .context("failed to create PerfEventArray from EVENTS map")?;

    let cpus = online_cpus().map_err(|(_, e)| e).context("failed to enumerate online CPUs")?;
    info!("📡  Spawning {} perf-event readers (one per CPU)", cpus.len());

    for cpu_id in cpus {
        let mut buf = perf_array
            .open(cpu_id, Some(64)) // 64-page (256 KiB) ring buffer per CPU
            .context("failed to open perf buffer")?;

        let store = store.clone();
        let tx = tx.clone();
        let config = config.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(core::mem::size_of::<FileOpenEvent>()))
                .collect::<Vec<_>>();

            let mut interval = tokio::time::interval(std::time::Duration::from_millis(10));

            loop {
                interval.tick().await;

                while buf.readable() {
                    let events = match buf.read_events(&mut buffers) {
                        Ok(evts) => evts,
                        Err(e) => {
                            warn!("CPU {} perf read error: {:#}", cpu_id, e);
                            break;
                        }
                    };

                    if events.lost > 0 {
                        warn!(
                            "CPU {} lost {} events (ring buffer full)",
                            cpu_id, events.lost
                        );
                    }

                    for i in 0..events.read {
                        let raw = &buffers[i];
                        if raw.len() < core::mem::size_of::<FileOpenEvent>() {
                            warn!("CPU {} truncated event ({} bytes)", cpu_id, raw.len());
                            continue;
                        }

                        // SAFETY: `FileOpenEvent` is `#[repr(C)]`, `Copy`, and
                        // contains only fixed-size fields.  The buffer is at
                        // least `size_of::<FileOpenEvent>()` bytes (checked above).
                        let event: FileOpenEvent = unsafe {
                            core::ptr::read_unaligned(raw.as_ptr() as *const FileOpenEvent)
                        };

                        let raw_filename = c_buf_to_str(&event.filename);
                        let comm = c_buf_to_str(&event.comm);

                        // ── Whitelist checks ─────────────────────
                        if config.is_process_whitelisted(&comm) {
                            debug!("Skipping whitelisted process: {} (PID: {})", comm, event.pid);
                            continue;
                        }
                        if config.is_pid_whitelisted(event.pid) {
                            debug!("Skipping whitelisted PID: {}", event.pid);
                            continue;
                        }

                        // ── Resolve relative paths via /proc/<pid>/cwd ──
                        let filename = path_resolver::resolve_path(event.pid, &raw_filename);

                        if config.is_path_whitelisted(&filename) {
                            debug!("Skipping whitelisted path: {}", filename);
                            continue;
                        }

                        debug!(
                            "CPU {} event: pid={} comm={} file={}",
                            cpu_id, event.pid, comm, filename,
                        );

                        if config.is_sensitive(&filename) {
                            let mode_tag = if config.dry_run { "DRY-RUN" } else { "LIVE" };
                            warn!(
                                "[🚨 HIGH RISK] [{}] Process {} (PID: {}) is trying to read {}",
                                mode_tag, comm, event.pid, filename,
                            );

                            let alert = AlertEvent {
                                id: Uuid::new_v4().to_string(),
                                timestamp: Utc::now(),
                                pid: event.pid,
                                comm: comm.clone(),
                                filename: filename.clone(),
                                severity: Severity::High,
                                status: AlertStatus::Active,
                                dry_run: config.dry_run,
                            };

                            {
                                let mut s = store.write().await;
                                s.push(alert.clone());
                            }

                            let _ = tx.send(alert);
                        }
                    }

                    if events.read == 0 {
                        break;
                    }
                }
            }
        });
    }

    // ── 6. Block until Ctrl-C ────────────────────────────────────
    signal::ctrl_c()
        .await
        .context("failed to listen for Ctrl-C signal")?;
    info!("\n🛑  Shutting down Agent-WatchDog. Goodbye.");

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────

fn c_buf_to_str(buf: &[u8]) -> String {
    let nul_pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..nul_pos]).into_owned()
}
