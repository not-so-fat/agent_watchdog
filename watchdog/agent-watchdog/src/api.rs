//! Axum HTTP + WebSocket server for Agent-WatchDog dashboard.
//!
//! Provides REST endpoints for the React frontend and a WebSocket
//! endpoint for real-time event streaming.

use std::sync::Arc;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use futures::{SinkExt, StreamExt};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};

use crate::config::Config;
use crate::event_store::{AlertEvent, SharedEventStore};

/// Thread-safe handle to the eBPF `WATCHED_PIDS` HashMap.
///
/// Wrapped in `Arc<Mutex<…>>` so the API handlers can insert new
/// PIDs at runtime without holding the Aya `Ebpf` borrow.
pub type SharedWatchedPids =
    Arc<tokio::sync::Mutex<aya::maps::HashMap<aya::maps::MapData, u32, u8>>>;

// ── App state ────────────────────────────────────────────────────

/// Shared application state passed to all handlers.
#[derive(Clone)]
pub struct AppState {
    pub store: SharedEventStore,
    pub tx: broadcast::Sender<AlertEvent>,
    pub config: Arc<Config>,
    /// Handle to the eBPF WATCHED_PIDS map for runtime PID updates.
    pub watched_pids: SharedWatchedPids,
}

// ── Router ───────────────────────────────────────────────────────

/// Build the Axum router with all API routes.
pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Serve the React dashboard from ./dashboard-dist (SPA fallback to index.html)
    let spa_service = ServeDir::new("dashboard-dist")
        .not_found_service(ServeFile::new("dashboard-dist/index.html"));

    Router::new()
        // Dashboard stats
        .route("/api/stats", get(get_stats))
        // All events (paginated in the future)
        .route("/api/events", get(get_events))
        // Active alerts only
        .route("/api/alerts", get(get_active_alerts))
        // Block a process
        .route("/api/events/{id}/block", post(block_event))
        // Mark as false-positive
        .route("/api/events/{id}/ignore", post(ignore_event))
        // Runtime config (dry-run status, whitelist info)
        .route("/api/config", get(get_config))
        // Dynamically add a PID to the eBPF watched-set
        .route("/api/config/watch-pid", post(add_watch_pid))
        // WebSocket for real-time events
        .route("/ws/events", get(ws_handler))
        // Health check
        .route("/api/health", get(health))
        // Static files: serve React dashboard at all other paths
        .fallback_service(spa_service)
        .layer(cors)
        .with_state(Arc::new(state))
}

// ── Handlers ─────────────────────────────────────────────────────

async fn health() -> &'static str {
    "ok"
}

/// Expose runtime configuration to the frontend.
#[derive(Serialize)]
struct ConfigResponse {
    dry_run: bool,
    whitelist_processes: Vec<String>,
    whitelist_pids: Vec<u32>,
    whitelist_paths: Vec<String>,
}

async fn get_config(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    Json(ConfigResponse {
        dry_run: state.config.dry_run,
        whitelist_processes: state.config.whitelist_processes.clone(),
        whitelist_pids: state.config.whitelist_pids.clone(),
        whitelist_paths: state.config.whitelist_paths.clone(),
    })
}

// ── Watch-PID endpoint ───────────────────────────────────────────

/// Request body for `POST /api/config/watch-pid`.
#[derive(Deserialize)]
struct WatchPidRequest {
    /// The PID to add to the eBPF watched-set.
    pid: u32,
}

/// Response for the watch-pid endpoint.
#[derive(Serialize)]
struct WatchPidResponse {
    success: bool,
    message: String,
}

/// Dynamically insert a PID into the eBPF `WATCHED_PIDS` map so the
/// kernel probe starts monitoring it immediately.
async fn add_watch_pid(
    State(state): State<Arc<AppState>>,
    Json(body): Json<WatchPidRequest>,
) -> impl IntoResponse {
    let mut map = state.watched_pids.lock().await;

    match map.insert(body.pid, 1u8, 0) {
        Ok(()) => {
            info!("📌  Dynamically added PID {} to WATCHED_PIDS", body.pid);
            (
                StatusCode::OK,
                Json(WatchPidResponse {
                    success: true,
                    message: format!("PID {} is now being watched", body.pid),
                }),
            )
        }
        Err(e) => {
            warn!("Failed to insert PID {} into WATCHED_PIDS: {:#}", body.pid, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(WatchPidResponse {
                    success: false,
                    message: format!("Failed to watch PID {}: {}", body.pid, e),
                }),
            )
        }
    }
}

// ── Stats / events / alerts ──────────────────────────────────────

async fn get_stats(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(store.stats())
}

async fn get_events(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(store.all_events())
}

async fn get_active_alerts(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(store.active_alerts())
}

/// Response for block/ignore actions.
#[derive(Serialize)]
struct ActionResponse {
    success: bool,
    message: String,
    event: Option<AlertEvent>,
}

async fn block_event(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut store = state.store.write().await;

    match store.block_event(&id) {
        Some(event) => {
            let pid = event.pid;
            let dry_run = state.config.dry_run;
            drop(store); // release lock before syscall

            let msg = if dry_run {
                info!(
                    "🔸 [DRY-RUN] Would have killed process {} (PID: {}), but dry-run is enabled",
                    event.comm, pid
                );
                format!(
                    "[DRY-RUN] Process {} (PID: {}) marked as blocked (not actually killed)",
                    event.comm, pid
                )
            } else {
                // SAFETY: we are sending SIGKILL to the process.
                // This requires root — which Agent-WatchDog already runs as.
                let killed = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
                if killed == 0 {
                    info!("🛑 Blocked process {} (PID: {})", event.comm, pid);
                    format!("Process {} (PID: {}) has been killed", event.comm, pid)
                } else {
                    warn!("Failed to kill PID {} (may have already exited)", pid);
                    format!(
                        "Process marked as blocked but kill failed (PID: {} may have exited)",
                        pid
                    )
                }
            };

            Json(ActionResponse {
                success: true,
                message: msg,
                event: Some(event),
            })
        }
        None => Json(ActionResponse {
            success: false,
            message: format!("Event {} not found", id),
            event: None,
        }),
    }
}

async fn ignore_event(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut store = state.store.write().await;

    match store.ignore_event(&id) {
        Some(event) => {
            info!("👁 Marked event {} as false positive", id);
            Json(ActionResponse {
                success: true,
                message: "Event marked as false positive".to_string(),
                event: Some(event),
            })
        }
        None => Json(ActionResponse {
            success: false,
            message: format!("Event {} not found", id),
            event: None,
        }),
    }
}

// ── WebSocket ────────────────────────────────────────────────────

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.tx.subscribe();

    info!("🔌 WebSocket client connected");

    // Forward broadcast events → WebSocket client
    let send_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            if let Ok(json) = serde_json::to_string(&event) {
                if sender.send(Message::Text(json.into())).await.is_err() {
                    break; // client disconnected
                }
            }
        }
    });

    // Read from client (we don't expect messages, but drain to detect close)
    let recv_task = tokio::spawn(async move {
        while let Some(Ok(_msg)) = receiver.next().await {
            // ignore client messages for now
        }
    });

    // When either task finishes, abort the other
    tokio::select! {
        _ = send_task => {}
        _ = recv_task => {}
    }

    info!("🔌 WebSocket client disconnected");
}
