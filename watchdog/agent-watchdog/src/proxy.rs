//! Proxy API — The Agent Firewall interceptor endpoint.
//!
//! This is the **core product surface**: an HTTP endpoint that
//! AI agents call INSTEAD of directly invoking tools.
//!
//! ```text
//! Agent ──► POST /v1/intercept ──► PolicyEngine ──► Allow/Block
//!                                       │
//!                                   AuditStore
//! ```
//!
//! ## Integration Modes
//!
//! 1. **Proxy mode**: Agent sends tool calls here; if allowed,
//!    WatchDog forwards to the real tool and returns the result.
//!
//! 2. **Interceptor mode**: Agent SDK wraps tool calls with a
//!    pre-check to `POST /v1/intercept`. If blocked, raises
//!    `SecurityException` before the tool ever executes.
//!
//! Both modes are non-invasive — no need to modify agent core code.

use std::sync::Arc;

use axum::{
    extract::State,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};

use crate::antihijack::{AntiHijackGateway, GatewayVerdict};
use crate::audit::SharedAuditStore;
use crate::policy::{Decision, PolicyEngine, PolicyResult, ToolCallRequest};
use crate::risk::RiskEngine;

// ── Proxy State ──────────────────────────────────────────────────

/// Shared state for the proxy/firewall API.
pub struct ProxyState {
    pub policy: PolicyEngine,
    pub risk: RiskEngine,
    pub audit: SharedAuditStore,
    pub gateway: AntiHijackGateway,
}

// ── Request / Response types ─────────────────────────────────────

/// Incoming intercept request from an agent or SDK wrapper.
#[derive(Debug, Deserialize)]
pub struct InterceptRequest {
    /// Agent identifier.
    pub agent_id: String,
    /// User or session owner.
    pub user_id: String,
    /// The tool being called (e.g. "file_read", "shell_exec").
    pub tool: String,
    /// Tool arguments (arbitrary JSON).
    pub args: serde_json::Value,
    /// Optional session ID for grouping.
    #[serde(default)]
    pub session_id: Option<String>,

    // ── Anti-Hijack envelope fields (optional for backward compat) ──

    /// Unix timestamp (seconds) when the command was created.
    /// If omitted, the server uses the current time (legacy mode).
    #[serde(default)]
    pub timestamp: Option<i64>,
    /// One-time nonce to prevent replay attacks.
    /// If omitted, a server-generated nonce is used (legacy mode).
    #[serde(default)]
    pub nonce: Option<String>,
    /// HMAC signature (reserved for future verification).
    #[serde(default)]
    pub signature: Option<String>,
    /// Device / client fingerprint.
    #[serde(default)]
    pub device_id: Option<String>,
    /// Challenge ID for step-up authentication responses.
    #[serde(default)]
    pub challenge_response: Option<String>,
}

/// Intercept response — the enforcement verdict.
#[derive(Debug, Serialize)]
pub struct InterceptResponse {
    /// "allow" or "block"
    pub decision: String,
    /// true if the tool call is permitted to proceed
    pub allowed: bool,
    /// Risk score (0–100)
    pub risk_score: f64,
    /// Risk score breakdown
    pub risk_breakdown: RiskBreakdown,
    /// Human-readable reason
    pub reason: String,
    /// Which rule matched (if any)
    pub matched_rule: Option<String>,
    /// Whether the system is in dry-run mode
    pub dry_run: bool,
    /// Challenge ID (only set when step-up auth is required)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
    /// Whether the kill-switch is active
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kill_switch_active: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct RiskBreakdown {
    pub total: f64,
    pub tool_weight: f64,
    pub arg_danger: f64,
    pub frequency_penalty: f64,
    pub details: Vec<String>,
}

/// Audit query response.
#[derive(Debug, Serialize)]
pub struct AuditResponse {
    pub records: Vec<crate::audit::AuditRecord>,
    pub stats: crate::audit::AuditStats,
}

// ── Router ───────────────────────────────────────────────────────

/// Build the firewall proxy router.
pub fn create_proxy_router(state: Arc<ProxyState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // ── Core firewall endpoint ──
        .route("/v1/intercept", post(intercept))
        // ── Step-up challenge verification ──
        .route("/v1/challenge/verify", post(verify_challenge))
        // ── Audit endpoints ──
        .route("/v1/audit", get(get_audit))
        .route("/v1/audit/stats", get(get_audit_stats))
        // ── Health ──
        .route("/v1/health", get(health))
        .layer(cors)
        .with_state(state)
}

// ── Handlers ─────────────────────────────────────────────────────

async fn health() -> &'static str {
    "ok"
}

/// **THE CORE FIREWALL ENDPOINT.**
///
/// Pipeline: ReplayCheck → RiskEngine → PolicyEngine → StepUpGate → AuditStore
///
/// Anti-hijack replay checks run FIRST (timestamp + nonce).
/// Then the policy engine evaluates.  If it explicitly BLOCKs,
/// we return 403 immediately — no need for step-up.
/// Step-up auth only fires for requests that the policy engine
/// ALLOWs but are still classified as high-risk.
async fn intercept(
    State(state): State<Arc<ProxyState>>,
    Json(req): Json<InterceptRequest>,
) -> impl IntoResponse {
    // ── 0. Resolve envelope fields (backward-compatible) ─────────
    let timestamp = req.timestamp.unwrap_or_else(|| Utc::now().timestamp());
    let nonce = req
        .nonce
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Cache whether this request carries a challenge response,
    // since `req` fields will be moved into `tool_call` later.
    let is_challenge_response = req.challenge_response.is_some();

    // ── 0b. If this is a challenge response, verify it first ─────
    if let Some(ref challenge_id) = req.challenge_response {
        if let Some(challenge) = state.gateway.verify_challenge(challenge_id) {
            info!(
                "✅ Step-up challenge verified: id={}, tool={}",
                challenge_id, challenge.tool
            );
            // Challenge verified — fall through to normal policy evaluation
        } else {
            warn!("🛑 Invalid/expired challenge response: {}", challenge_id);
            let response = InterceptResponse {
                decision: "block".into(),
                allowed: false,
                risk_score: 0.0,
                risk_breakdown: RiskBreakdown {
                    total: 0.0,
                    tool_weight: 0.0,
                    arg_danger: 0.0,
                    frequency_penalty: 0.0,
                    details: vec![],
                },
                reason: "Invalid or expired challenge ID".into(),
                matched_rule: Some("antihijack:challenge-invalid".into()),
                dry_run: state.policy.dry_run(),
                challenge_id: None,
                kill_switch_active: None,
            };
            return (axum::http::StatusCode::FORBIDDEN, Json(response));
        }
    }

    // ── 1. Compute risk score ────────────────────────────────────
    let risk = state.risk.score(&req.tool, &req.args, &req.agent_id);

    // ── 2. Replay protection (timestamp + nonce) ─────────────────
    //    Skip for challenge responses (already verified above)
    if !is_challenge_response {
        let verdict = state.gateway.check_replay_only(
            timestamp,
            &nonce,
        );

        match verdict {
            GatewayVerdict::ReplayExpired {
                age_seconds,
                max_seconds,
            } => {
                let response = InterceptResponse {
                    decision: "block".into(),
                    allowed: false,
                    risk_score: risk.total,
                    risk_breakdown: RiskBreakdown {
                        total: risk.total,
                        tool_weight: risk.tool_weight,
                        arg_danger: risk.arg_danger,
                        frequency_penalty: risk.frequency_penalty,
                        details: risk.details.clone(),
                    },
                    reason: format!(
                        "Replay protection: timestamp expired (age={}s, max={}s)",
                        age_seconds, max_seconds
                    ),
                    matched_rule: Some("antihijack:replay-expired".into()),
                    dry_run: state.policy.dry_run(),
                    challenge_id: None,
                    kill_switch_active: None,
                };
                return (axum::http::StatusCode::FORBIDDEN, Json(response));
            }

            GatewayVerdict::ReplayDuplicate { nonce } => {
                let response = InterceptResponse {
                    decision: "block".into(),
                    allowed: false,
                    risk_score: risk.total,
                    risk_breakdown: RiskBreakdown {
                        total: risk.total,
                        tool_weight: risk.tool_weight,
                        arg_danger: risk.arg_danger,
                        frequency_penalty: risk.frequency_penalty,
                        details: risk.details.clone(),
                    },
                    reason: format!("Replay protection: duplicate nonce '{}'", nonce),
                    matched_rule: Some("antihijack:replay-duplicate".into()),
                    dry_run: state.policy.dry_run(),
                    challenge_id: None,
                    kill_switch_active: None,
                };
                return (axum::http::StatusCode::FORBIDDEN, Json(response));
            }

            _ => { /* Pass — proceed */ }
        }
    }

    // ── 3. Build the tool-call request for the policy engine ─────
    let tool_call = ToolCallRequest {
        agent_id: req.agent_id,
        user_id: req.user_id,
        tool: req.tool,
        args: req.args,
        timestamp: Utc::now(),
        session_id: req.session_id,
    };

    // ── 4. Evaluate against policy rules ─────────────────────────
    //    Policy engine runs BEFORE step-up / kill-switch.
    //    If a rule explicitly blocks, we return 403 immediately.
    let result: PolicyResult = state.policy.evaluate(&tool_call, &risk);

    if result.decision == Decision::Block {
        // Explicit block — record audit and return 403
        let audit_record = state.policy.to_audit_record(&tool_call, &result);
        {
            let mut store = state.audit.write().await;
            store.record(audit_record);
        }
        warn!(
            "🛑 BLOCKED: agent={} tool={} args={} reason={}",
            tool_call.agent_id, tool_call.tool, tool_call.args, result.reason,
        );

        let response = InterceptResponse {
            decision: "block".into(),
            allowed: false,
            risk_score: result.risk_score.total,
            risk_breakdown: RiskBreakdown {
                total: result.risk_score.total,
                tool_weight: result.risk_score.tool_weight,
                arg_danger: result.risk_score.arg_danger,
                frequency_penalty: result.risk_score.frequency_penalty,
                details: result.risk_score.details,
            },
            reason: result.reason,
            matched_rule: result.matched_rule,
            dry_run: state.policy.dry_run(),
            challenge_id: None,
            kill_switch_active: None,
        };
        return (axum::http::StatusCode::FORBIDDEN, Json(response));
    }

    // ── 5. Kill-switch & Step-up (only for ALLOWED requests) ─────
    //    Skip for challenge responses (already verified above)
    if !is_challenge_response {
        let verdict = state.gateway.check_risk_gate(
            &tool_call.tool,
            risk.total,
            &tool_call.agent_id,
            &tool_call.user_id,
            &tool_call.args,
        );

        match verdict {
            GatewayVerdict::KillSwitchActive { tool } => {
                let response = InterceptResponse {
                    decision: "block".into(),
                    allowed: false,
                    risk_score: risk.total,
                    risk_breakdown: RiskBreakdown {
                        total: risk.total,
                        tool_weight: risk.tool_weight,
                        arg_danger: risk.arg_danger,
                        frequency_penalty: risk.frequency_penalty,
                        details: risk.details.clone(),
                    },
                    reason: format!(
                        "Emergency read-only mode: high-risk tool '{}' blocked by kill-switch",
                        tool
                    ),
                    matched_rule: Some("antihijack:kill-switch".into()),
                    dry_run: state.policy.dry_run(),
                    challenge_id: None,
                    kill_switch_active: Some(true),
                };
                return (axum::http::StatusCode::FORBIDDEN, Json(response));
            }

            GatewayVerdict::StepUpRequired {
                challenge_id,
                risk_level,
                tool,
            } => {
                let response = InterceptResponse {
                    decision: "block".into(),
                    allowed: false,
                    risk_score: risk.total,
                    risk_breakdown: RiskBreakdown {
                        total: risk.total,
                        tool_weight: risk.tool_weight,
                        arg_danger: risk.arg_danger,
                        frequency_penalty: risk.frequency_penalty,
                        details: risk.details.clone(),
                    },
                    reason: format!(
                        "Step-up authentication required: tool '{}' classified as {:?}",
                        tool, risk_level
                    ),
                    matched_rule: Some("antihijack:step-up-required".into()),
                    dry_run: state.policy.dry_run(),
                    challenge_id: Some(challenge_id),
                    kill_switch_active: None,
                };
                return (axum::http::StatusCode::UNAUTHORIZED, Json(response));
            }

            _ => { /* Pass — proceed */ }
        }
    }

    // ── 6. Record audit trail ────────────────────────────────────
    let audit_record = state.policy.to_audit_record(&tool_call, &result);
    {
        let mut store = state.audit.write().await;
        store.record(audit_record);
    }

    // ── 7. Log and return ALLOW ──────────────────────────────────
    info!(
        "✅ ALLOWED: agent={} tool={} risk={:.1}",
        tool_call.agent_id, tool_call.tool, result.risk_score.total,
    );

    let response = InterceptResponse {
        decision: "allow".into(),
        allowed: true,
        risk_score: result.risk_score.total,
        risk_breakdown: RiskBreakdown {
            total: result.risk_score.total,
            tool_weight: result.risk_score.tool_weight,
            arg_danger: result.risk_score.arg_danger,
            frequency_penalty: result.risk_score.frequency_penalty,
            details: result.risk_score.details,
        },
        reason: result.reason,
        matched_rule: result.matched_rule,
        dry_run: state.policy.dry_run(),
        challenge_id: None,
        kill_switch_active: None,
    };

    (axum::http::StatusCode::OK, Json(response))
}

// ── Step-Up Challenge Verification ───────────────────────────────

/// Request to verify a step-up challenge.
#[derive(Debug, Deserialize)]
pub struct ChallengeVerifyRequest {
    /// The challenge ID returned from a previous 401 response.
    pub challenge_id: String,
    /// The verification token (e.g. OTP, biometric proof).
    /// In MVP this is a simple presence check — if the field exists
    /// the challenge is accepted.
    #[serde(default)]
    pub verification_token: Option<String>,
}

/// Response to a challenge verification.
#[derive(Debug, Serialize)]
pub struct ChallengeVerifyResponse {
    pub verified: bool,
    pub message: String,
    /// Original tool that was challenged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// The agent can now re-send the intercept with `challenge_response`
    /// set to this ID to bypass the step-up gate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
}

/// Verify a step-up authentication challenge.
async fn verify_challenge(
    State(state): State<Arc<ProxyState>>,
    Json(req): Json<ChallengeVerifyRequest>,
) -> impl IntoResponse {
    match state.gateway.verify_challenge(&req.challenge_id) {
        Some(challenge) => {
            info!(
                "✅ Challenge verified: id={}, tool={}, agent={}",
                req.challenge_id, challenge.tool, challenge.agent_id
            );
            (
                axum::http::StatusCode::OK,
                Json(ChallengeVerifyResponse {
                    verified: true,
                    message: format!(
                        "Challenge verified. Re-send intercept with challenge_response='{}'",
                        req.challenge_id
                    ),
                    tool: Some(challenge.tool),
                    challenge_id: Some(req.challenge_id),
                }),
            )
        }
        None => {
            warn!("🛑 Challenge verification failed: {}", req.challenge_id);
            (
                axum::http::StatusCode::FORBIDDEN,
                Json(ChallengeVerifyResponse {
                    verified: false,
                    message: "Challenge not found or expired".into(),
                    tool: None,
                    challenge_id: None,
                }),
            )
        }
    }
}

/// Get audit records.
async fn get_audit(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let store = state.audit.read().await;
    Json(AuditResponse {
        records: store.recent(100),
        stats: store.stats(),
    })
}

/// Get audit summary stats.
async fn get_audit_stats(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let store = state.audit.read().await;
    Json(store.stats())
}
