//! Anti-Hijack Gateway for Agent-WatchDog.
//!
//! Provides three security layers on top of the existing policy engine:
//!
//! 1. **Replay Protection** — rejects commands with expired timestamps
//!    or duplicate nonces.
//! 2. **Kill-Switch** — emergency read-only mode that blocks all
//!    high-risk / mutating commands instantly.
//! 3. **Step-Up Authentication** — high-risk commands require a
//!    challenge/response before execution.
//!
//! ```text
//! Request ──► Replay Check ──► Kill-Switch ──► Risk Gate ──► PolicyEngine
//!                  │                │               │
//!               Reject           Reject         Challenge
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::Utc;
use log::{info, warn};
use uuid::Uuid;

use agent_watchdog_common::RiskLevel;

// ── Nonce Cache (TTL-based) ──────────────────────────────────────

/// Entry in the nonce cache: the nonce value + when it expires.
struct NonceEntry {
    /// Monotonic expiry instant for O(1) comparison.
    expires_at: Instant,
}

/// In-memory TTL cache for replay prevention.
///
/// Stores recent nonces so that any duplicate within the replay
/// window is detected and rejected.  Expired entries are lazily
/// purged on each `check_and_insert` call.
pub struct NonceCache {
    inner: Mutex<NonceCacheInner>,
    /// How long nonces are kept before they expire.
    ttl: Duration,
}

struct NonceCacheInner {
    entries: HashMap<String, NonceEntry>,
    /// Monotonic clock snapshot of last garbage-collection sweep.
    last_gc: Instant,
}

impl NonceCache {
    /// Create a new nonce cache with the given TTL (seconds).
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            inner: Mutex::new(NonceCacheInner {
                entries: HashMap::new(),
                last_gc: Instant::now(),
            }),
            ttl: Duration::from_secs(ttl_seconds),
        }
    }

    /// Check whether `nonce` has been seen before.
    ///
    /// - Returns `true` if the nonce is **fresh** (inserted OK).
    /// - Returns `false` if the nonce is **duplicate** (replay!).
    pub fn check_and_insert(&self, nonce: &str) -> bool {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // Lazy GC every 30 seconds
        if now.duration_since(inner.last_gc) > Duration::from_secs(30) {
            inner.entries.retain(|_, entry| entry.expires_at > now);
            inner.last_gc = now;
        }

        // Check for duplicate
        if let Some(entry) = inner.entries.get(nonce) {
            if entry.expires_at > now {
                return false; // duplicate — replay detected
            }
            // Expired entry — overwrite below
        }

        inner.entries.insert(
            nonce.to_string(),
            NonceEntry {
                expires_at: now + self.ttl,
            },
        );

        true
    }

    /// Number of active (non-expired) entries.  Used by tests.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        let now = Instant::now();
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.entries.values().filter(|e| e.expires_at > now).count()
    }
}

// ── Challenge Store ──────────────────────────────────────────────

/// A pending step-up authentication challenge.
#[derive(Debug, Clone)]
pub struct PendingChallenge {
    /// Unique challenge ID returned to the caller.
    pub challenge_id: String,
    /// Which agent triggered the challenge.
    pub agent_id: String,
    /// Which user owns the session.
    pub user_id: String,
    /// The tool that was requested.
    pub tool: String,
    /// Original arguments (frozen).
    pub args: serde_json::Value,
    /// When the challenge was created.
    pub created_at: chrono::DateTime<Utc>,
    /// Monotonic expiry instant.
    pub expires_at: Instant,
}

/// Temporary store for high-risk challenges awaiting step-up verification.
pub struct ChallengeStore {
    inner: Mutex<ChallengeStoreInner>,
    /// How long a challenge remains valid.
    ttl: Duration,
}

struct ChallengeStoreInner {
    challenges: HashMap<String, PendingChallenge>,
    last_gc: Instant,
}

impl ChallengeStore {
    /// Create a new challenge store.  Challenges expire after `ttl_seconds`.
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            inner: Mutex::new(ChallengeStoreInner {
                challenges: HashMap::new(),
                last_gc: Instant::now(),
            }),
            ttl: Duration::from_secs(ttl_seconds),
        }
    }

    /// Create a new pending challenge.  Returns the challenge ID.
    pub fn create(
        &self,
        agent_id: &str,
        user_id: &str,
        tool: &str,
        args: &serde_json::Value,
    ) -> String {
        let now_mono = Instant::now();
        let id = Uuid::new_v4().to_string();

        let challenge = PendingChallenge {
            challenge_id: id.clone(),
            agent_id: agent_id.to_string(),
            user_id: user_id.to_string(),
            tool: tool.to_string(),
            args: args.clone(),
            created_at: Utc::now(),
            expires_at: now_mono + self.ttl,
        };

        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // Lazy GC
        if now_mono.duration_since(inner.last_gc) > Duration::from_secs(30) {
            inner
                .challenges
                .retain(|_, c| c.expires_at > now_mono);
            inner.last_gc = now_mono;
        }

        inner.challenges.insert(id.clone(), challenge);
        id
    }

    /// Verify and consume a challenge.
    ///
    /// Returns `Some(challenge)` if the ID is valid and not expired,
    /// and removes it from the store (single-use).
    /// Returns `None` if the challenge is unknown or expired.
    pub fn verify_and_consume(&self, challenge_id: &str) -> Option<PendingChallenge> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        match inner.challenges.remove(challenge_id) {
            Some(c) if c.expires_at > now => Some(c),
            _ => None,
        }
    }

    /// Number of active (non-expired) challenges.  Used by tests.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        let now = Instant::now();
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner
            .challenges
            .values()
            .filter(|c| c.expires_at > now)
            .count()
    }
}

// ── Risk Classification ──────────────────────────────────────────

/// Mutating / high-risk tool names.  Used by the kill-switch and
/// risk classifier to identify operations that must be blocked in
/// emergency mode or require step-up auth.
const HIGH_RISK_TOOLS: &[&str] = &[
    "shell_exec",
    "exec",
    "run_command",
    "bash",
    "file_write",
    "file_delete",
    "fs_write",
    "write_file",
    "code_exec",
    "eval",
    "python_exec",
    "database_query",
    "sql_query",
    "db_exec",
];

const MEDIUM_RISK_TOOLS: &[&str] = &[
    "file_read",
    "fs_read",
    "read_file",
    "http_request",
    "fetch",
    "curl",
    "api_call",
    "env_read",
    "get_env",
    "read_env",
];

/// Classify a tool + risk-score into a `RiskLevel`.
pub fn classify_risk(tool: &str, risk_score: f64) -> RiskLevel {
    let tool_lower = tool.to_ascii_lowercase();

    if HIGH_RISK_TOOLS.iter().any(|t| *t == tool_lower) || risk_score >= 70.0 {
        RiskLevel::High
    } else if MEDIUM_RISK_TOOLS.iter().any(|t| *t == tool_lower) || risk_score >= 40.0 {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

// ── Gateway Verdict ──────────────────────────────────────────────

/// Result of the anti-hijack gateway check.
#[derive(Debug, Clone)]
pub enum GatewayVerdict {
    /// Request passes all anti-hijack checks — proceed to policy engine.
    Pass,
    /// Blocked: timestamp too old (replay window exceeded).
    ReplayExpired {
        age_seconds: i64,
        max_seconds: i64,
    },
    /// Blocked: duplicate nonce detected.
    ReplayDuplicate {
        nonce: String,
    },
    /// Blocked: kill-switch is active (emergency read-only mode).
    KillSwitchActive {
        tool: String,
    },
    /// Blocked: high-risk operation requires step-up authentication.
    StepUpRequired {
        challenge_id: String,
        risk_level: RiskLevel,
        tool: String,
    },
}

impl GatewayVerdict {
    /// Whether the request should be allowed to proceed.
    pub fn is_pass(&self) -> bool {
        matches!(self, GatewayVerdict::Pass)
    }
}

// ── Gateway ──────────────────────────────────────────────────────

/// The Anti-Hijack Gateway.
///
/// Sits in front of the `PolicyEngine` and performs envelope-level
/// security checks before the request ever reaches policy evaluation.
pub struct AntiHijackGateway {
    nonce_cache: NonceCache,
    challenge_store: ChallengeStore,
    replay_window_seconds: i64,
    kill_switch_enabled: bool,
}

impl AntiHijackGateway {
    /// Create a new gateway with the given configuration.
    pub fn new(replay_window_seconds: i64, kill_switch_enabled: bool) -> Self {
        Self {
            nonce_cache: NonceCache::new(replay_window_seconds as u64),
            challenge_store: ChallengeStore::new(300), // 5-minute challenge TTL
            replay_window_seconds,
            kill_switch_enabled,
        }
    }

    /// Primary entry point: validate an incoming command envelope.
    ///
    /// Returns a `GatewayVerdict` indicating whether the request
    /// should proceed, be rejected, or requires step-up auth.
    pub fn check(
        &self,
        timestamp: i64,
        nonce: &str,
        tool: &str,
        risk_score: f64,
        agent_id: &str,
        user_id: &str,
        args: &serde_json::Value,
    ) -> GatewayVerdict {
        // ── 1. Replay protection: timestamp freshness ────────────
        let now = Utc::now().timestamp();
        let age = now - timestamp;

        if age > self.replay_window_seconds || age < -self.replay_window_seconds {
            warn!(
                "🛑 REPLAY: timestamp expired — age={}s, max={}s, nonce={}",
                age, self.replay_window_seconds, nonce
            );
            return GatewayVerdict::ReplayExpired {
                age_seconds: age,
                max_seconds: self.replay_window_seconds,
            };
        }

        // ── 2. Replay protection: nonce uniqueness ───────────────
        if !self.nonce_cache.check_and_insert(nonce) {
            warn!("🛑 REPLAY: duplicate nonce detected — nonce={}", nonce);
            return GatewayVerdict::ReplayDuplicate {
                nonce: nonce.to_string(),
            };
        }

        // ── 3. Kill-switch: emergency read-only mode ─────────────
        let risk_level = classify_risk(tool, risk_score);

        if self.kill_switch_enabled && risk_level == RiskLevel::High {
            warn!(
                "🛑 KILL-SWITCH: blocking high-risk tool={} (read-only mode)",
                tool
            );
            return GatewayVerdict::KillSwitchActive {
                tool: tool.to_string(),
            };
        }

        // ── 4. Step-up authentication for high-risk commands ─────
        if risk_level == RiskLevel::High {
            let challenge_id = self.challenge_store.create(
                agent_id, user_id, tool, args,
            );
            info!(
                "⚠️  STEP-UP required: tool={}, challenge_id={}, risk_level={:?}",
                tool, challenge_id, risk_level
            );
            return GatewayVerdict::StepUpRequired {
                challenge_id,
                risk_level,
                tool: tool.to_string(),
            };
        }

        // ── 5. All checks passed ─────────────────────────────────
        GatewayVerdict::Pass
    }

    /// Verify a step-up challenge response.
    ///
    /// Returns the original challenge if valid, `None` if expired
    /// or unknown.
    pub fn verify_challenge(&self, challenge_id: &str) -> Option<PendingChallenge> {
        self.challenge_store.verify_and_consume(challenge_id)
    }

    /// Check **only** replay protection (timestamp + nonce).
    ///
    /// Used by the restructured pipeline where policy evaluation
    /// happens *before* step-up / kill-switch gating.
    pub fn check_replay_only(
        &self,
        timestamp: i64,
        nonce: &str,
    ) -> GatewayVerdict {
        // ── Timestamp freshness ──────────────────────────────────
        let now = Utc::now().timestamp();
        let age = now - timestamp;

        if age > self.replay_window_seconds || age < -self.replay_window_seconds {
            warn!(
                "🛑 REPLAY: timestamp expired — age={}s, max={}s, nonce={}",
                age, self.replay_window_seconds, nonce
            );
            return GatewayVerdict::ReplayExpired {
                age_seconds: age,
                max_seconds: self.replay_window_seconds,
            };
        }

        // ── Nonce uniqueness ─────────────────────────────────────
        if !self.nonce_cache.check_and_insert(nonce) {
            warn!("🛑 REPLAY: duplicate nonce detected — nonce={}", nonce);
            return GatewayVerdict::ReplayDuplicate {
                nonce: nonce.to_string(),
            };
        }

        GatewayVerdict::Pass
    }

    /// Check kill-switch and step-up authentication **only**.
    ///
    /// Called *after* the policy engine has already evaluated the
    /// request — only for requests that the policy ALLOWs.
    /// High-risk tools that policy explicitly blocks will never
    /// reach this method.
    pub fn check_risk_gate(
        &self,
        tool: &str,
        risk_score: f64,
        agent_id: &str,
        user_id: &str,
        args: &serde_json::Value,
    ) -> GatewayVerdict {
        let risk_level = classify_risk(tool, risk_score);

        // ── Kill-switch: emergency read-only mode ────────────────
        if self.kill_switch_enabled && risk_level == RiskLevel::High {
            warn!(
                "🛑 KILL-SWITCH: blocking high-risk tool={} (read-only mode)",
                tool
            );
            return GatewayVerdict::KillSwitchActive {
                tool: tool.to_string(),
            };
        }

        // ── Step-up authentication for high-risk commands ────────
        if risk_level == RiskLevel::High {
            let challenge_id = self.challenge_store.create(
                agent_id, user_id, tool, args,
            );
            info!(
                "⚠️  STEP-UP required: tool={}, challenge_id={}, risk_level={:?}",
                tool, challenge_id, risk_level
            );
            return GatewayVerdict::StepUpRequired {
                challenge_id,
                risk_level,
                tool: tool.to_string(),
            };
        }

        GatewayVerdict::Pass
    }

    /// Runtime toggle: enable or disable the kill-switch.
    pub fn set_kill_switch(&mut self, enabled: bool) {
        info!("🔧 Kill-switch set to: {}", enabled);
        self.kill_switch_enabled = enabled;
    }

    /// Whether the kill-switch is currently active.
    pub fn kill_switch_active(&self) -> bool {
        self.kill_switch_enabled
    }
}

// ══════════════════════════════════════════════════════════════════
// ── Tests ────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Nonce Cache ──────────────────────────────────────────────

    #[test]
    fn fresh_nonce_is_accepted() {
        let cache = NonceCache::new(60);
        assert!(cache.check_and_insert("nonce-1"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn duplicate_nonce_is_rejected() {
        let cache = NonceCache::new(60);
        assert!(cache.check_and_insert("nonce-dup"));
        assert!(!cache.check_and_insert("nonce-dup")); // replay!
    }

    #[test]
    fn different_nonces_are_independent() {
        let cache = NonceCache::new(60);
        assert!(cache.check_and_insert("a"));
        assert!(cache.check_and_insert("b"));
        assert!(cache.check_and_insert("c"));
        assert_eq!(cache.len(), 3);
    }

    // ── Challenge Store ──────────────────────────────────────────

    #[test]
    fn challenge_create_and_verify() {
        let store = ChallengeStore::new(300);
        let id = store.create(
            "agent-1",
            "user-1",
            "shell_exec",
            &serde_json::json!({"cmd": "rm -rf /"}),
        );
        assert_eq!(store.len(), 1);

        let challenge = store.verify_and_consume(&id);
        assert!(challenge.is_some());
        assert_eq!(challenge.unwrap().tool, "shell_exec");

        // Single-use: second verify returns None
        assert!(store.verify_and_consume(&id).is_none());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn unknown_challenge_returns_none() {
        let store = ChallengeStore::new(300);
        assert!(store.verify_and_consume("nonexistent").is_none());
    }

    // ── Risk Classification ──────────────────────────────────────

    #[test]
    fn shell_exec_is_high_risk() {
        assert_eq!(classify_risk("shell_exec", 0.0), RiskLevel::High);
    }

    #[test]
    fn calculator_is_low_risk() {
        assert_eq!(classify_risk("calculator", 5.0), RiskLevel::Low);
    }

    #[test]
    fn high_score_overrides_tool_category() {
        // Even a "calculator" becomes High if the risk score is ≥ 70
        assert_eq!(classify_risk("calculator", 75.0), RiskLevel::High);
    }

    #[test]
    fn file_read_is_medium_risk() {
        assert_eq!(classify_risk("file_read", 20.0), RiskLevel::Medium);
    }

    // ── Gateway: Replay Protection ───────────────────────────────

    #[test]
    fn expired_timestamp_is_rejected() {
        let gw = AntiHijackGateway::new(60, false);
        let old_ts = Utc::now().timestamp() - 120; // 2 minutes ago

        let verdict = gw.check(
            old_ts,
            "nonce-expired",
            "calculator",
            5.0,
            "agent-1",
            "user-1",
            &serde_json::json!({}),
        );

        assert!(!verdict.is_pass());
        assert!(matches!(verdict, GatewayVerdict::ReplayExpired { .. }));
    }

    #[test]
    fn nonce_replay_is_rejected() {
        let gw = AntiHijackGateway::new(60, false);
        let now = Utc::now().timestamp();

        // First request: fresh
        let v1 = gw.check(now, "nonce-1", "calculator", 5.0, "a", "u", &serde_json::json!({}));
        assert!(v1.is_pass());

        // Second request: same nonce → replay
        let v2 = gw.check(now, "nonce-1", "calculator", 5.0, "a", "u", &serde_json::json!({}));
        assert!(!v2.is_pass());
        assert!(matches!(v2, GatewayVerdict::ReplayDuplicate { .. }));
    }

    #[test]
    fn fresh_request_passes() {
        let gw = AntiHijackGateway::new(60, false);
        let now = Utc::now().timestamp();

        let verdict = gw.check(
            now,
            "unique-nonce",
            "calculator",
            5.0,
            "agent-1",
            "user-1",
            &serde_json::json!({"expr": "1+1"}),
        );

        assert!(verdict.is_pass());
    }

    // ── Gateway: Kill-Switch ─────────────────────────────────────

    #[test]
    fn kill_switch_blocks_high_risk() {
        let gw = AntiHijackGateway::new(60, true); // kill-switch ON
        let now = Utc::now().timestamp();

        let verdict = gw.check(
            now,
            "ks-nonce",
            "shell_exec",
            40.0,
            "agent-1",
            "user-1",
            &serde_json::json!({"cmd": "ls"}),
        );

        assert!(!verdict.is_pass());
        assert!(matches!(verdict, GatewayVerdict::KillSwitchActive { .. }));
    }

    #[test]
    fn kill_switch_allows_low_risk() {
        let gw = AntiHijackGateway::new(60, true); // kill-switch ON
        let now = Utc::now().timestamp();

        let verdict = gw.check(
            now,
            "ks-low",
            "calculator",
            5.0,
            "agent-1",
            "user-1",
            &serde_json::json!({"expr": "2+2"}),
        );

        assert!(verdict.is_pass());
    }

    // ── Gateway: Step-Up Authentication ──────────────────────────

    #[test]
    fn high_risk_requires_step_up() {
        let gw = AntiHijackGateway::new(60, false); // kill-switch OFF
        let now = Utc::now().timestamp();

        let verdict = gw.check(
            now,
            "stepup-nonce",
            "shell_exec",
            40.0,
            "agent-1",
            "user-1",
            &serde_json::json!({"cmd": "rm -rf /"}),
        );

        assert!(!verdict.is_pass());
        match verdict {
            GatewayVerdict::StepUpRequired {
                challenge_id,
                risk_level,
                tool,
            } => {
                assert!(!challenge_id.is_empty());
                assert_eq!(risk_level, RiskLevel::High);
                assert_eq!(tool, "shell_exec");

                // Verify the challenge can be consumed
                let challenge = gw.verify_challenge(&challenge_id);
                assert!(challenge.is_some());

                // Second verify fails (single-use)
                assert!(gw.verify_challenge(&challenge_id).is_none());
            }
            _ => panic!("Expected StepUpRequired, got {:?}", verdict),
        }
    }

    #[test]
    fn medium_risk_passes_without_step_up() {
        let gw = AntiHijackGateway::new(60, false);
        let now = Utc::now().timestamp();

        let verdict = gw.check(
            now,
            "med-nonce",
            "file_read",
            20.0,
            "agent-1",
            "user-1",
            &serde_json::json!({"path": "/tmp/readme.txt"}),
        );

        assert!(verdict.is_pass());
    }

    // ── Gateway: Combined Scenarios ──────────────────────────────

    #[test]
    fn replay_checked_before_kill_switch() {
        // Even with kill-switch ON, expired timestamps are rejected first
        let gw = AntiHijackGateway::new(60, true);
        let old_ts = Utc::now().timestamp() - 300;

        let verdict = gw.check(
            old_ts,
            "combo-nonce",
            "shell_exec",
            40.0,
            "agent-1",
            "user-1",
            &serde_json::json!({}),
        );

        assert!(matches!(verdict, GatewayVerdict::ReplayExpired { .. }));
    }

    #[test]
    fn future_timestamp_is_rejected() {
        let gw = AntiHijackGateway::new(60, false);
        let future_ts = Utc::now().timestamp() + 120; // 2 minutes in the future

        let verdict = gw.check(
            future_ts,
            "future-nonce",
            "calculator",
            5.0,
            "agent-1",
            "user-1",
            &serde_json::json!({}),
        );

        assert!(!verdict.is_pass());
        assert!(matches!(verdict, GatewayVerdict::ReplayExpired { .. }));
    }
}
