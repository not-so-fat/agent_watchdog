//! Audit Trail for Agent-WatchDog.
//!
//! Every tool-call request is recorded with full context:
//! agent_id, user_id, tool, args, decision, risk_score, timestamp.
//!
//! The audit log is the **moat** — it provides forensic evidence
//! and compliance data that no competitor can retroactively build.

use std::collections::VecDeque;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::risk::RiskScore;

/// Maximum audit records kept in memory.
const MAX_AUDIT_RECORDS: usize = 50_000;

// ── Audit Record ─────────────────────────────────────────────────

/// The enforcement decision recorded in the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditDecision {
    Allow,
    Block,
}

/// A complete audit record for a single tool-call evaluation.
///
/// This is the minimum viable audit schema that captures:
/// WHO (agent_id, user_id) did WHAT (tool, args)
/// and WHAT HAPPENED (decision, risk_score, reason).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unique record ID.
    pub id: String,
    /// When the evaluation occurred.
    pub timestamp: DateTime<Utc>,
    /// Which AI agent made the call.
    pub agent_id: String,
    /// Which user/session owns the agent.
    pub user_id: String,
    /// Optional session/conversation ID.
    pub session_id: Option<String>,
    /// The tool being invoked.
    pub tool: String,
    /// Full tool arguments (preserved for forensics).
    pub args: serde_json::Value,
    /// The enforcement decision.
    pub decision: AuditDecision,
    /// Numeric risk score (0–100).
    pub risk_score: f64,
    /// Detailed risk score breakdown.
    pub risk_breakdown: RiskScore,
    /// Human-readable reason for the decision.
    pub reason: String,
    /// Which policy rule triggered (if any).
    pub matched_rule: Option<String>,
    /// Whether the system was in dry-run mode.
    pub dry_run: bool,
}

// ── Audit Store ──────────────────────────────────────────────────

/// Thread-safe handle to the audit store.
pub type SharedAuditStore = Arc<RwLock<AuditStore>>;

/// In-memory ring buffer of audit records.
pub struct AuditStore {
    records: VecDeque<AuditRecord>,
}

impl AuditStore {
    /// Create a new empty audit store.
    pub fn new() -> Self {
        Self {
            records: VecDeque::with_capacity(MAX_AUDIT_RECORDS),
        }
    }

    /// Create a thread-safe shared handle.
    pub fn shared() -> SharedAuditStore {
        Arc::new(RwLock::new(Self::new()))
    }

    /// Record an audit entry.
    pub fn record(&mut self, entry: AuditRecord) {
        if self.records.len() >= MAX_AUDIT_RECORDS {
            self.records.pop_front();
        }
        self.records.push_back(entry);
    }

    /// Get all audit records, newest first.
    pub fn all_records(&self) -> Vec<AuditRecord> {
        self.records.iter().rev().cloned().collect()
    }

    /// Get recent N records.
    pub fn recent(&self, limit: usize) -> Vec<AuditRecord> {
        self.records
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get records for a specific agent.
    pub fn by_agent(&self, agent_id: &str) -> Vec<AuditRecord> {
        self.records
            .iter()
            .rev()
            .filter(|r| r.agent_id == agent_id)
            .cloned()
            .collect()
    }

    /// Get blocked-only records.
    pub fn blocked_only(&self) -> Vec<AuditRecord> {
        self.records
            .iter()
            .rev()
            .filter(|r| r.decision == AuditDecision::Block)
            .cloned()
            .collect()
    }

    /// Summary statistics.
    pub fn stats(&self) -> AuditStats {
        let total = self.records.len();
        let blocked = self.records.iter().filter(|r| r.decision == AuditDecision::Block).count();
        let allowed = total - blocked;

        let now = Utc::now();
        let one_hour_ago = now - chrono::Duration::hours(1);
        let recent_blocked = self
            .records
            .iter()
            .filter(|r| r.timestamp >= one_hour_ago && r.decision == AuditDecision::Block)
            .count();

        let avg_risk = if total > 0 {
            self.records.iter().map(|r| r.risk_score).sum::<f64>() / total as f64
        } else {
            0.0
        };

        AuditStats {
            total_evaluations: total,
            total_allowed: allowed,
            total_blocked: blocked,
            blocked_last_hour: recent_blocked,
            avg_risk_score: avg_risk,
        }
    }
}

/// Audit summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    pub total_evaluations: usize,
    pub total_allowed: usize,
    pub total_blocked: usize,
    pub blocked_last_hour: usize,
    pub avg_risk_score: f64,
}
