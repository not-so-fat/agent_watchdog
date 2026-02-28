//! In-memory event store for Agent-WatchDog alerts.
//!
//! Stores recent `AlertEvent`s in a `VecDeque` with a configurable
//! capacity.  Thread-safe via `Arc<RwLock<...>>`.

use std::collections::VecDeque;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Maximum number of events kept in memory.
const MAX_EVENTS: usize = 10_000;

// ── Data types ───────────────────────────────────────────────────

/// Severity level of an alert.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Medium,
    Low,
}

/// Status of an alert event.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AlertStatus {
    /// Alert is active and needs attention.
    Active,
    /// Process has been blocked (killed).
    Blocked,
    /// Alert was marked as false-positive.
    Ignored,
}

/// A single alert event, enriched from the raw eBPF `FileOpenEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    /// Unique event identifier.
    pub id: String,
    /// When the event was captured.
    pub timestamp: DateTime<Utc>,
    /// Process ID that triggered the alert.
    pub pid: u32,
    /// Process command name (e.g. "cat", "python3").
    pub comm: String,
    /// File path being accessed (resolved to absolute path).
    pub filename: String,
    /// Alert severity.
    pub severity: Severity,
    /// Current status.
    pub status: AlertStatus,
    /// Whether this event was captured in dry-run mode.
    /// If `true`, blocking will NOT actually kill the process.
    pub dry_run: bool,
}

/// Dashboard summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    /// Alerts in the past 24 hours.
    pub today_alerts: usize,
    /// Currently active (unresolved) alerts.
    pub active_alerts: usize,
    /// Total processes blocked historically.
    pub blocked_count: usize,
    /// Total alerts marked as false-positive.
    pub ignored_count: usize,
    /// Total events captured.
    pub total_events: usize,
}

// ── EventStore ───────────────────────────────────────────────────

/// Thread-safe handle to the event store.
pub type SharedEventStore = Arc<RwLock<EventStore>>;

/// In-memory ring buffer of alert events.
pub struct EventStore {
    events: VecDeque<AlertEvent>,
    /// Lifetime counter of blocked processes.
    total_blocked: usize,
    /// Lifetime counter of ignored alerts.
    total_ignored: usize,
}

impl EventStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self {
            events: VecDeque::with_capacity(MAX_EVENTS),
            total_blocked: 0,
            total_ignored: 0,
        }
    }

    /// Create a thread-safe shared handle.
    pub fn shared() -> SharedEventStore {
        Arc::new(RwLock::new(Self::new()))
    }

    /// Push a new alert event, evicting the oldest if at capacity.
    pub fn push(&mut self, event: AlertEvent) {
        if self.events.len() >= MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    /// Return all events, newest first.
    pub fn all_events(&self) -> Vec<AlertEvent> {
        self.events.iter().rev().cloned().collect()
    }

    /// Return only active alerts, newest first.
    pub fn active_alerts(&self) -> Vec<AlertEvent> {
        self.events
            .iter()
            .rev()
            .filter(|e| e.status == AlertStatus::Active)
            .cloned()
            .collect()
    }

    /// Mark an event as blocked and increment the counter.
    /// Returns `true` if the event was found and updated.
    pub fn block_event(&mut self, id: &str) -> Option<AlertEvent> {
        if let Some(ev) = self.events.iter_mut().find(|e| e.id == id) {
            ev.status = AlertStatus::Blocked;
            self.total_blocked += 1;
            Some(ev.clone())
        } else {
            None
        }
    }

    /// Mark an event as ignored (false positive).
    pub fn ignore_event(&mut self, id: &str) -> Option<AlertEvent> {
        if let Some(ev) = self.events.iter_mut().find(|e| e.id == id) {
            ev.status = AlertStatus::Ignored;
            self.total_ignored += 1;
            Some(ev.clone())
        } else {
            None
        }
    }

    /// Compute dashboard statistics.
    pub fn stats(&self) -> DashboardStats {
        let now = Utc::now();
        let twenty_four_hours_ago = now - chrono::Duration::hours(24);

        let today_alerts = self
            .events
            .iter()
            .filter(|e| e.timestamp >= twenty_four_hours_ago)
            .count();

        let active_alerts = self
            .events
            .iter()
            .filter(|e| e.status == AlertStatus::Active)
            .count();

        DashboardStats {
            today_alerts,
            active_alerts,
            blocked_count: self.total_blocked,
            ignored_count: self.total_ignored,
            total_events: self.events.len(),
        }
    }
}
