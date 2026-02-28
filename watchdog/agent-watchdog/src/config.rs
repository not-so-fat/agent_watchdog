//! Configuration loading for Agent-WatchDog.
//!
//! Reads a TOML configuration file that controls dry-run mode,
//! process/PID/path whitelists, policy rules, and risk thresholds.

use std::path::Path;

use anyhow::{Context, Result};
use log::info;
use serde::Deserialize;

use crate::policy::{Decision, PolicyRule, RuleAction, RuleConditions};

/// Top-level configuration structure.
///
/// Loaded from a TOML file (default: `watchdog.toml`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// When `true`, alerts are logged but `SIGKILL` is never sent.
    pub dry_run: bool,

    /// Process names to ignore (case-insensitive match on `comm`).
    pub whitelist_processes: Vec<String>,

    /// Specific PIDs to ignore.
    pub whitelist_pids: Vec<u32>,

    /// File-path prefixes to ignore.
    pub whitelist_paths: Vec<String>,

    /// Override built-in sensitive keywords.
    /// If `None` (omitted), the compiled-in defaults are used.
    pub sensitive_keywords: Option<Vec<String>>,

    // ── Firewall / Policy settings ───────────────────────────────

    /// Default action when no policy rules match: "allow" or "block".
    pub default_action: String,

    /// Risk score threshold for auto-blocking (0–100).
    /// If the computed risk score exceeds this, the call is blocked
    /// even without a matching rule.
    pub risk_threshold: f64,

    /// Firewall proxy port (separate from dashboard API).
    pub firewall_port: u16,

    // ── Anti-Hijack settings ─────────────────────────────────────

    /// Maximum age (in seconds) of a command timestamp before it is
    /// rejected as a potential replay.  Default: 60.
    pub replay_window_seconds: i64,

    /// Emergency kill-switch.  When `true`, ALL high-risk / mutating
    /// commands are immediately blocked (read-only mode).  Default: false.
    pub kill_switch_enabled: bool,

    // ── PID-based eBPF filtering ─────────────────────────────────

    /// PIDs to watch in the eBPF probe.  Only `openat` events from
    /// these PIDs will be forwarded to user-space.  When empty, the
    /// eBPF map stays empty and **no** events are monitored (secure
    /// by default — you must opt-in).
    ///
    /// Populated into the `WATCHED_PIDS` BPF HashMap on startup and
    /// can be updated at runtime via `POST /api/config/watch-pid`.
    #[serde(default)]
    pub target_pids: Vec<u32>,

    /// Policy rules loaded from the TOML config.
    #[serde(default, rename = "policy_rule")]
    pub policy_rules: Vec<PolicyRuleConfig>,
}

/// A policy rule as deserialized from TOML.
///
/// Maps to a `[[policy_rule]]` table array in the config file.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRuleConfig {
    pub id: String,
    pub description: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub action: String,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub arg_contains: Vec<String>,
    #[serde(default)]
    pub agent_ids: Vec<String>,
    #[serde(default)]
    pub min_risk_score: Option<f64>,
}

fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dry_run: false,
            whitelist_processes: Vec::new(),
            whitelist_pids: Vec::new(),
            whitelist_paths: Vec::new(),
            sensitive_keywords: None,
            default_action: "allow".into(),
            risk_threshold: 80.0,
            firewall_port: 3001,
            replay_window_seconds: 60,
            kill_switch_enabled: false,
            target_pids: Vec::new(),
            policy_rules: Vec::new(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file.
    ///
    /// If the file does not exist, returns the default configuration
    /// with a warning.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            info!(
                "Config file '{}' not found — using defaults",
                path.display()
            );
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file '{}'", path.display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("failed to parse config file '{}'", path.display()))?;

        info!("📋  Loaded config from '{}'", path.display());
        info!("    dry_run = {}", config.dry_run);
        info!(
            "    whitelist_processes = {:?}",
            config.whitelist_processes
        );
        info!("    whitelist_pids = {:?}", config.whitelist_pids);
        info!("    whitelist_paths = {:?}", config.whitelist_paths);
        info!("    default_action = {}", config.default_action);
        info!("    risk_threshold = {:.1}", config.risk_threshold);
        info!("    firewall_port = {}", config.firewall_port);
        info!("    replay_window_seconds = {}", config.replay_window_seconds);
        info!("    kill_switch_enabled = {}", config.kill_switch_enabled);
        info!("    target_pids = {:?}", config.target_pids);
        info!("    policy_rules = {} loaded", config.policy_rules.len());

        Ok(config)
    }

    /// Check whether a process name is whitelisted.
    pub fn is_process_whitelisted(&self, comm: &str) -> bool {
        let lower = comm.to_ascii_lowercase();
        self.whitelist_processes
            .iter()
            .any(|w| lower == w.to_ascii_lowercase())
    }

    /// Check whether a PID is whitelisted.
    pub fn is_pid_whitelisted(&self, pid: u32) -> bool {
        self.whitelist_pids.contains(&pid)
    }

    /// Check whether a file path is whitelisted (by prefix).
    pub fn is_path_whitelisted(&self, path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        self.whitelist_paths
            .iter()
            .any(|prefix| lower.starts_with(&prefix.to_ascii_lowercase()))
    }

    /// Check if a filename matches any sensitive keyword.
    ///
    /// Uses the configured keywords if set, otherwise falls back to
    /// the built-in `DEFAULT_SENSITIVE_KEYWORDS`.
    pub fn is_sensitive(&self, filename: &str) -> bool {
        let lower = filename.to_ascii_lowercase();
        match &self.sensitive_keywords {
            Some(keywords) => keywords.iter().any(|kw| lower.contains(kw)),
            None => DEFAULT_SENSITIVE_KEYWORDS
                .iter()
                .any(|kw| lower.contains(kw)),
        }
    }

    /// Parse the string `default_action` into a `Decision` enum.
    pub fn parsed_default_action(&self) -> Decision {
        match self.default_action.to_ascii_lowercase().as_str() {
            "block" | "deny" => Decision::Block,
            _ => Decision::Allow,
        }
    }

    /// Convert the TOML-loaded policy rules into the engine's `PolicyRule` type.
    pub fn build_policy_rules(&self) -> Vec<PolicyRule> {
        self.policy_rules
            .iter()
            .map(|r| PolicyRule {
                id: r.id.clone(),
                description: r.description.clone(),
                enabled: r.enabled,
                action: match r.action.to_ascii_lowercase().as_str() {
                    "block" | "deny" => RuleAction::Block,
                    _ => RuleAction::Allow,
                },
                conditions: RuleConditions {
                    tools: r.tools.clone(),
                    arg_contains: r.arg_contains.clone(),
                    agent_ids: r.agent_ids.clone(),
                    min_risk_score: r.min_risk_score,
                },
            })
            .collect()
    }
}

/// Built-in default sensitive keywords.
pub const DEFAULT_SENSITIVE_KEYWORDS: &[&str] = &[
    ".env",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "shadow",
    "aws/credentials",
    "gcp/application_default_credentials.json",
    ".kube/config",
    ".docker/config.json",
    "secrets.yaml",
    "secrets.yml",
    "master.key",
    ".pgpass",
    ".netrc",
];
