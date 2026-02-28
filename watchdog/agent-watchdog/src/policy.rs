//! Policy Engine — Rule-based decision engine for Agent-WatchDog.
//!
//! Evaluates incoming tool-call requests against a set of configurable
//! rules and returns an **enforce** decision: `Allow` or `Block`.
//!
//! This is the core "firewall" logic — NOT just logging.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::audit::{AuditDecision, AuditRecord};
use crate::risk::RiskScore;

// ── Policy Decision ──────────────────────────────────────────────

/// The enforcement result. This is a hard decision, not a suggestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// The tool call is permitted.
    Allow,
    /// The tool call is blocked. The caller receives a SecurityException.
    Block,
}

/// Full evaluation result with reasoning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    /// The hard decision.
    pub decision: Decision,
    /// Risk score that contributed to the decision.
    pub risk_score: RiskScore,
    /// Human-readable reason for the decision.
    pub reason: String,
    /// Which rule triggered the block (if any).
    pub matched_rule: Option<String>,
}

// ── Policy Rule ──────────────────────────────────────────────────

/// A single policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique rule identifier (e.g. "block-file-read-shadow").
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Whether the rule is currently active.
    pub enabled: bool,
    /// Rule action: "block" or "allow".
    pub action: RuleAction,
    /// Match conditions — ALL must match for the rule to trigger.
    pub conditions: RuleConditions,
}

/// What happens when a rule matches.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Block,
    Allow,
}

/// Conditions that must ALL match for the rule to fire.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleConditions {
    /// Match against tool name (glob-like, e.g. "file_read", "exec_*").
    #[serde(default)]
    pub tools: Vec<String>,
    /// Match against argument values containing these substrings.
    #[serde(default)]
    pub arg_contains: Vec<String>,
    /// Match against specific agent IDs.
    #[serde(default)]
    pub agent_ids: Vec<String>,
    /// Risk score threshold — rule fires if score >= threshold.
    #[serde(default)]
    pub min_risk_score: Option<f64>,
}

// ── Policy Engine ────────────────────────────────────────────────

/// The tool-call request that gets evaluated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRequest {
    /// Which agent is making the call.
    pub agent_id: String,
    /// User/session that owns the agent.
    pub user_id: String,
    /// The tool being invoked (e.g. "file_read", "shell_exec", "http_request").
    pub tool: String,
    /// Tool arguments as key-value pairs.
    pub args: serde_json::Value,
    /// When the request was received.
    pub timestamp: DateTime<Utc>,
    /// Optional session/conversation ID.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// The policy engine. Holds all rules and evaluates requests.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
    /// Default action when no rules match.
    default_action: Decision,
    /// Risk score threshold for auto-blocking (even without a matching rule).
    risk_threshold: f64,
    /// Dry-run mode — log but don't enforce.
    dry_run: bool,
}

impl PolicyEngine {
    /// Whether the engine is in dry-run mode.
    pub fn dry_run(&self) -> bool {
        self.dry_run
    }

    /// Create a new policy engine.
    pub fn new(
        rules: Vec<PolicyRule>,
        default_action: Decision,
        risk_threshold: f64,
        dry_run: bool,
    ) -> Self {
        Self {
            rules,
            default_action,
            risk_threshold,
            dry_run,
        }
    }

    /// Evaluate a tool-call request against all rules.
    ///
    /// Returns a `PolicyResult` with the enforcement decision.
    /// This is the **core firewall logic** — the result is ENFORCED,
    /// not just logged.
    pub fn evaluate(&self, request: &ToolCallRequest, risk: &RiskScore) -> PolicyResult {
        // 1. Check explicit rules (deny-first, then allow)
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if self.rule_matches(rule, request, risk) {
                let decision = match rule.action {
                    RuleAction::Block => Decision::Block,
                    RuleAction::Allow => Decision::Allow,
                };

                return PolicyResult {
                    decision: if self.dry_run { Decision::Allow } else { decision },
                    risk_score: risk.clone(),
                    reason: if self.dry_run {
                        format!("[DRY-RUN] Rule '{}' would {}: {}",
                            rule.id,
                            if decision == Decision::Block { "BLOCK" } else { "ALLOW" },
                            rule.description
                        )
                    } else {
                        format!("Rule '{}': {}", rule.id, rule.description)
                    },
                    matched_rule: Some(rule.id.clone()),
                };
            }
        }

        // 2. Check risk threshold — auto-block if score exceeds threshold.
        if risk.total >= self.risk_threshold {
            let decision = if self.dry_run { Decision::Allow } else { Decision::Block };
            return PolicyResult {
                decision,
                risk_score: risk.clone(),
                reason: format!(
                    "{}Risk score {:.1} exceeds threshold {:.1}",
                    if self.dry_run { "[DRY-RUN] " } else { "" },
                    risk.total,
                    self.risk_threshold
                ),
                matched_rule: Some("auto:risk-threshold".to_string()),
            };
        }

        // 3. No rules matched, risk below threshold → default action.
        PolicyResult {
            decision: self.default_action,
            risk_score: risk.clone(),
            reason: "No matching rules — default policy applied".to_string(),
            matched_rule: None,
        }
    }

    /// Check if a single rule's conditions all match.
    fn rule_matches(&self, rule: &PolicyRule, req: &ToolCallRequest, risk: &RiskScore) -> bool {
        let cond = &rule.conditions;

        // Tool name match
        if !cond.tools.is_empty()
            && !cond.tools.iter().any(|t| glob_match(t, &req.tool))
        {
            return false;
        }

        // Argument content match
        if !cond.arg_contains.is_empty() {
            let args_str = req.args.to_string().to_ascii_lowercase();
            if !cond
                .arg_contains
                .iter()
                .any(|s| args_str.contains(&s.to_ascii_lowercase()))
            {
                return false;
            }
        }

        // Agent ID match
        if !cond.agent_ids.is_empty()
            && !cond.agent_ids.iter().any(|a| a == &req.agent_id)
        {
            return false;
        }

        // Risk threshold
        if let Some(min_score) = cond.min_risk_score {
            if risk.total < min_score {
                return false;
            }
        }

        true
    }

    /// Convert an evaluation into a full audit record.
    pub fn to_audit_record(
        &self,
        request: &ToolCallRequest,
        result: &PolicyResult,
    ) -> AuditRecord {
        AuditRecord {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: request.timestamp,
            agent_id: request.agent_id.clone(),
            user_id: request.user_id.clone(),
            session_id: request.session_id.clone(),
            tool: request.tool.clone(),
            args: request.args.clone(),
            decision: match result.decision {
                Decision::Allow => AuditDecision::Allow,
                Decision::Block => AuditDecision::Block,
            },
            risk_score: result.risk_score.total,
            risk_breakdown: result.risk_score.clone(),
            reason: result.reason.clone(),
            matched_rule: result.matched_rule.clone(),
            dry_run: self.dry_run,
        }
    }
}

/// Simple glob matching: `*` matches any sequence.
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let pat_lower = pattern.to_ascii_lowercase();
    let val_lower = value.to_ascii_lowercase();

    if pat_lower.starts_with('*') && pat_lower.ends_with('*') {
        val_lower.contains(&pat_lower[1..pat_lower.len() - 1])
    } else if pat_lower.starts_with('*') {
        val_lower.ends_with(&pat_lower[1..])
    } else if pat_lower.ends_with('*') {
        val_lower.starts_with(&pat_lower[..pat_lower.len() - 1])
    } else {
        val_lower == pat_lower
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::RiskScore;

    fn make_request(tool: &str, args: &str) -> ToolCallRequest {
        ToolCallRequest {
            agent_id: "agent-1".into(),
            user_id: "user-1".into(),
            tool: tool.into(),
            args: serde_json::from_str(args).unwrap_or(serde_json::Value::Null),
            timestamp: Utc::now(),
            session_id: None,
        }
    }

    fn low_risk() -> RiskScore {
        RiskScore {
            total: 15.0,
            tool_weight: 5.0,
            arg_danger: 5.0,
            frequency_penalty: 5.0,
            details: vec![],
        }
    }

    fn high_risk() -> RiskScore {
        RiskScore {
            total: 90.0,
            tool_weight: 40.0,
            arg_danger: 30.0,
            frequency_penalty: 20.0,
            details: vec!["Accessing /etc/shadow".into()],
        }
    }

    #[test]
    fn explicit_block_rule_fires() {
        let rules = vec![PolicyRule {
            id: "block-shadow".into(),
            description: "Block reading shadow file".into(),
            enabled: true,
            action: RuleAction::Block,
            conditions: RuleConditions {
                tools: vec!["file_read".into()],
                arg_contains: vec!["shadow".into()],
                ..Default::default()
            },
        }];

        let engine = PolicyEngine::new(rules, Decision::Allow, 80.0, false);
        let req = make_request("file_read", r#"{"path": "/etc/shadow"}"#);
        let result = engine.evaluate(&req, &low_risk());

        assert_eq!(result.decision, Decision::Block);
        assert_eq!(result.matched_rule, Some("block-shadow".into()));
    }

    #[test]
    fn risk_threshold_auto_blocks() {
        let engine = PolicyEngine::new(vec![], Decision::Allow, 80.0, false);
        let req = make_request("shell_exec", r#"{"cmd": "rm -rf /"}"#);
        let result = engine.evaluate(&req, &high_risk());

        assert_eq!(result.decision, Decision::Block);
        assert_eq!(result.matched_rule, Some("auto:risk-threshold".into()));
    }

    #[test]
    fn low_risk_allowed_by_default() {
        let engine = PolicyEngine::new(vec![], Decision::Allow, 80.0, false);
        let req = make_request("file_read", r#"{"path": "/tmp/readme.txt"}"#);
        let result = engine.evaluate(&req, &low_risk());

        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn dry_run_does_not_block() {
        let rules = vec![PolicyRule {
            id: "block-all-exec".into(),
            description: "Block all shell exec".into(),
            enabled: true,
            action: RuleAction::Block,
            conditions: RuleConditions {
                tools: vec!["shell_exec".into()],
                ..Default::default()
            },
        }];

        let engine = PolicyEngine::new(rules, Decision::Allow, 80.0, true);
        let req = make_request("shell_exec", r#"{"cmd": "ls"}"#);
        let result = engine.evaluate(&req, &low_risk());

        // Dry-run: decision is Allow but reason says it would have blocked
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.reason.contains("DRY-RUN"));
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match("file_*", "file_read"));
        assert!(glob_match("*exec", "shell_exec"));
        assert!(glob_match("*http*", "http_request"));
        assert!(!glob_match("file_read", "shell_exec"));
    }
}
