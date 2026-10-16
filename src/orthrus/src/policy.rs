//! Orthrus Policy Engine, Operator Approval Gates, and Rollback Registry
//!
//! Enforces threshold-based autonomous execution vs human-in-the-loop
//! cryptographic approval token gates, IP/PID whitelists, and containment rollbacks.

use anyhow::{anyhow, Result};
use cerberus_core::action::{ActionDirective, ActionResult, RollbackInfo, TargetSelector};
use cerberus_core::crypto::VerifyingKeyWrapper;
use cerberus_core::verdict::ActionType;
use chrono::Utc;
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::info;
use uuid::Uuid;

/// Policy configuration controlling autonomous vs operator-approved containment
#[derive(Debug, Clone)]
pub struct ContainmentPolicy {
    /// Minimum confidence threshold for autonomous tripwire execution (0.0 to 1.0)
    pub autonomous_confidence_threshold: f32,
    /// Minimum action urgency required for autonomous execution
    pub autonomous_urgency_threshold: f32,
    /// Force operator confirmation regardless of confidence
    pub force_human_approval: bool,
    /// Operator public key used to verify approval tokens
    pub operator_verifying_key: Option<VerifyingKeyWrapper>,
    /// Protected IP addresses that cannot be quarantined
    pub whitelisted_ips: HashSet<String>,
    /// Protected process PIDs that cannot be killed
    pub protected_pids: HashSet<u32>,
    /// Maximum quarantine duration before expiration (seconds)
    pub default_quarantine_secs: u64,
}

impl Default for ContainmentPolicy {
    fn default() -> Self {
        let mut whitelisted_ips = HashSet::new();
        whitelisted_ips.insert("127.0.0.1".to_string());
        whitelisted_ips.insert("::1".to_string());
        whitelisted_ips.insert("0.0.0.0".to_string());

        let mut protected_pids = HashSet::new();
        protected_pids.insert(1); // init / systemd
        protected_pids.insert(std::process::id()); // Self PID

        Self {
            autonomous_confidence_threshold: 0.85,
            autonomous_urgency_threshold: 0.80,
            force_human_approval: false,
            operator_verifying_key: None,
            whitelisted_ips,
            protected_pids,
            default_quarantine_secs: 3600,
        }
    }
}

impl ContainmentPolicy {
    /// Determine whether an action directive qualifies for autonomous execution
    pub fn is_autonomous_allowed(&self, directive: &ActionDirective, confidence: f32) -> bool {
        if self.force_human_approval || directive.requires_confirmation {
            return false;
        }

        confidence >= self.autonomous_confidence_threshold && directive.urgency >= self.autonomous_urgency_threshold
    }

    /// Validate target against safety whitelists (prevent killing self or isolating loopback)
    pub fn validate_target_safety(&self, target: &TargetSelector, parameters: &HashMap<String, String>) -> Result<()> {
        if let Some(ref pid_str) = target.process_id {
            if let Ok(pid) = pid_str.parse::<u32>() {
                if self.protected_pids.contains(&pid) {
                    return Err(anyhow!("Target PID {} is protected by safety policy whitelist", pid));
                }
            }
        }

        let ip_candidates = [
            parameters.get("target_ip").cloned(),
            target.device_id.clone(),
            target.network.as_ref().and_then(|n| n.cidr.clone()),
        ];

        for ip_opt in ip_candidates.into_iter().flatten() {
            if self.whitelisted_ips.contains(&ip_opt) {
                return Err(anyhow!("Target IP {} is whitelisted against containment", ip_opt));
            }
        }

        Ok(())
    }
}

/// Cryptographically signed approval token provided by a human operator (Shepherd CLI)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalToken {
    pub token_id: String,
    pub directive_id: String,
    pub operator_id: String,
    pub granted_at_ns: i64,
    pub expires_at_ns: i64,
    pub signature: Vec<u8>,
}

impl ApprovalToken {
    /// Canonical payload for signing / verification
    pub fn canonical_payload(
        token_id: &str,
        directive_id: &str,
        operator_id: &str,
        granted_at_ns: i64,
        expires_at_ns: i64,
    ) -> Vec<u8> {
        format!(
            "CERBERUS_APPROVAL_V1:{}:{}:{}:{}:{}",
            token_id, directive_id, operator_id, granted_at_ns, expires_at_ns
        )
        .into_bytes()
    }

    /// Verify operator cryptographic signature
    pub fn verify(&self, operator_key: &VerifyingKeyWrapper) -> Result<()> {
        if self.signature.len() != 64 {
            return Err(anyhow!("Invalid operator approval signature length"));
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature);
        let sig = Signature::from_bytes(&sig_bytes);

        let canonical = Self::canonical_payload(
            &self.token_id,
            &self.directive_id,
            &self.operator_id,
            self.granted_at_ns,
            self.expires_at_ns,
        );

        operator_key
            .verify(&canonical, &sig)
            .map_err(|e| anyhow!("Approval token signature verification failed: {}", e))
    }

    /// Check if the approval token has expired
    pub fn is_expired(&self, current_ns: i64) -> bool {
        current_ns > self.expires_at_ns
    }
}

/// Active containment tracking record for rollback orchestration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackRecord {
    pub record_id: String,
    pub directive_id: String,
    pub result_id: String,
    pub action_type: ActionType,
    pub rollback_info: RollbackInfo,
    pub created_at_ns: i64,
    pub executed_rollback: bool,
}

/// In-memory manager tracking active containments and facilitating safe rollbacks
#[derive(Debug, Default)]
pub struct RollbackManager {
    records: HashMap<String, RollbackRecord>, // directive_id -> RollbackRecord
}

impl RollbackManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a newly executed action result
    pub fn register(&mut self, result: &ActionResult, action_type: ActionType) {
        if !result.rollback.reversible {
            return;
        }

        let record = RollbackRecord {
            record_id: Uuid::now_v7().to_string(),
            directive_id: result.directive_id.clone(),
            result_id: result.result_id.clone(),
            action_type,
            rollback_info: result.rollback.clone(),
            created_at_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0),
            executed_rollback: false,
        };

        info!(
            "RollbackManager: Registered reversible action for directive {} (procedure: {})",
            result.directive_id, result.rollback.rollback_procedure
        );
        self.records.insert(result.directive_id.clone(), record);
    }

    /// Query rollback record by directive_id
    pub fn get(&self, directive_id: &str) -> Option<&RollbackRecord> {
        self.records.get(directive_id)
    }

    /// Mark a record as rolled back
    pub fn mark_rolled_back(&mut self, directive_id: &str) -> Result<RollbackInfo> {
        let record = self
            .records
            .get_mut(directive_id)
            .ok_or_else(|| anyhow!("No active containment record found for directive {}", directive_id))?;

        if record.executed_rollback {
            return Err(anyhow!("Directive {} has already been rolled back", directive_id));
        }

        record.executed_rollback = true;
        Ok(record.rollback_info.clone())
    }

    /// Query all active containments currently registered
    pub fn list_active(&self) -> Vec<RollbackRecord> {
        self.records
            .values()
            .filter(|r| !r.executed_rollback)
            .cloned()
            .collect()
    }

    /// Find all records whose TTL has expired
    pub fn find_expired(&self, current_ns: i64) -> Vec<RollbackRecord> {
        self.records
            .values()
            .filter(|r| !r.executed_rollback && r.rollback_info.expires_ns > 0 && current_ns >= r.rollback_info.expires_ns)
            .cloned()
            .collect()
    }
}
