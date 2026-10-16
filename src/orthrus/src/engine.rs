//! Orthrus Active Containment Engine
//!
//! Orchestrates safety checks, operator approval verification, containment action dispatch,
//! cryptographic result signing, and rollback lifecycle management.

use anyhow::{anyhow, Result};
use cerberus_core::action::{ActionDirective, ActionResult, ActionStatus, EvidencePreservation, RollbackInfo};
use cerberus_core::crypto::{SigningKeyWrapper, VerifyingKeyWrapper};
use std::sync::{Arc, RwLock};
use tracing::{error, info, warn};

use crate::action::action_from_directive;
use crate::platform::PlatformAdapter;
use crate::policy::{ApprovalToken, ContainmentPolicy, RollbackManager, RollbackRecord};

/// Primary orchestrator for active host containment, mitigation, and recovery
pub struct OrthrusEngine {
    instance_id: String,
    signing_key: SigningKeyWrapper,
    platform: Arc<dyn PlatformAdapter>,
    policy: ContainmentPolicy,
    rollback_manager: Arc<RwLock<RollbackManager>>,
}

impl OrthrusEngine {
    /// Create a new Orthrus containment engine
    pub fn new(
        instance_id: String,
        signing_key: SigningKeyWrapper,
        platform: Arc<dyn PlatformAdapter>,
        policy: ContainmentPolicy,
    ) -> Self {
        Self {
            instance_id,
            signing_key,
            platform,
            policy,
            rollback_manager: Arc::new(RwLock::new(RollbackManager::new())),
        }
    }

    /// Return the public verifying key of this Orthrus instance
    pub fn verifying_key(&self) -> VerifyingKeyWrapper {
        VerifyingKeyWrapper(self.signing_key.verifying_key())
    }

    /// Access active policy configuration
    pub fn policy(&self) -> &ContainmentPolicy {
        &self.policy
    }

    /// Dry run / simulate an action directive without modifying host state
    pub fn dry_run(&self, directive: &ActionDirective) -> Result<String> {
        self.policy
            .validate_target_safety(&directive.target, &directive.parameters)?;
        let action = action_from_directive(directive)?;
        action.dry_run()
    }

    /// Evaluate policy gates and execute a containment directive
    pub async fn execute_directive(
        &self,
        directive: &ActionDirective,
        verdict_confidence: f32,
        approval: Option<ApprovalToken>,
    ) -> Result<ActionResult> {
        info!(
            "OrthrusEngine [{}]: Evaluating containment directive {} (action: {:?}, urgency: {:.2}, confidence: {:.2})",
            self.instance_id, directive.directive_id, directive.action_type, directive.urgency, verdict_confidence
        );

        // 1. Safety Whitelist Validation (prevent self-kill or loopback isolation)
        self.policy
            .validate_target_safety(&directive.target, &directive.parameters)?;

        // 2. Policy & Approval Gate
        let autonomous_permitted = self.policy.is_autonomous_allowed(directive, verdict_confidence);

        if !autonomous_permitted {
            let token = approval.ok_or_else(|| {
                anyhow!(
                    "Containment directive {} requires operator approval (confidence: {:.2}, threshold: {:.2})",
                    directive.directive_id,
                    verdict_confidence,
                    self.policy.autonomous_confidence_threshold
                )
            })?;

            if token.directive_id != directive.directive_id {
                return Err(anyhow!(
                    "Approval token directive mismatch: expected {}, got {}",
                    directive.directive_id,
                    token.directive_id
                ));
            }

            let current_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
            if token.is_expired(current_ns) {
                return Err(anyhow!("Approval token {} has expired", token.token_id));
            }

            if let Some(ref operator_key) = self.policy.operator_verifying_key {
                token.verify(operator_key)?;
                info!(
                    "OrthrusEngine: Operator {} cryptographically verified for directive {}",
                    token.operator_id, directive.directive_id
                );
            } else {
                warn!("OrthrusEngine: Operator verification key not set; accepting unsigned/unchecked approval token");
            }
        } else {
            info!(
                "OrthrusEngine: Autonomous tripwire containment approved for directive {}",
                directive.directive_id
            );
        }

        // 3. Build concrete ContainmentAction
        let action = action_from_directive(directive)?;

        // 4. Execute action against PlatformAdapter
        let mut result = match action.execute(&*self.platform).await {
            Ok(res) => res,
            Err(e) => {
                error!("OrthrusEngine: Containment execution failed for directive {}: {}", directive.directive_id, e);
                let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
                return Ok(ActionResult {
                    result_id: uuid::Uuid::now_v7().to_string(),
                    directive_id: directive.directive_id.clone(),
                    started_ns: now_ns,
                    completed_ns: now_ns,
                    status: ActionStatus::Failed,
                    details: format!("Execution failed: {}", e),
                    preservation: EvidencePreservation {
                        memory_captured: false,
                        disk_imaged: false,
                        netflow_captured: false,
                        logs_preserved: true,
                        storage_location: String::new(),
                    },
                    rollback: RollbackInfo {
                        reversible: false,
                        rollback_procedure: String::new(),
                        rollback_parameters: std::collections::HashMap::new(),
                        expires_ns: 0,
                    },
                    signature: Vec::new(),
                });
            }
        };

        // 5. Cryptographically sign the ActionResult
        let canonical_bytes = format!(
            "CERBERUS_ORTHRUS_RESULT_V1:{}:{}:{}:{:?}:{}",
            result.result_id, result.directive_id, result.completed_ns, result.status, result.details
        )
        .into_bytes();

        let sig = self.signing_key.sign(&canonical_bytes);
        result.signature = sig.to_bytes().to_vec();

        // 6. Register in RollbackManager if reversible
        if result.status == ActionStatus::Succeeded && result.rollback.reversible {
            let mut rollback_mgr = self.rollback_manager.write().unwrap();
            rollback_mgr.register(&result, directive.action_type);
        }

        info!(
            "OrthrusEngine: Completed containment for directive {} with status {:?}",
            directive.directive_id, result.status
        );

        Ok(result)
    }

    /// Roll back an active containment by directive ID
    pub async fn rollback_directive(&self, directive_id: &str) -> Result<()> {
        info!("OrthrusEngine: Triggering rollback for directive {}", directive_id);

        let rollback_info = {
            let mut rollback_mgr = self.rollback_manager.write().unwrap();
            rollback_mgr.mark_rolled_back(directive_id)?
        };

        match rollback_info.rollback_procedure.as_str() {
            "UNQUARANTINE_IP" => {
                let rule_handle = rollback_info
                    .rollback_parameters
                    .get("rule_handle")
                    .ok_or_else(|| anyhow!("Missing rule_handle in rollback parameters"))?;
                self.platform.remove_isolation(rule_handle).await?;
            }
            "RESTORE_TRAFFIC_ROUTE" => {
                let route_handle = rollback_info
                    .rollback_parameters
                    .get("route_handle")
                    .ok_or_else(|| anyhow!("Missing route_handle in rollback parameters"))?;
                self.platform.remove_redirection(route_handle).await?;
            }
            "RESTORE_CREDENTIAL" => {
                let user_id = rollback_info
                    .rollback_parameters
                    .get("user_id")
                    .ok_or_else(|| anyhow!("Missing user_id in rollback parameters"))?;
                self.platform.restore_credential(user_id).await?;
            }
            proc => {
                warn!("OrthrusEngine: Unknown or non-reversible rollback procedure: {}", proc);
            }
        }

        info!("OrthrusEngine: Successfully rolled back directive {}", directive_id);
        Ok(())
    }

    /// List all currently active containment records
    pub fn list_active_containments(&self) -> Vec<RollbackRecord> {
        let rollback_mgr = self.rollback_manager.read().unwrap();
        rollback_mgr.list_active()
    }

    /// Sweep and roll back all containments whose TTL has expired
    pub async fn sweep_expired_containments(&self, current_ns: i64) -> Result<usize> {
        let expired = {
            let rollback_mgr = self.rollback_manager.read().unwrap();
            rollback_mgr.find_expired(current_ns)
        };

        let mut count = 0;
        for record in expired {
            info!(
                "OrthrusEngine: Expired containment detected for directive {}; rolling back",
                record.directive_id
            );
            if let Err(e) = self.rollback_directive(&record.directive_id).await {
                error!("OrthrusEngine: Failed to roll back expired directive {}: {}", record.directive_id, e);
            } else {
                count += 1;
            }
        }

        Ok(count)
    }
}
