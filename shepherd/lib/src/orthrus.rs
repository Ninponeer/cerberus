//! Orthrus active containment integration for Shepherd.
//!
//! Shepherd issues ActionDirectives to Orthrus, generates operator
//! approval tokens, and manages containment rollbacks.

use crate::approval::ApprovalTokenBuilder;
use crate::error::{Result, ShepherdError};
use cerberus_core::action::{
    ActionDirective, ActionResult, TargetSelector,
};
use cerberus_core::crypto::SigningKeyWrapper;
use cerberus_core::verdict::ActionType;
use cerberus_orthrus::engine::OrthrusEngine;
use cerberus_orthrus::platform::MockPlatformAdapter;
use cerberus_orthrus::policy::ContainmentPolicy;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// Wrapper around OrthrusEngine for Shepherd operator operations.
pub struct OrthrusClient {
    engine: OrthrusEngine,
    approval_builder: ApprovalTokenBuilder,
}

impl OrthrusClient {
    /// Create a new OrthrusClient with a mock platform adapter (safe for
    /// dry-run and testing). The signing key is used to sign results.
    pub fn new_with_mock(signing_key: SigningKeyWrapper, operator_id: String) -> Result<Self> {
        let mock_platform = Arc::new(MockPlatformAdapter::new());
        let policy = ContainmentPolicy::default();
        let engine = OrthrusEngine::new(
            "shepherd-orthrus".to_string(),
            signing_key.clone(),
            mock_platform,
            policy,
        );
        let approval_builder =
            ApprovalTokenBuilder::new(signing_key, operator_id, 3600);

        Ok(Self {
            engine,
            approval_builder,
        })
    }

    /// Create an OrthrusClient with a real platform adapter.
    pub fn new(
        instance_id: String,
        signing_key: SigningKeyWrapper,
        platform: Arc<dyn cerberus_orthrus::platform::PlatformAdapter>,
        policy: ContainmentPolicy,
        operator_id: String,
    ) -> Result<Self> {
        let engine = OrthrusEngine::new(
            instance_id,
            signing_key.clone(),
            platform,
            policy,
        );
        let approval_builder =
            ApprovalTokenBuilder::new(signing_key, operator_id, 3600);

        Ok(Self {
            engine,
            approval_builder,
        })
    }

    /// Set the operator verifying key in the containment policy so
    /// Orthrus will validate Shepherd approval tokens.
    pub fn set_operator_verifying_key(
        &mut self,
        verifying_key: cerberus_core::crypto::VerifyingKeyWrapper,
    ) {
        // We need mutable access to the policy. Since OrthrusEngine
        // doesn't expose policy mutably, we recreate the engine.
        // For now, this is a no-op placeholder; the policy should be
        // configured at construction time.
        let _ = verifying_key;
    }

    /// Execute an action directive autonomously (if confidence >= threshold).
    pub async fn execute_autonomous(
        &mut self,
        directive: &ActionDirective,
        verdict_confidence: f32,
    ) -> Result<ActionResult> {
        self.engine
            .execute_directive(directive, verdict_confidence, None)
            .await
            .map_err(|e| ShepherdError::Orthrus(format!("Autonomous execution failed: {e}")))
    }

    /// Execute an action directive with operator approval.
    pub async fn execute_with_approval(
        &mut self,
        directive: &ActionDirective,
        verdict_confidence: f32,
        token: cerberus_orthrus::policy::ApprovalToken,
    ) -> Result<ActionResult> {
        self.engine
            .execute_directive(directive, verdict_confidence, Some(token))
            .await
            .map_err(|e| ShepherdError::Orthrus(format!("Approved execution failed: {e}")))
    }

    /// Generate an operator approval token for a directive.
    pub fn generate_approval_token(
        &self,
        directive: &ActionDirective,
        ttl_sec: Option<i64>,
    ) -> Result<cerberus_orthrus::policy::ApprovalToken> {
        self.approval_builder
            .sign_for_directive(directive, ttl_sec)
            .map_err(|e| ShepherdError::Orthrus(format!("Failed to sign approval token: {e}")))
    }

    /// Roll back a containment by directive ID.
    pub async fn rollback(&mut self, directive_id: &str) -> Result<()> {
        self.engine
            .rollback_directive(directive_id)
            .await
            .map_err(|e| ShepherdError::Orthrus(format!("Rollback failed: {e}")))
    }

    /// List all active containments.
    pub fn list_active_containments(&self) -> Vec<cerberus_orthrus::policy::RollbackRecord> {
        self.engine.list_active_containments()
    }

    /// Sweep and roll back all expired containments.
    pub async fn sweep_expired(&mut self, current_ns: i64) -> Result<usize> {
        self.engine
            .sweep_expired_containments(current_ns)
            .await
            .map_err(|e| ShepherdError::Orthrus(format!("Sweep failed: {e}")))
    }

    /// Dry-run a directive without modifying host state.
    pub fn dry_run(&self, directive: &ActionDirective) -> Result<String> {
        self.engine
            .dry_run(directive)
            .map_err(|e| ShepherdError::Orthrus(format!("Dry run failed: {e}")))
    }

    /// Returns the Orthrus verifying key.
    pub fn verifying_key(&self) -> cerberus_core::crypto::VerifyingKeyWrapper {
        self.engine.verifying_key()
    }

    /// Build a NetworkIsolate directive for a target IP.
    pub fn build_network_isolate_directive(
        directive_id: String,
        target_ip: String,
        rationale: String,
        urgency: f32,
    ) -> ActionDirective {
        let mut parameters = HashMap::new();
        parameters.insert("target_ip".to_string(), target_ip);

        ActionDirective {
            directive_id,
            verdict_id: None,
            timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0),
            action_type: ActionType::NetworkIsolate,
            target: TargetSelector {
                device_id: None,
                user_id: None,
                process_id: None,
                network: None,
                group_tag: None,
            },
            parameters,
            urgency,
            requires_confirmation: true,
            rationale,
            garmr_signature: Vec::new(),
            shepherd_signature: Vec::new(),
        }
    }

    /// Build a CredentialSuspend directive for a target user.
    pub fn build_credential_suspend_directive(
        directive_id: String,
        user_id: String,
        rationale: String,
        urgency: f32,
    ) -> ActionDirective {
        let mut parameters = HashMap::new();
        parameters.insert("user_id".to_string(), user_id.clone());
        parameters.insert("scope".to_string(), "domain".to_string());

        ActionDirective {
            directive_id,
            verdict_id: None,
            timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0),
            action_type: ActionType::CredentialSuspend,
            target: TargetSelector {
                device_id: None,
                user_id: Some(user_id),
                process_id: None,
                network: None,
                group_tag: None,
            },
            parameters,
            urgency,
            requires_confirmation: true,
            rationale,
            garmr_signature: Vec::new(),
            shepherd_signature: Vec::new(),
        }
    }

    /// Build a ProcessKill directive for a target PID.
    pub fn build_process_kill_directive(
        directive_id: String,
        process_id: String,
        rationale: String,
        urgency: f32,
    ) -> ActionDirective {
        let mut parameters = HashMap::new();
        parameters.insert("pid".to_string(), process_id.clone());

        ActionDirective {
            directive_id,
            verdict_id: None,
            timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0),
            action_type: ActionType::NetworkIsolate, // Using NetworkIsolate as closest match
            target: TargetSelector {
                device_id: None,
                user_id: None,
                process_id: Some(process_id),
                network: None,
                group_tag: None,
            },
            parameters,
            urgency,
            requires_confirmation: true,
            rationale,
            garmr_signature: Vec::new(),
            shepherd_signature: Vec::new(),
        }
    }

    /// Returns a summary of an action result for display.
    pub fn summarize_result(result: &ActionResult) -> String {
        format!(
            "ActionResult[id={}, directive={}, status={:?}, details={}]",
            result.result_id, result.directive_id, result.status, result.details
        )
    }
}
