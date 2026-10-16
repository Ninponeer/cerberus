//! Orthrus Containment Action Trait and Concrete Implementations
//!
//! Provides the core abstraction for active containment actions against
//! anomalous edge nodes, rogue AI botnets, and compromised processes.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use cerberus_core::action::{
    ActionDirective, ActionResult, ActionStatus, EvidencePreservation, RollbackInfo, TargetSelector,
};
use cerberus_core::verdict::ActionType;
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

use crate::platform::PlatformAdapter;

/// Core trait representing an active containment or mitigation action
#[async_trait]
pub trait ContainmentAction: Send + Sync {
    /// Return the semantic ActionType
    fn action_type(&self) -> ActionType;

    /// Return the TargetSelector describing what is being targeted
    fn target(&self) -> &TargetSelector;

    /// Urgency score (0.0 to 1.0)
    fn urgency(&self) -> f32;

    /// Directive ID associated with this action
    fn directive_id(&self) -> &str;

    /// Execute the action against the underlying platform adapter
    async fn execute(&self, platform: &dyn PlatformAdapter) -> Result<ActionResult>;

    /// Roll back this action using the stored rollback record
    async fn rollback(&self, rollback_info: &RollbackInfo, platform: &dyn PlatformAdapter) -> Result<()>;

    /// Dry run / simulate action execution without modifying host state
    fn dry_run(&self) -> Result<String>;
}

/// Network Quarantine Action: Isolates a compromised host or IP address from network egress/ingress
#[derive(Debug, Clone)]
pub struct NetworkQuarantineAction {
    pub directive_id: String,
    pub target: TargetSelector,
    pub ip_address: String,
    pub drop_all: bool,
    pub urgency: f32,
}

impl NetworkQuarantineAction {
    pub fn new(directive_id: String, target: TargetSelector, ip_address: String, drop_all: bool, urgency: f32) -> Self {
        Self {
            directive_id,
            target,
            ip_address,
            drop_all,
            urgency,
        }
    }
}

#[async_trait]
impl ContainmentAction for NetworkQuarantineAction {
    fn action_type(&self) -> ActionType {
        ActionType::NetworkIsolate
    }

    fn target(&self) -> &TargetSelector {
        &self.target
    }

    fn urgency(&self) -> f32 {
        self.urgency
    }

    fn directive_id(&self) -> &str {
        &self.directive_id
    }

    async fn execute(&self, platform: &dyn PlatformAdapter) -> Result<ActionResult> {
        let started_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let rule_handle = platform.isolate_ip(&self.ip_address, self.drop_all).await?;
        let completed_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);

        let mut rollback_params = HashMap::new();
        rollback_params.insert("rule_handle".to_string(), rule_handle.clone());
        rollback_params.insert("ip".to_string(), self.ip_address.clone());

        let rollback = RollbackInfo {
            reversible: true,
            rollback_procedure: "UNQUARANTINE_IP".to_string(),
            rollback_parameters: rollback_params,
            expires_ns: completed_ns + (3600 * 1_000_000_000), // Default 1 hour TTL
        };

        let preservation = EvidencePreservation {
            memory_captured: false,
            disk_imaged: false,
            netflow_captured: true,
            logs_preserved: true,
            storage_location: "/DataVolume/cerberus_vault".to_string(),
        };

        Ok(ActionResult {
            result_id: Uuid::now_v7().to_string(),
            directive_id: self.directive_id.clone(),
            started_ns,
            completed_ns,
            status: ActionStatus::Succeeded,
            details: format!("Isolated IP {} via handle {}", self.ip_address, rule_handle),
            preservation,
            rollback,
            signature: Vec::new(),
        })
    }

    async fn rollback(&self, rollback_info: &RollbackInfo, platform: &dyn PlatformAdapter) -> Result<()> {
        let rule_handle = rollback_info
            .rollback_parameters
            .get("rule_handle")
            .ok_or_else(|| anyhow!("Missing rule_handle in rollback parameters"))?;
        platform.remove_isolation(rule_handle).await
    }

    fn dry_run(&self) -> Result<String> {
        Ok(format!(
            "[DRY_RUN] Would isolate IP {} (drop_all: {}) with urgency {:.2}",
            self.ip_address, self.drop_all, self.urgency
        ))
    }
}

/// Process Kill Action: Terminates a rogue botnet or model runtime process by PID
#[derive(Debug, Clone)]
pub struct ProcessKillAction {
    pub directive_id: String,
    pub target: TargetSelector,
    pub pid: u32,
    pub process_name: Option<String>,
    pub graceful: bool,
    pub urgency: f32,
}

impl ProcessKillAction {
    pub fn new(
        directive_id: String,
        target: TargetSelector,
        pid: u32,
        process_name: Option<String>,
        graceful: bool,
        urgency: f32,
    ) -> Self {
        Self {
            directive_id,
            target,
            pid,
            process_name,
            graceful,
            urgency,
        }
    }
}

#[async_trait]
impl ContainmentAction for ProcessKillAction {
    fn action_type(&self) -> ActionType {
        ActionType::NetworkIsolate
    }

    fn target(&self) -> &TargetSelector {
        &self.target
    }

    fn urgency(&self) -> f32 {
        self.urgency
    }

    fn directive_id(&self) -> &str {
        &self.directive_id
    }

    async fn execute(&self, platform: &dyn PlatformAdapter) -> Result<ActionResult> {
        let started_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        platform.kill_process(self.pid, self.graceful).await?;
        let completed_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);

        let mut rollback_params = HashMap::new();
        rollback_params.insert("pid".to_string(), self.pid.to_string());
        if let Some(ref name) = self.process_name {
            rollback_params.insert("process_name".to_string(), name.clone());
        }

        let rollback = RollbackInfo {
            reversible: false, // Process termination cannot be directly undone
            rollback_procedure: "PROCESS_TERMINATED".to_string(),
            rollback_parameters: rollback_params,
            expires_ns: 0,
        };

        let preservation = EvidencePreservation {
            memory_captured: true,
            disk_imaged: false,
            netflow_captured: false,
            logs_preserved: true,
            storage_location: "/DataVolume/cerberus_vault".to_string(),
        };

        Ok(ActionResult {
            result_id: Uuid::now_v7().to_string(),
            directive_id: self.directive_id.clone(),
            started_ns,
            completed_ns,
            status: ActionStatus::Succeeded,
            details: format!("Terminated process PID {} (graceful: {})", self.pid, self.graceful),
            preservation,
            rollback,
            signature: Vec::new(),
        })
    }

    async fn rollback(&self, _rollback_info: &RollbackInfo, _platform: &dyn PlatformAdapter) -> Result<()> {
        // Non-reversible action: process cannot be unkilled
        Ok(())
    }

    fn dry_run(&self) -> Result<String> {
        Ok(format!(
            "[DRY_RUN] Would terminate PID {} (name: {:?}, graceful: {}) with urgency {:.2}",
            self.pid, self.process_name, self.graceful, self.urgency
        ))
    }
}

/// Traffic Redirect Action: Diverts suspicious traffic from a target to a forensic honeypot / PCAP capture ring
#[derive(Debug, Clone)]
pub struct TrafficRedirectAction {
    pub directive_id: String,
    pub target: TargetSelector,
    pub source_ip: String,
    pub destination_ip: String,
    pub sink_port: u16,
    pub urgency: f32,
}

impl TrafficRedirectAction {
    pub fn new(
        directive_id: String,
        target: TargetSelector,
        source_ip: String,
        destination_ip: String,
        sink_port: u16,
        urgency: f32,
    ) -> Self {
        Self {
            directive_id,
            target,
            source_ip,
            destination_ip,
            sink_port,
            urgency,
        }
    }
}

#[async_trait]
impl ContainmentAction for TrafficRedirectAction {
    fn action_type(&self) -> ActionType {
        ActionType::TrafficRedirect
    }

    fn target(&self) -> &TargetSelector {
        &self.target
    }

    fn urgency(&self) -> f32 {
        self.urgency
    }

    fn directive_id(&self) -> &str {
        &self.directive_id
    }

    async fn execute(&self, platform: &dyn PlatformAdapter) -> Result<ActionResult> {
        let started_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let route_handle = platform
            .redirect_traffic(&self.source_ip, &self.destination_ip, self.sink_port)
            .await?;
        let completed_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);

        let mut rollback_params = HashMap::new();
        rollback_params.insert("route_handle".to_string(), route_handle.clone());
        rollback_params.insert("source_ip".to_string(), self.source_ip.clone());

        let rollback = RollbackInfo {
            reversible: true,
            rollback_procedure: "RESTORE_TRAFFIC_ROUTE".to_string(),
            rollback_parameters: rollback_params,
            expires_ns: completed_ns + (7200 * 1_000_000_000), // Default 2 hours TTL
        };

        let preservation = EvidencePreservation {
            memory_captured: false,
            disk_imaged: false,
            netflow_captured: true,
            logs_preserved: true,
            storage_location: "/DataVolume/cerberus_vault".to_string(),
        };

        Ok(ActionResult {
            result_id: Uuid::now_v7().to_string(),
            directive_id: self.directive_id.clone(),
            started_ns,
            completed_ns,
            status: ActionStatus::Succeeded,
            details: format!(
                "Redirected traffic from {} to {}:{} via handle {}",
                self.source_ip, self.destination_ip, self.sink_port, route_handle
            ),
            preservation,
            rollback,
            signature: Vec::new(),
        })
    }

    async fn rollback(&self, rollback_info: &RollbackInfo, platform: &dyn PlatformAdapter) -> Result<()> {
        let route_handle = rollback_info
            .rollback_parameters
            .get("route_handle")
            .ok_or_else(|| anyhow!("Missing route_handle in rollback parameters"))?;
        platform.remove_redirection(route_handle).await
    }

    fn dry_run(&self) -> Result<String> {
        Ok(format!(
            "[DRY_RUN] Would redirect traffic from {} to {}:{} with urgency {:.2}",
            self.source_ip, self.destination_ip, self.sink_port, self.urgency
        ))
    }
}

/// Credential Suspend Action: Locks an account or revokes active authentication tokens
#[derive(Debug, Clone)]
pub struct CredentialSuspendAction {
    pub directive_id: String,
    pub target: TargetSelector,
    pub user_id: String,
    pub urgency: f32,
}

impl CredentialSuspendAction {
    pub fn new(directive_id: String, target: TargetSelector, user_id: String, urgency: f32) -> Self {
        Self {
            directive_id,
            target,
            user_id,
            urgency,
        }
    }
}

#[async_trait]
impl ContainmentAction for CredentialSuspendAction {
    fn action_type(&self) -> ActionType {
        ActionType::CredentialSuspend
    }

    fn target(&self) -> &TargetSelector {
        &self.target
    }

    fn urgency(&self) -> f32 {
        self.urgency
    }

    fn directive_id(&self) -> &str {
        &self.directive_id
    }

    async fn execute(&self, platform: &dyn PlatformAdapter) -> Result<ActionResult> {
        let started_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        platform.suspend_credential(&self.user_id).await?;
        let completed_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);

        let mut rollback_params = HashMap::new();
        rollback_params.insert("user_id".to_string(), self.user_id.clone());

        let rollback = RollbackInfo {
            reversible: true,
            rollback_procedure: "RESTORE_CREDENTIAL".to_string(),
            rollback_parameters: rollback_params,
            expires_ns: completed_ns + (86400 * 1_000_000_000), // Default 24 hours TTL
        };

        let preservation = EvidencePreservation {
            memory_captured: false,
            disk_imaged: false,
            netflow_captured: false,
            logs_preserved: true,
            storage_location: "/DataVolume/cerberus_vault".to_string(),
        };

        Ok(ActionResult {
            result_id: Uuid::now_v7().to_string(),
            directive_id: self.directive_id.clone(),
            started_ns,
            completed_ns,
            status: ActionStatus::Succeeded,
            details: format!("Suspended credentials for user {}", self.user_id),
            preservation,
            rollback,
            signature: Vec::new(),
        })
    }

    async fn rollback(&self, rollback_info: &RollbackInfo, platform: &dyn PlatformAdapter) -> Result<()> {
        let user_id = rollback_info
            .rollback_parameters
            .get("user_id")
            .ok_or_else(|| anyhow!("Missing user_id in rollback parameters"))?;
        platform.restore_credential(user_id).await
    }

    fn dry_run(&self) -> Result<String> {
        Ok(format!(
            "[DRY_RUN] Would suspend credentials for user {} with urgency {:.2}",
            self.user_id, self.urgency
        ))
    }
}

/// Forensic Capture Action: Captures memory snapshot, disk image, or PCAP ring buffer into vault
#[derive(Debug, Clone)]
pub struct ForensicCaptureAction {
    pub directive_id: String,
    pub target: TargetSelector,
    pub target_identifier: String,
    pub vault_path: String,
    pub urgency: f32,
}

impl ForensicCaptureAction {
    pub fn new(
        directive_id: String,
        target: TargetSelector,
        target_identifier: String,
        vault_path: String,
        urgency: f32,
    ) -> Self {
        Self {
            directive_id,
            target,
            target_identifier,
            vault_path,
            urgency,
        }
    }
}

#[async_trait]
impl ContainmentAction for ForensicCaptureAction {
    fn action_type(&self) -> ActionType {
        ActionType::ForensicCapture
    }

    fn target(&self) -> &TargetSelector {
        &self.target
    }

    fn urgency(&self) -> f32 {
        self.urgency
    }

    fn directive_id(&self) -> &str {
        &self.directive_id
    }

    async fn execute(&self, platform: &dyn PlatformAdapter) -> Result<ActionResult> {
        let started_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let preservation = platform
            .capture_evidence(&self.target_identifier, &self.vault_path)
            .await?;
        let completed_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);

        let rollback = RollbackInfo {
            reversible: false,
            rollback_procedure: "EVIDENCE_PRESERVED".to_string(),
            rollback_parameters: HashMap::new(),
            expires_ns: 0,
        };

        Ok(ActionResult {
            result_id: Uuid::now_v7().to_string(),
            directive_id: self.directive_id.clone(),
            started_ns,
            completed_ns,
            status: ActionStatus::Succeeded,
            details: format!(
                "Captured forensic evidence for {} stored at {}",
                self.target_identifier, preservation.storage_location
            ),
            preservation,
            rollback,
            signature: Vec::new(),
        })
    }

    async fn rollback(&self, _rollback_info: &RollbackInfo, _platform: &dyn PlatformAdapter) -> Result<()> {
        // Preserved evidence is immutable and not rolled back
        Ok(())
    }

    fn dry_run(&self) -> Result<String> {
        Ok(format!(
            "[DRY_RUN] Would capture forensic evidence for {} to {} with urgency {:.2}",
            self.target_identifier, self.vault_path, self.urgency
        ))
    }
}

/// Factory function to instantiate a concrete ContainmentAction from an ActionDirective
pub fn action_from_directive(directive: &ActionDirective) -> Result<Box<dyn ContainmentAction>> {
    match directive.action_type {
        ActionType::NetworkIsolate | ActionType::Microsegment => {
            if let Some(ref pid_str) = directive.target.process_id {
                let pid: u32 = pid_str
                    .parse()
                    .map_err(|e| anyhow!("Invalid process PID '{}': {}", pid_str, e))?;
                let proc_name = directive.parameters.get("process_name").cloned();
                Ok(Box::new(ProcessKillAction::new(
                    directive.directive_id.clone(),
                    directive.target.clone(),
                    pid,
                    proc_name,
                    false,
                    directive.urgency,
                )))
            } else {
                let ip = directive
                    .parameters
                    .get("target_ip")
                    .cloned()
                    .or_else(|| directive.target.device_id.clone())
                    .or_else(|| {
                        directive
                            .target
                            .network
                            .as_ref()
                            .and_then(|n| n.cidr.clone())
                    })
                    .ok_or_else(|| anyhow!("Network isolation requires target_ip, device_id, or CIDR"))?;
                Ok(Box::new(NetworkQuarantineAction::new(
                    directive.directive_id.clone(),
                    directive.target.clone(),
                    ip,
                    true,
                    directive.urgency,
                )))
            }
        }
        ActionType::TrafficRedirect => {
            let source_ip = directive
                .parameters
                .get("source_ip")
                .or_else(|| directive.parameters.get("target_ip"))
                .ok_or_else(|| anyhow!("Traffic redirect requires source_ip or target_ip"))?
                .clone();
            let dest_ip = directive
                .parameters
                .get("destination_ip")
                .cloned()
                .unwrap_or_else(|| "127.0.0.1".to_string());
            let sink_port: u16 = directive
                .parameters
                .get("sink_port")
                .and_then(|p| p.parse().ok())
                .unwrap_or(8080);
            Ok(Box::new(TrafficRedirectAction::new(
                directive.directive_id.clone(),
                directive.target.clone(),
                source_ip,
                dest_ip,
                sink_port,
                directive.urgency,
            )))
        }
        ActionType::CredentialSuspend => {
            let user_id = directive
                .target
                .user_id
                .clone()
                .or_else(|| directive.parameters.get("target_user").cloned())
                .ok_or_else(|| anyhow!("Credential suspension requires target user_id or target_user parameter"))?;
            Ok(Box::new(CredentialSuspendAction::new(
                directive.directive_id.clone(),
                directive.target.clone(),
                user_id,
                directive.urgency,
            )))
        }
        ActionType::ForensicCapture => {
            let target_id = directive
                .target
                .device_id
                .clone()
                .or_else(|| directive.parameters.get("target_host").cloned())
                .unwrap_or_else(|| "unknown_target".to_string());
            let vault_path = directive
                .parameters
                .get("vault_path")
                .cloned()
                .unwrap_or_else(|| "/DataVolume/cerberus_vault".to_string());
            Ok(Box::new(ForensicCaptureAction::new(
                directive.directive_id.clone(),
                directive.target.clone(),
                target_id,
                vault_path,
                directive.urgency,
            )))
        }
        ActionType::DecoyActivate | ActionType::EnhancedMonitoring => {
            // Enhanced monitoring maps to non-blocking forensic capture
            let target_id = directive
                .target
                .device_id
                .clone()
                .unwrap_or_else(|| "monitoring_target".to_string());
            Ok(Box::new(ForensicCaptureAction::new(
                directive.directive_id.clone(),
                directive.target.clone(),
                target_id,
                "/DataVolume/cerberus_vault".to_string(),
                directive.urgency,
            )))
        }
    }
}
