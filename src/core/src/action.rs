//! Action types (Orthrus input/output)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Action execution status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ActionStatus {
    Pending = 0,
    Executing = 1,
    Succeeded = 2,
    Failed = 3,
    Partial = 4,
    RolledBack = 5,
}

/// Target selector for actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetSelector {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkSelector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_tag: Option<String>,
}

/// Network target selector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSelector {
    pub cidr: Option<String>,
    pub vlan: Option<i32>,
    pub switch_id: Option<String>,
}

/// Action directive from Garmr or Shepherd
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionDirective {
    pub directive_id: String,
    pub verdict_id: Option<String>,
    pub timestamp_ns: i64,
    pub action_type: crate::verdict::ActionType,
    pub target: TargetSelector,
    pub parameters: HashMap<String, String>,
    pub urgency: f32,
    pub requires_confirmation: bool,
    pub rationale: String,
    pub garmr_signature: Vec<u8>,
    pub shepherd_signature: Vec<u8>,
}

/// Evidence preservation info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePreservation {
    pub memory_captured: bool,
    pub disk_imaged: bool,
    pub netflow_captured: bool,
    pub logs_preserved: bool,
    pub storage_location: String,
}

/// Rollback information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackInfo {
    pub reversible: bool,
    pub rollback_procedure: String,
    pub rollback_parameters: HashMap<String, String>,
    pub expires_ns: i64,
}

/// Action execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub result_id: String,
    pub directive_id: String,
    pub started_ns: i64,
    pub completed_ns: i64,
    pub status: ActionStatus,
    pub details: String,
    pub preservation: EvidencePreservation,
    pub rollback: RollbackInfo,
    pub signature: Vec<u8>,
}