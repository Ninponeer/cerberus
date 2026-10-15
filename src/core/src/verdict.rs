//! Verdict types (Garmr output)

use serde::{Deserialize, Serialize};

/// Verdict classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Classification {
    Benign = 0,
    Suspicious = 1,
    Probable = 2,
    Confirmed = 3,
}

/// Recommended action types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum ActionType {
    NetworkIsolate = 1,
    CredentialSuspend = 2,
    Microsegment = 3,
    DecoyActivate = 4,
    TrafficRedirect = 5,
    EnhancedMonitoring = 6,
    ForensicCapture = 7,
}

/// Recommended action from Garmr
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedAction {
    pub action_type: ActionType,
    pub parameters: std::collections::HashMap<String, String>,
    pub urgency: f32,
}

/// Garmr verdict record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub verdict_id: String,
    pub timestamp_ns: i64,
    pub correlation_id: String,
    pub participating_nodes: Vec<String>,
    pub confidence: f32,
    pub classification: Classification,
    pub threat_class: String,
    pub evidence_trail: Vec<String>,
    pub recommended_actions: Vec<RecommendedAction>,
    pub rationale: String,
    pub garmr_instance: String,
    pub signature: Vec<u8>,
}

impl Verdict {
    pub fn should_trigger_orthrus(&self, threshold: f32) -> bool {
        self.confidence >= threshold
    }
}