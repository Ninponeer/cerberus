//! Observation types (Fenrir output)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Observation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationType {
    Anomaly,
    BehavioralDeviation,
    IndicatorMatch,
    AttackChainLink,
}

/// Evidence attached to an observation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub fields: HashMap<String, String>,
    pub raw_events: Vec<crate::telemetry::TelemetryEvent>,
    pub feature_vector: HashMap<String, f32>,
}

/// Fenrir observation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub observation_id: String,
    pub agent_id: String,
    pub timestamp_ns: i64,
    pub obs_type: ObservationType,
    pub confidence: f32,
    pub evidence: Evidence,
    pub yggdrasil_refs: Vec<String>,
    pub signature: Vec<u8>,
}

impl Observation {
    pub fn new(
        agent_id: impl Into<String>,
        obs_type: ObservationType,
        confidence: f32,
        evidence: Evidence,
    ) -> Self {
        Self {
            observation_id: uuid::Uuid::now_v7().to_string(),
            agent_id: agent_id.into(),
            timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
            obs_type,
            confidence: confidence.clamp(0.0, 1.0),
            evidence,
            yggdrasil_refs: Vec::new(),
            signature: Vec::new(),
        }
    }
}