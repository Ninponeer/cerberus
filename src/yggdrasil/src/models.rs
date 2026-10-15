//! Domain entity models and schemas for Yggdrasil knowledge graph

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Device entity in the living topology
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceEntity {
    pub id: String,
    pub hostname: String,
    pub ips: Vec<String>,
    pub os: String,
    pub role: String,
    pub tier: u32,
    pub trust_score: f32,
    pub first_seen_ns: i64,
    pub last_seen_ns: i64,
}

/// User identity entity
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserEntity {
    pub id: String,
    pub upn: String,
    pub risk_score: f32,
    pub department: Option<String>,
    pub roles: Vec<String>,
    pub last_seen_ns: i64,
}

/// Process execution entity
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessEntity {
    pub id: String,
    pub device_id: String,
    pub pid: u32,
    pub ppid: u32,
    pub exe_path: String,
    pub exe_hash_sha256: String,
    pub cmdline: String,
    pub user_id: Option<String>,
    pub first_seen_ns: i64,
}

/// Enum wrapper for polymorphically storing entities
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "entity_type", content = "data")]
pub enum EntityRecord {
    Device(DeviceEntity),
    User(UserEntity),
    Process(ProcessEntity),
}

/// Behavioral baseline profile for an entity
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehavioralBaseline {
    pub entity_id: String,
    pub entity_type: String,
    pub sample_count: u64,
    pub feature_means: HashMap<String, f32>,
    pub feature_stds: HashMap<String, f32>,
    pub updated_at_ns: i64,
}

impl BehavioralBaseline {
    pub fn new(entity_id: String, entity_type: String) -> Self {
        Self {
            entity_id,
            entity_type,
            sample_count: 0,
            feature_means: HashMap::new(),
            feature_stds: HashMap::new(),
            updated_at_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
        }
    }
}

/// Trust score record for a swarm peer
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustScoreRecord {
    pub agent_id: String,
    pub score: f32,
    pub observation_count: u64,
    pub accurate_verdict_count: u64,
    pub calibrated_at_ns: i64,
}
