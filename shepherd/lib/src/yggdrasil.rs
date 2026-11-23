//! Yggdrasil knowledge graph client for Shepherd.
//!
//! Reads Yggdrasil data from a file-based JSON store (compatible with
//! Yggdrasil's entity/verdict/observation data model). Designed to be
//! upgraded to a gRPC client or direct RocksDB reader when the Yggdrasil
//! service is operational.
//!
//! Data files live in `<store_path>/` with subdirectories:
//! - `verdicts/` - `ver-<id>.json`
//! - `observations/` - `obs-<id>.json`
//! - `entities/` - `device-<id>.json`, `user-<id>.json`, `process-<id>.json`
//! - `trust_scores/` - `<agent_id>.json`
//! - `baselines/` - `<entity_id>.json`

use crate::error::{Result, ShepherdError};
use cerberus_core::observation::Observation;
use cerberus_core::verdict::Verdict;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Summary of a verdict for operator display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictSummary {
    pub verdict_id: String,
    pub timestamp_ns: i64,
    pub correlation_id: String,
    pub confidence: f32,
    pub classification: String,
    pub threat_class: String,
    pub participating_nodes: Vec<String>,
    pub evidence_trail: Vec<String>,
    pub recommended_actions: Vec<String>,
    pub rationale: String,
    pub garmr_instance: String,
}

/// Summary of an observation for operator display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationSummary {
    pub observation_id: String,
    pub agent_id: String,
    pub timestamp_ns: i64,
    pub obs_type: String,
    pub confidence: f32,
    pub classification: String,
    pub yggdrasil_refs: Vec<String>,
}

/// Summary of a device entity for operator display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSummary {
    pub id: String,
    pub hostname: String,
    pub ips: Vec<String>,
    pub os: String,
    pub role: String,
    pub tier: u32,
    pub trust_score: f32,
    pub status: String,
}

/// Summary of a trust score for operator display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScoreSummary {
    pub agent_id: String,
    pub score: f32,
    pub observation_count: u64,
    pub accurate_verdict_count: u64,
}

/// File-based Yggdrasil store client for Shepherd.
pub struct YggdrasilClient {
    store_path: PathBuf,
}

impl YggdrasilClient {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let store_path = path.as_ref().to_path_buf();
        for sub in ["verdicts", "observations", "entities", "trust_scores", "baselines"] {
            let dir = store_path.join(sub);
            if !dir.exists() {
                std::fs::create_dir_all(&dir)
                    .map_err(|e| ShepherdError::Yggdrasil(format!("Failed to create store dir {sub}: {e}")))?;
            }
        }
        Ok(Self { store_path })
    }

    #[cfg(test)]
    pub fn open_ephemeral() -> Result<(Self, tempfile::TempDir)> {
        let temp_dir = tempfile::tempdir()
            .map_err(|e| ShepherdError::Yggdrasil(format!("Failed to create tempdir: {e}")))?;
        let client = Self::open(temp_dir.path())?;
        Ok((client, temp_dir))
    }

    fn verdict_path(&self, verdict_id: &str) -> PathBuf {
        self.store_path.join("verdicts").join(format!("ver-{verdict_id}.json"))
    }

    fn observation_path(&self, obs_id: &str) -> PathBuf {
        self.store_path.join("observations").join(format!("obs-{obs_id}.json"))
    }

    fn entity_path(&self, entity_id: &str) -> PathBuf {
        self.store_path.join("entities").join(format!("{entity_id}.json"))
    }

    fn trust_score_path(&self, agent_id: &str) -> PathBuf {
        self.store_path.join("trust_scores").join(format!("{agent_id}.json"))
    }

    pub fn record_verdict(&self, verdict: &Verdict) -> Result<()> {
        let path = self.verdict_path(&verdict.verdict_id);
        let json = serde_json::to_string_pretty(verdict)
            .map_err(|e| ShepherdError::Serialization(e))?;
        std::fs::write(path, json)
            .map_err(|e| ShepherdError::Yggdrasil(format!("Failed to write verdict: {e}")))?;
        Ok(())
    }

    pub fn record_observation(&self, obs: &Observation) -> Result<()> {
        let path = self.observation_path(&obs.observation_id);
        let json = serde_json::to_string_pretty(obs)
            .map_err(|e| ShepherdError::Serialization(e))?;
        std::fs::write(path, json)
            .map_err(|e| ShepherdError::Yggdrasil(format!("Failed to write observation: {e}")))?;
        Ok(())
    }

    pub fn record_trust_score(&self, agent_id: &str, score: f32) -> Result<()> {
        let path = self.trust_score_path(agent_id);
        let json = serde_json::to_string_pretty(&serde_json::json!({
            "agent_id": agent_id,
            "score": score,
            "observation_count": 0u64,
            "accurate_verdict_count": 0u64,
        }))
        .map_err(|e| ShepherdError::Serialization(e))?;
        std::fs::write(path, json)
            .map_err(|e| ShepherdError::Yggdrasil(format!("Failed to write trust score: {e}")))?;
        Ok(())
    }

    pub fn get_verdict(&self, verdict_id: &str) -> Result<Option<Verdict>> {
        let path = self.verdict_path(verdict_id);
        if !path.exists() {
            return Ok(None);
        }
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| ShepherdError::Yggdrasil(format!("Failed to read verdict: {e}")))?;
        let verdict: Verdict = serde_json::from_str(&contents)
            .map_err(|e| ShepherdError::Serialization(e))?;
        Ok(Some(verdict))
    }

    pub fn list_verdicts(&self, limit: usize) -> Result<Vec<VerdictSummary>> {
        let mut results = Vec::new();
        let verdicts_dir = self.store_path.join("verdicts");
        if !verdicts_dir.exists() {
            return Ok(results);
        }
        for entry in std::fs::read_dir(&verdicts_dir)
            .map_err(|e| ShepherdError::Yggdrasil(format!("Failed to read verdicts dir: {e}")))? {
            let entry = entry.map_err(|e| ShepherdError::Yggdrasil(format!("Failed to read dir entry: {e}")))?;
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "json") {
                let contents = std::fs::read_to_string(&path)
                    .map_err(|e| ShepherdError::Yggdrasil(format!("Failed to read verdict file: {e}")))?;
                let verdict: Verdict = serde_json::from_str(&contents)
                    .map_err(|e| ShepherdError::Serialization(e))?;
                results.push(self.verdict_to_summary(&verdict));
                if results.len() >= limit { break; }
            }
        }
        results.sort_by(|a, b| b.timestamp_ns.cmp(&a.timestamp_ns));
        Ok(results)
    }

    pub fn get_verdicts_for_correlation(&self, correlation_id: &str) -> Result<Vec<Verdict>> {
        let all = self.list_verdicts(1000)?;
        let mut results = Vec::new();
        for summary in &all {
            if let Some(verdict) = self.get_verdict(&summary.verdict_id)? {
                if verdict.correlation_id == correlation_id {
                    results.push(verdict);
                }
            }
        }
        Ok(results)
    }

    pub fn get_observation(&self, obs_id: &str) -> Result<Option<Observation>> {
        let path = self.observation_path(obs_id);
        if !path.exists() {
            return Ok(None);
        }
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| ShepherdError::Yggdrasil(format!("Failed to read observation: {e}")))?;
        let obs: Observation = serde_json::from_str(&contents)
            .map_err(|e| ShepherdError::Serialization(e))?;
        Ok(Some(obs))
    }

    pub fn get_observations_for_entity(&self, entity_prefix: &str, limit: usize) -> Result<Vec<Observation>> {
        let mut results = Vec::new();
        let obs_dir = self.store_path.join("observations");
        if !obs_dir.exists() {
            return Ok(results);
        }
        for entry in std::fs::read_dir(&obs_dir)
            .map_err(|e| ShepherdError::Yggdrasil(format!("Failed to read observations dir: {e}")))? {
            let entry = entry.map_err(|e| ShepherdError::Yggdrasil(format!("Failed to read dir entry: {e}")))?;
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "json") {
                let contents = std::fs::read_to_string(&path)
                    .map_err(|e| ShepherdError::Yggdrasil(format!("Failed to read observation file: {e}")))?;
                let obs: Observation = serde_json::from_str(&contents)
                    .map_err(|e| ShepherdError::Serialization(e))?;
                if obs.agent_id == entity_prefix || obs.evidence.fields.values().any(|v| v == entity_prefix) {
                    results.push(obs);
                    if results.len() >= limit { break; }
                }
            }
        }
        Ok(results)
    }

    pub fn get_device(&self, device_id: &str) -> Result<Option<DeviceSummary>> {
        let path = self.entity_path(device_id);
        if !path.exists() {
            return Ok(None);
        }
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| ShepherdError::Yggdrasil(format!("Failed to read entity: {e}")))?;
        let data: serde_json::Value = serde_json::from_str(&contents)
            .map_err(|e| ShepherdError::Serialization(e))?;
        if data.get("entity_type").and_then(|v| v.as_str()) != Some("Device") {
            return Ok(None);
        }
        let d = data.get("data").ok_or_else(|| {
            ShepherdError::Validation("Missing device data".to_string())
        })?;
        Ok(Some(DeviceSummary {
            id: d.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            hostname: d.get("hostname").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            ips: d.get("ips").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(),
            os: d.get("os").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            role: d.get("role").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            tier: d.get("tier").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            trust_score: d.get("trust_score").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32,
            status: "ACTIVE".to_string(),
        }))
    }

    pub fn get_all_trust_scores(&self) -> Result<Vec<TrustScoreSummary>> {
        let mut results = Vec::new();
        let ts_dir = self.store_path.join("trust_scores");
        if !ts_dir.exists() {
            return Ok(results);
        }
        for entry in std::fs::read_dir(&ts_dir)
            .map_err(|e| ShepherdError::Yggdrasil(format!("Failed to read trust scores dir: {e}")))? {
            let entry = entry.map_err(|e| ShepherdError::Yggdrasil(format!("Failed to read dir entry: {e}")))?;
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "json") {
                let contents = std::fs::read_to_string(&path)
                    .map_err(|e| ShepherdError::Yggdrasil(format!("Failed to read trust score: {e}")))?;
                let data: serde_json::Value = serde_json::from_str(&contents)
                    .map_err(|e| ShepherdError::Serialization(e))?;
                results.push(TrustScoreSummary {
                    agent_id: data.get("agent_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    score: data.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32,
                    observation_count: data.get("observation_count").and_then(|v| v.as_u64()).unwrap_or(0),
                    accurate_verdict_count: data.get("accurate_verdict_count").and_then(|v| v.as_u64()).unwrap_or(0),
                });
            }
        }
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        Ok(results)
    }

    pub fn get_trust_score(&self, agent_id: &str) -> Result<Option<f32>> {
        let path = self.trust_score_path(agent_id);
        if !path.exists() {
            return Ok(None);
        }
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| ShepherdError::Yggdrasil(format!("Failed to read trust score: {e}")))?;
        let data: serde_json::Value = serde_json::from_str(&contents)
            .map_err(|e| ShepherdError::Serialization(e))?;
        Ok(Some(data.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32))
    }

    pub fn get_baseline(&self, _entity_id: &str) -> Result<Option<serde_json::Value>> {
        Ok(None)
    }

    fn verdict_to_summary(&self, v: &Verdict) -> VerdictSummary {
        VerdictSummary {
            verdict_id: v.verdict_id.clone(),
            timestamp_ns: v.timestamp_ns,
            correlation_id: v.correlation_id.clone(),
            confidence: v.confidence,
            classification: format!("{:?}", v.classification),
            threat_class: v.threat_class.clone(),
            participating_nodes: v.participating_nodes.clone(),
            evidence_trail: v.evidence_trail.clone(),
            recommended_actions: v.recommended_actions.iter().map(|a| format!("{:?}", a.action_type)).collect(),
            rationale: v.rationale.clone(),
            garmr_instance: v.garmr_instance.clone(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.store_path
    }
}
