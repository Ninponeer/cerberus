//! Embedded RocksDB storage engine for Yggdrasil knowledge graph and event state

use crate::models::{BehavioralBaseline, EntityRecord, TrustScoreRecord};
use anyhow::{anyhow, Result};
use cerberus_core::observation::Observation;
use cerberus_core::verdict::Verdict;
use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, IteratorMode, Options, DB};
use std::collections::HashMap;
use std::path::Path;

pub const CF_ENTITIES: &str = "entities";
pub const CF_OBSERVATIONS: &str = "observations";
pub const CF_VERDICTS: &str = "verdicts";
pub const CF_TRUST_SCORES: &str = "trust_scores";
pub const CF_BASELINES: &str = "baselines";

/// Local high-performance RocksDB-backed state store for Yggdrasil
pub struct RocksYggdrasilStore {
    db: DB,
}

impl RocksYggdrasilStore {
    /// Open or create a RocksDB store with all Yggdrasil column families
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        let cf_names = [
            "default",
            CF_ENTITIES,
            CF_OBSERVATIONS,
            CF_VERDICTS,
            CF_TRUST_SCORES,
            CF_BASELINES,
        ];

        let descriptors: Vec<ColumnFamilyDescriptor> = cf_names
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, Options::default()))
            .collect();

        let db = DB::open_cf_descriptors(&db_opts, path, descriptors)
            .map_err(|e| anyhow!("Failed to open RocksDB store: {}", e))?;

        Ok(Self { db })
    }

    /// Open an ephemeral store backed by a temporary directory (for testing)
    pub fn open_ephemeral() -> Result<(Self, tempfile::TempDir)> {
        let temp_dir = tempfile::tempdir().map_err(|e| anyhow!("Failed to create tempdir: {}", e))?;
        let store = Self::open(temp_dir.path())?;
        Ok((store, temp_dir))
    }

    // ========================================================================
    // Entity Operations (CF_ENTITIES)
    // ========================================================================

    pub fn put_entity(&self, key: &str, entity: &EntityRecord) -> Result<()> {
        let cf = self.cf_handle(CF_ENTITIES)?;
        let bytes = serde_json::to_vec(entity)?;
        self.db.put_cf(cf, key.as_bytes(), bytes)?;
        Ok(())
    }

    pub fn get_entity(&self, key: &str) -> Result<Option<EntityRecord>> {
        let cf = self.cf_handle(CF_ENTITIES)?;
        match self.db.get_cf(cf, key.as_bytes())? {
            Some(bytes) => {
                let entity = serde_json::from_slice(&bytes)?;
                Ok(Some(entity))
            }
            None => Ok(None),
        }
    }

    // ========================================================================
    // Observation Operations (CF_OBSERVATIONS)
    // ========================================================================

    pub fn record_observation(&self, obs: &Observation) -> Result<()> {
        let cf = self.cf_handle(CF_OBSERVATIONS)?;
        let bytes = serde_json::to_vec(obs)?;

        // Primary key: obs:<observation_id>
        let primary_key = format!("obs:{}", obs.observation_id);
        self.db.put_cf(cf, primary_key.as_bytes(), &bytes)?;

        // Secondary index by agent/entity: idx:entity:<agent_id>:<timestamp>:<obs_id>
        let agent_idx = format!("idx:entity:{}:{}:{}", obs.agent_id, obs.timestamp_ns, obs.observation_id);
        self.db.put_cf(cf, agent_idx.as_bytes(), obs.observation_id.as_bytes())?;

        // Contextual entity indices (e.g. host, user)
        for (k, v) in &obs.evidence.fields {
            if ["user", "host", "hostname", "src_ip"].contains(&k.as_str()) {
                let entity_idx = format!("idx:entity:{}:{}:{}:{}", k, v.to_lowercase(), obs.timestamp_ns, obs.observation_id);
                self.db.put_cf(cf, entity_idx.as_bytes(), obs.observation_id.as_bytes())?;
            }
        }

        Ok(())
    }

    pub fn get_observation(&self, obs_id: &str) -> Result<Option<Observation>> {
        let cf = self.cf_handle(CF_OBSERVATIONS)?;
        let key = format!("obs:{}", obs_id);
        match self.db.get_cf(cf, key.as_bytes())? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn get_observations_for_entity(&self, entity_prefix: &str, limit: usize) -> Result<Vec<Observation>> {
        let cf = self.cf_handle(CF_OBSERVATIONS)?;
        let prefix = format!("idx:entity:{}:", entity_prefix);
        let prefix_bytes = prefix.as_bytes();

        let mut results = Vec::new();
        let iter = self.db.iterator_cf(cf, IteratorMode::From(prefix_bytes, rocksdb::Direction::Forward));

        for item in iter {
            let (k, v) = item?;
            if !k.starts_with(prefix_bytes) {
                break;
            }
            if let Ok(obs_id) = std::str::from_utf8(&v) {
                if let Some(obs) = self.get_observation(obs_id)? {
                    results.push(obs);
                    if results.len() >= limit {
                        break;
                    }
                }
            }
        }

        Ok(results)
    }

    // ========================================================================
    // Verdict Operations (CF_VERDICTS)
    // ========================================================================

    pub fn record_verdict(&self, verdict: &Verdict) -> Result<()> {
        let cf = self.cf_handle(CF_VERDICTS)?;
        let bytes = serde_json::to_vec(verdict)?;

        // Primary key: ver:<verdict_id>
        let primary_key = format!("ver:{}", verdict.verdict_id);
        self.db.put_cf(cf, primary_key.as_bytes(), &bytes)?;

        // Secondary index by correlation: idx:corr:<correlation_id>:<verdict_id>
        let corr_idx = format!("idx:corr:{}:{}", verdict.correlation_id, verdict.verdict_id);
        self.db.put_cf(cf, corr_idx.as_bytes(), verdict.verdict_id.as_bytes())?;

        Ok(())
    }

    pub fn get_verdict(&self, verdict_id: &str) -> Result<Option<Verdict>> {
        let cf = self.cf_handle(CF_VERDICTS)?;
        let key = format!("ver:{}", verdict_id);
        match self.db.get_cf(cf, key.as_bytes())? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn get_verdicts_for_correlation(&self, correlation_id: &str) -> Result<Vec<Verdict>> {
        let cf = self.cf_handle(CF_VERDICTS)?;
        let prefix = format!("idx:corr:{}:", correlation_id);
        let prefix_bytes = prefix.as_bytes();

        let mut results = Vec::new();
        let iter = self.db.iterator_cf(cf, IteratorMode::From(prefix_bytes, rocksdb::Direction::Forward));

        for item in iter {
            let (k, v) = item?;
            if !k.starts_with(prefix_bytes) {
                break;
            }
            if let Ok(ver_id) = std::str::from_utf8(&v) {
                if let Some(verdict) = self.get_verdict(ver_id)? {
                    results.push(verdict);
                }
            }
        }

        Ok(results)
    }

    // ========================================================================
    // Trust Scores Operations (CF_TRUST_SCORES)
    // ========================================================================

    pub fn update_trust_score(&self, record: &TrustScoreRecord) -> Result<()> {
        let cf = self.cf_handle(CF_TRUST_SCORES)?;
        let bytes = serde_json::to_vec(record)?;
        self.db.put_cf(cf, record.agent_id.as_bytes(), bytes)?;
        Ok(())
    }

    pub fn get_trust_score(&self, agent_id: &str) -> Result<Option<f32>> {
        let cf = self.cf_handle(CF_TRUST_SCORES)?;
        match self.db.get_cf(cf, agent_id.as_bytes())? {
            Some(bytes) => {
                let record: TrustScoreRecord = serde_json::from_slice(&bytes)?;
                Ok(Some(record.score))
            }
            None => Ok(None),
        }
    }

    /// Extract all active trust scores for hydrating Garmr's consensus cache
    pub fn get_all_trust_scores(&self) -> Result<HashMap<String, f32>> {
        let cf = self.cf_handle(CF_TRUST_SCORES)?;
        let mut scores = HashMap::new();

        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        for item in iter {
            let (k, v) = item?;
            if let Ok(agent_id) = std::str::from_utf8(&k) {
                if let Ok(record) = serde_json::from_slice::<TrustScoreRecord>(&v) {
                    scores.insert(agent_id.to_string(), record.score);
                }
            }
        }

        Ok(scores)
    }

    // ========================================================================
    // Behavioral Baseline Operations (CF_BASELINES)
    // ========================================================================

    pub fn put_baseline(&self, baseline: &BehavioralBaseline) -> Result<()> {
        let cf = self.cf_handle(CF_BASELINES)?;
        let bytes = serde_json::to_vec(baseline)?;
        self.db.put_cf(cf, baseline.entity_id.as_bytes(), bytes)?;
        Ok(())
    }

    pub fn get_baseline(&self, entity_id: &str) -> Result<Option<BehavioralBaseline>> {
        let cf = self.cf_handle(CF_BASELINES)?;
        match self.db.get_cf(cf, entity_id.as_bytes())? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    // ========================================================================
    // Internal Helpers
    // ========================================================================

    fn cf_handle(&self, name: &str) -> Result<&ColumnFamily> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| anyhow!("Column family '{}' not found in store", name))
    }
}
