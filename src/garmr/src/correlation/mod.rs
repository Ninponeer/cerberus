//! Correlation engine for temporal clustering and entity resolution

pub mod cluster;

use crate::config::CorrelationConfig;
use anyhow::{anyhow, Result};
use cerberus_core::observation::Observation;
pub use cluster::ObservationCluster;
use std::collections::{HashMap, HashSet};

/// Core correlation engine managing sliding-window observation clusters
pub struct CorrelationEngine {
    config: CorrelationConfig,
    active_clusters: HashMap<String, ObservationCluster>,
    entity_to_correlation: HashMap<String, String>,
    seen_observations: HashSet<String>,
}

impl CorrelationEngine {
    pub fn new(config: CorrelationConfig) -> Self {
        Self {
            config,
            active_clusters: HashMap::new(),
            entity_to_correlation: HashMap::new(),
            seen_observations: HashSet::new(),
        }
    }

    /// Ingest a new observation, performing replay validation, entity resolution, and temporal clustering
    pub fn ingest(&mut self, obs: Observation) -> Result<String> {
        // 1. Replay check
        if self.seen_observations.contains(&obs.observation_id) {
            return Err(anyhow!("Replay detected for observation ID {}", obs.observation_id));
        }
        self.seen_observations.insert(obs.observation_id.clone());

        // 2. Extract entities
        let entities = Self::extract_entities(&obs);
        if entities.is_empty() {
            return Err(anyhow!("Observation {} contains no resolvable entities", obs.observation_id));
        }

        // 3. Find existing correlation if any entity is already tracked
        let mut target_correlation_id = None;
        for entity in &entities {
            if let Some(corr_id) = self.entity_to_correlation.get(entity) {
                target_correlation_id = Some(corr_id.clone());
                break;
            }
        }

        match target_correlation_id {
            Some(corr_id) => {
                if let Some(cluster) = self.active_clusters.get_mut(&corr_id) {
                    cluster.add_observation(obs, &entities);
                    // Map any newly observed entities to this cluster
                    for entity in entities {
                        self.entity_to_correlation.insert(entity, corr_id.clone());
                    }
                    Ok(corr_id)
                } else {
                    // Cluster was removed or matured, create fresh cluster
                    let primary = entities[0].clone();
                    let cluster = ObservationCluster::new(primary.clone(), obs);
                    let new_id = cluster.correlation_id.clone();
                    for entity in entities {
                        self.entity_to_correlation.insert(entity, new_id.clone());
                    }
                    self.active_clusters.insert(new_id.clone(), cluster);
                    Ok(new_id)
                }
            }
            None => {
                let primary = entities[0].clone();
                let cluster = ObservationCluster::new(primary.clone(), obs);
                let new_id = cluster.correlation_id.clone();
                for entity in entities {
                    self.entity_to_correlation.insert(entity, new_id.clone());
                }
                self.active_clusters.insert(new_id.clone(), cluster);
                Ok(new_id)
            }
        }
    }

    /// Extract searchable entity identifiers from an observation record
    pub fn extract_entities(obs: &Observation) -> Vec<String> {
        let mut entities = Vec::new();

        // Host / Endpoint entity
        if !obs.agent_id.is_empty() {
            entities.push(format!("agent:{}", obs.agent_id));
        }

        // Context fields
        if let Some(user) = obs.evidence.fields.get("user") {
            if !user.is_empty() {
                entities.push(format!("user:{}", user.to_lowercase()));
            }
        }
        if let Some(host) = obs.evidence.fields.get("host").or_else(|| obs.evidence.fields.get("hostname")) {
            if !host.is_empty() {
                entities.push(format!("host:{}", host.to_lowercase()));
            }
        }
        if let Some(src_ip) = obs.evidence.fields.get("src_ip").or_else(|| obs.evidence.fields.get("source_ip")) {
            if !src_ip.is_empty() {
                entities.push(format!("ip:{}", src_ip));
            }
        }
        if let Some(dst_ip) = obs.evidence.fields.get("dst_ip").or_else(|| obs.evidence.fields.get("dest_ip")) {
            if !dst_ip.is_empty() {
                entities.push(format!("ip:{}", dst_ip));
            }
        }
        if let Some(process) = obs.evidence.fields.get("process").or_else(|| obs.evidence.fields.get("image_path")) {
            if !process.is_empty() {
                entities.push(format!("proc:{}", process.to_lowercase()));
            }
        }
        if let Some(sha256) = obs.evidence.fields.get("sha256") {
            if !sha256.is_empty() {
                entities.push(format!("sha256:{}", sha256.to_lowercase()));
            }
        }

        entities.dedup();
        entities
    }

    /// Drain clusters that have matured.
    /// A cluster is mature if:
    /// - It has been idle longer than the temporal sliding window (must be evaluated, even with partial observations)
    /// - It has hit max allowable cluster lifespan (prevents infinite memory creep)
    /// - It has met minimum observations and has 3+ distinct agents agreeing
    pub fn drain_mature_clusters(&mut self, current_ns: i64) -> Vec<ObservationCluster> {
        let mut mature_ids = Vec::new();

        for (id, cluster) in &self.active_clusters {
            let idle_timed_out = cluster.is_idle_timeout(current_ns, self.config.temporal_window_sec);
            let max_span_hit = cluster.is_max_span_reached(self.config.max_cluster_span_sec);
            let eager_quorum_ready = cluster.observation_count() >= self.config.min_observations_per_cluster
                && cluster.distinct_agent_count() >= 3;

            if idle_timed_out || max_span_hit || eager_quorum_ready {
                mature_ids.push(id.clone());
            }
        }

        let mut ready = Vec::new();
        for id in mature_ids {
            if let Some(cluster) = self.active_clusters.remove(&id) {
                // Clean up entity lookups
                self.entity_to_correlation.retain(|_, v| v != &id);
                ready.push(cluster);
            }
        }

        ready
    }

    /// Get reference to active cluster by correlation ID
    pub fn get_cluster(&self, correlation_id: &str) -> Option<&ObservationCluster> {
        self.active_clusters.get(correlation_id)
    }

    /// Count of active clusters
    pub fn active_cluster_count(&self) -> usize {
        self.active_clusters.len()
    }
}
