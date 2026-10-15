//! Correlation cluster representation and temporal tracking

use cerberus_core::observation::Observation;
use std::collections::HashSet;

/// Represents a correlated cluster of observations bound to common entities
#[derive(Debug, Clone)]
pub struct ObservationCluster {
    pub correlation_id: String,
    pub primary_entity: String,
    pub associated_entities: HashSet<String>,
    pub observations: Vec<Observation>,
    pub participating_nodes: HashSet<String>,
    pub first_seen_ns: i64,
    pub last_seen_ns: i64,
}

impl ObservationCluster {
    pub fn new(primary_entity: String, initial_obs: Observation) -> Self {
        let mut participating_nodes = HashSet::new();
        participating_nodes.insert(initial_obs.agent_id.clone());

        let ts = initial_obs.timestamp_ns;
        let correlation_id = uuid::Uuid::now_v7().to_string();

        Self {
            correlation_id,
            primary_entity,
            associated_entities: HashSet::new(),
            observations: vec![initial_obs],
            participating_nodes,
            first_seen_ns: ts,
            last_seen_ns: ts,
        }
    }

    /// Add an observation to the cluster, expanding entity links and temporal boundary
    pub fn add_observation(&mut self, obs: Observation, related_entities: &[String]) {
        self.participating_nodes.insert(obs.agent_id.clone());
        if obs.timestamp_ns < self.first_seen_ns {
            self.first_seen_ns = obs.timestamp_ns;
        }
        if obs.timestamp_ns > self.last_seen_ns {
            self.last_seen_ns = obs.timestamp_ns;
        }
        for entity in related_entities {
            if entity != &self.primary_entity {
                self.associated_entities.insert(entity.clone());
            }
        }
        self.observations.push(obs);
    }

    /// Duration spanned by the cluster in seconds
    pub fn span_seconds(&self) -> u64 {
        if self.last_seen_ns <= self.first_seen_ns {
            0
        } else {
            ((self.last_seen_ns - self.first_seen_ns) / 1_000_000_000) as u64
        }
    }

    /// Check if the cluster has been idle longer than the temporal sliding window
    pub fn is_idle_timeout(&self, current_ns: i64, window_sec: u64) -> bool {
        let window_ns = (window_sec as i64) * 1_000_000_000;
        current_ns - self.last_seen_ns >= window_ns
    }

    /// Check if the cluster has reached maximum temporal lifespan
    pub fn is_max_span_reached(&self, max_span_sec: u64) -> bool {
        self.span_seconds() >= max_span_sec
    }

    /// Number of distinct reporting agents in this cluster
    pub fn distinct_agent_count(&self) -> usize {
        self.participating_nodes.len()
    }

    /// Total count of observations clustered
    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }
}
