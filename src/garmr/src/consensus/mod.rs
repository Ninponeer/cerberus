//! Consensus and quorum assembly module

pub mod bayesian;

use crate::config::ConsensusConfig;
use crate::correlation::ObservationCluster;
pub use bayesian::BayesianScorer;
use cerberus_core::verdict::Classification;
use std::collections::HashMap;

/// Consensus outcome evaluated across a cluster of observations
#[derive(Debug, Clone)]
pub struct QuorumResult {
    pub has_quorum: bool,
    pub distinct_agents: usize,
    pub weighted_agreement: f32,
    pub calculated_confidence: f32,
    pub classification: Classification,
    pub rationale: String,
}

/// Evaluates quorum assembly and consensus across nodes
pub struct ConsensusEngine {
    config: ConsensusConfig,
    scorer: BayesianScorer,
    node_trust_cache: HashMap<String, f32>,
}

impl ConsensusEngine {
    pub fn new(config: ConsensusConfig, scorer: BayesianScorer) -> Self {
        Self {
            config,
            scorer,
            node_trust_cache: HashMap::new(),
        }
    }

    /// Update cached trust score for a node (from Yggdrasil)
    pub fn set_node_trust(&mut self, agent_id: String, trust_score: f32) {
        self.node_trust_cache.insert(agent_id, trust_score.clamp(0.0, 1.0));
    }

    /// Get trust score for a node, defaulting to probation weight if uncalibrated
    pub fn get_node_trust(&self, agent_id: &str) -> f32 {
        self.node_trust_cache
            .get(agent_id)
            .copied()
            .unwrap_or(self.config.probation_weight)
    }

    /// Evaluate quorum and compute consensus verdict for an observation cluster
    pub fn evaluate_cluster(&self, cluster: &ObservationCluster) -> QuorumResult {
        let distinct_agents = cluster.distinct_agent_count();
        let (raw_confidence, raw_classification) =
            self.scorer.compute_posterior(&cluster.observations, &self.node_trust_cache);

        // Calculate weighted agreement among participating nodes
        let mut total_weight = 0.0f32;
        let mut agreeing_weight = 0.0f32;

        for agent_id in &cluster.participating_nodes {
            let trust = self.get_node_trust(agent_id);
            if trust >= self.config.min_trust_for_vote {
                total_weight += trust;
                // Since this node emitted an anomaly observation in the cluster, it contributes to agreement
                agreeing_weight += trust;
            }
        }

        let agreement_ratio = if total_weight > 0.0 {
            agreeing_weight / total_weight
        } else {
            0.0
        };

        let meets_min_agents = distinct_agents >= self.config.min_agents;
        let meets_agreement = agreement_ratio >= self.config.agreement_threshold;
        let has_quorum = meets_min_agents && meets_agreement;

        if !has_quorum {
            // Quorum failed: downgrade verdict to Suspicious or Benign and do not trigger aggressive Orthrus containment
            let capped_classification = match raw_classification {
                Classification::Confirmed | Classification::Probable => Classification::Suspicious,
                other => other,
            };
            let capped_confidence = raw_confidence.min(0.60);

            let rationale = format!(
                "Quorum not achieved: {}/{} distinct agents, {:.1}%/{:.1}% weighted agreement. Demoted to {:?}.",
                distinct_agents,
                self.config.min_agents,
                agreement_ratio * 100.0,
                self.config.agreement_threshold * 100.0,
                capped_classification
            );

            QuorumResult {
                has_quorum: false,
                distinct_agents,
                weighted_agreement: agreement_ratio,
                calculated_confidence: capped_confidence,
                classification: capped_classification,
                rationale,
            }
        } else {
            let rationale = format!(
                "Quorum confirmed: {} distinct agents, {:.1}% weighted agreement. Bayesian confidence: {:.2}.",
                distinct_agents,
                agreement_ratio * 100.0,
                raw_confidence
            );

            QuorumResult {
                has_quorum: true,
                distinct_agents,
                weighted_agreement: agreement_ratio,
                calculated_confidence: raw_confidence,
                classification: raw_classification,
                rationale,
            }
        }
    }
}
