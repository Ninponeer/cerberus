//! Unified Garmr Sentinel Engine orchestrating correlation, consensus, and verdict emission

use crate::config::GarmrConfig;
use crate::consensus::{BayesianScorer, ConsensusEngine};
use crate::correlation::CorrelationEngine;
use crate::verdict::VerdictBuilder;
use anyhow::Result;
use cerberus_core::crypto::{SigningKeyWrapper, VerifyingKeyWrapper};
use cerberus_core::observation::Observation;
use cerberus_core::verdict::Verdict;
use std::collections::HashMap;

/// Primary orchestrator for the Garmr Sentinel
pub struct GarmrEngine {
    config: GarmrConfig,
    correlation: CorrelationEngine,
    consensus: ConsensusEngine,
    verdict_builder: VerdictBuilder,
}

impl GarmrEngine {
    pub fn new(config: GarmrConfig, signing_key: SigningKeyWrapper) -> Self {
        let correlation = CorrelationEngine::new(config.correlation.clone());
        let scorer = BayesianScorer::new(config.confidence.clone());
        let consensus = ConsensusEngine::new(config.consensus.clone(), scorer);
        let verdict_builder = VerdictBuilder::new(config.instance_id.clone(), signing_key);

        Self {
            config,
            correlation,
            consensus,
            verdict_builder,
        }
    }

    /// Ingest an incoming observation from a Fenrir node
    pub fn ingest_observation(&mut self, obs: Observation) -> Result<String> {
        self.correlation.ingest(obs)
    }

    /// Update the cached trust score for a node (from Yggdrasil or Raft reputation)
    pub fn update_node_trust(&mut self, agent_id: String, trust: f32) {
        self.consensus.set_node_trust(agent_id, trust);
    }

    /// Return the public verifying key of this Garmr instance
    pub fn verifying_key(&self) -> VerifyingKeyWrapper {
        self.verdict_builder.verifying_key()
    }

    /// Process and evaluate all mature observation clusters, emitting cryptographically signed verdicts
    pub fn evaluate_mature_clusters(&mut self, current_ns: i64) -> Vec<Verdict> {
        let mature_clusters = self.correlation.drain_mature_clusters(current_ns);
        let mut verdicts = Vec::new();

        for cluster in mature_clusters {
            let quorum_result = self.consensus.evaluate_cluster(&cluster);

            // Collect target entities across observations for surgical containment actions
            let mut target_entities = HashMap::new();
            for obs in &cluster.observations {
                for (k, v) in &obs.evidence.fields {
                    if ["user", "host", "src_ip", "dst_ip", "process"].contains(&k.as_str()) {
                        target_entities.insert(k.clone(), v.clone());
                    }
                }
            }
            if !target_entities.contains_key("agent") && !cluster.participating_nodes.is_empty() {
                if let Some(agent) = cluster.participating_nodes.iter().next() {
                    target_entities.insert("agent".to_string(), agent.clone());
                }
            }

            // Determine dominant threat class
            let threat_class = cluster
                .observations
                .first()
                .map(|o| format!("{:?}", o.obs_type))
                .unwrap_or_else(|| "Unknown".to_string());

            let evidence_trail: Vec<String> = cluster
                .observations
                .iter()
                .map(|o| o.observation_id.clone())
                .collect();

            let nodes: Vec<String> = cluster.participating_nodes.into_iter().collect();

            let verdict = self.verdict_builder.build(
                cluster.correlation_id,
                nodes,
                quorum_result.calculated_confidence,
                quorum_result.classification,
                threat_class,
                evidence_trail,
                quorum_result.rationale,
                &target_entities,
            );

            verdicts.push(verdict);
        }

        verdicts
    }

    /// Access active Garmr configuration
    pub fn config(&self) -> &GarmrConfig {
        &self.config
    }

    /// Number of clusters currently open in correlation window
    pub fn active_clusters(&self) -> usize {
        self.correlation.active_cluster_count()
    }
}
