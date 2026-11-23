//! Garmr consensus engine integration for Shepherd.
//!
//! Shepherd can instantiate a local GarmrEngine for dry-run verdict
//! evaluation and to verify verdict signatures against known
//! Garmr instance keys.

use crate::error::{Result, ShepherdError};
use cerberus_core::crypto::{SigningKeyWrapper, VerifyingKeyWrapper};
use cerberus_core::observation::Observation;
use cerberus_core::verdict::Verdict;
use cerberus_garmr::config::GarmrConfig;
use cerberus_garmr::engine::GarmrEngine;
use std::collections::HashMap;

/// Wrapper around GarmrEngine for Shepherd operations.
pub struct GarmrClient {
    engine: GarmrEngine,
    verifying_key: VerifyingKeyWrapper,
}

impl GarmrClient {
    /// Create a new GarmrClient with default config and a fresh signing key.
    pub fn new() -> Result<Self> {
        let config = GarmrConfig::default();
        let signing_key = SigningKeyWrapper::generate();
        let verifying_key = VerifyingKeyWrapper(signing_key.verifying_key());
        let engine = GarmrEngine::new(config, signing_key);

        Ok(Self {
            engine,
            verifying_key,
        })
    }

    /// Create a GarmrClient with a specific signing key (for matching
    /// a known Garmr instance's verification key).
    pub fn with_signing_key(signing_key: SigningKeyWrapper) -> Result<Self> {
        let config = GarmrConfig::default();
        let verifying_key = VerifyingKeyWrapper(signing_key.verifying_key());
        let engine = GarmrEngine::new(config, signing_key);

        Ok(Self {
            engine,
            verifying_key,
        })
    }

    /// Ingest an observation into the local Garmr engine.
    pub fn ingest_observation(&mut self, obs: Observation) -> Result<String> {
        self.engine
            .ingest_observation(obs)
            .map_err(|e| ShepherdError::Garmr(format!("Failed to ingest observation: {e}")))
    }

    /// Update the trust score for a participating node.
    pub fn update_node_trust(&mut self, agent_id: String, trust: f32) {
        self.engine.update_node_trust(agent_id, trust);
    }

    /// Evaluate mature observation clusters and emit verdicts.
    pub fn evaluate_mature_clusters(&mut self, current_ns: i64) -> Result<Vec<Verdict>> {
        Ok(self.engine.evaluate_mature_clusters(current_ns))
    }

    /// Verify a verdict's cryptographic signature.
    pub fn verify_verdict(&self, verdict: &Verdict) -> Result<()> {
        cerberus_garmr::verdict::VerdictBuilder::verify_verdict(verdict, &self.verifying_key)
            .map_err(|e| ShepherdError::Garmr(format!("Verdict verification failed: {e}")))
    }

    /// Returns the public verifying key of this Garmr instance.
    pub fn verifying_key(&self) -> &VerifyingKeyWrapper {
        &self.verifying_key
    }

    /// Returns the number of active correlation clusters.
    pub fn active_clusters(&self) -> usize {
        self.engine.active_clusters()
    }

    /// Returns the Garmr configuration.
    pub fn config(&self) -> &GarmrConfig {
        self.engine.config()
    }

    /// Build a target entity map from observations for surgical containment.
    pub fn extract_target_entities(
        observations: &[Observation],
    ) -> HashMap<String, String> {
        let mut entities = HashMap::new();
        for obs in observations {
            for (k, v) in &obs.evidence.fields {
                if ["user", "host", "src_ip", "dst_ip", "process"].contains(&k.as_str()) {
                    entities.insert(k.clone(), v.clone());
                }
            }
        }
        entities
    }
}

impl Default for GarmrClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default GarmrClient")
    }
}
