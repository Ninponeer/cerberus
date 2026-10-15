//! Bayesian confidence scoring and probability calculation

use crate::config::ConfidenceConfig;
use cerberus_core::observation::Observation;
use cerberus_core::verdict::Classification;
use std::collections::HashMap;

/// Calculates Bayesian threat posterior probabilities from multi-node evidence
pub struct BayesianScorer {
    config: ConfidenceConfig,
}

impl BayesianScorer {
    pub fn new(config: ConfidenceConfig) -> Self {
        Self { config }
    }

    /// Calculate the posterior threat probability given clustered observations and agent trust scores
    pub fn compute_posterior(
        &self,
        observations: &[Observation],
        node_trust_scores: &HashMap<String, f32>,
    ) -> (f32, Classification) {
        if observations.is_empty() {
            return (0.0, Classification::Benign);
        }

        let prior = self.config.default_prior.clamp(0.01, 0.99);
        let mut prior_odds = prior / (1.0 - prior);

        for obs in observations {
            let trust = node_trust_scores
                .get(&obs.agent_id)
                .copied()
                .unwrap_or(0.1) // Default to probationary trust
                .clamp(0.0, 1.0);

            // Skip zero-trust or quarantined nodes
            if trust < 0.05 {
                continue;
            }

            // Determine technique weight multiplier
            let technique_key = match obs.obs_type {
                cerberus_core::observation::ObservationType::Anomaly => "binary_anomaly",
                cerberus_core::observation::ObservationType::BehavioralDeviation => "lateral_movement",
                cerberus_core::observation::ObservationType::IndicatorMatch => "credential_abuse",
                cerberus_core::observation::ObservationType::AttackChainLink => "injection",
            };

            let weight = self
                .config
                .technique_weights
                .get(technique_key)
                .copied()
                .unwrap_or(1.0);

            // Likelihood ratio Lambda = P(Evidence | Threat) / P(Evidence | Benign)
            // An observation with high confidence from a calibrated node generates significant evidential weight
            let signal_strength = obs.confidence.clamp(0.0, 1.0) * trust * weight;
            let likelihood_ratio = 1.0 + (signal_strength * 5.0);

            prior_odds *= likelihood_ratio;

            // Cap odds to prevent float overflow
            if prior_odds > 10000.0 {
                prior_odds = 10000.0;
            }
        }

        // Convert posterior odds back to normalized probability P = Odds / (1 + Odds)
        let posterior = prior_odds / (1.0 + prior_odds);
        let confidence = posterior.clamp(0.0, 1.0);

        let classification = self.classify(confidence);
        (confidence, classification)
    }

    /// Map a continuous confidence score [0.0, 1.0] to a verdict classification
    pub fn classify(&self, confidence: f32) -> Classification {
        let t = &self.config.thresholds;
        if confidence >= t.confirmed_lower {
            Classification::Confirmed
        } else if confidence >= t.probable_lower {
            Classification::Probable
        } else if confidence >= t.suspicious_lower {
            Classification::Suspicious
        } else {
            Classification::Benign
        }
    }
}
