//! Configuration schema for Garmr consensus sentinel

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Master Garmr configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GarmrConfig {
    pub instance_id: String,
    pub consensus: ConsensusConfig,
    pub correlation: CorrelationConfig,
    pub confidence: ConfidenceConfig,
}

impl Default for GarmrConfig {
    fn default() -> Self {
        Self {
            instance_id: format!("garmr-{}", &uuid::Uuid::now_v7().to_string()[..8]),
            consensus: ConsensusConfig::default(),
            correlation: CorrelationConfig::default(),
            confidence: ConfidenceConfig::default(),
        }
    }
}

/// Consensus quorum and voting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Minimum distinct reporting agents required for valid consensus quorum
    pub min_agents: usize,
    /// Minimum weighted agreement ratio required (e.g. 0.66 for 66%)
    pub agreement_threshold: f32,
    /// Default trust weight assigned to probationary/uncalibrated nodes
    pub probation_weight: f32,
    /// Minimum node trust score required to participate in voting (below this are ignored)
    pub min_trust_for_vote: f32,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            min_agents: 3,
            agreement_threshold: 0.66,
            probation_weight: 0.1,
            min_trust_for_vote: 0.3,
        }
    }
}

/// Temporal and entity correlation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationConfig {
    /// Sliding window duration in seconds (default 300s = 5m)
    pub temporal_window_sec: u64,
    /// Minimum observations required to form a candidate cluster
    pub min_observations_per_cluster: usize,
    /// Maximum allowed span for an open cluster before forcing evaluation (default 1800s = 30m)
    pub max_cluster_span_sec: u64,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            temporal_window_sec: 300,
            min_observations_per_cluster: 3,
            max_cluster_span_sec: 1800,
        }
    }
}

/// Bayesian confidence scoring and classification thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceConfig {
    /// Thresholds for classification tiers
    pub thresholds: ClassificationThresholds,
    /// Domain and technique weighting multipliers
    pub technique_weights: HashMap<String, f32>,
    /// Prior probability of threat when no baseline is available
    pub default_prior: f32,
}

impl Default for ConfidenceConfig {
    fn default() -> Self {
        let mut weights = HashMap::new();
        weights.insert("credential_abuse".to_string(), 1.5);
        weights.insert("lateral_movement".to_string(), 1.3);
        weights.insert("injection".to_string(), 1.2);
        weights.insert("beaconing".to_string(), 1.0);
        weights.insert("dns_anomaly".to_string(), 0.8);
        weights.insert("binary_anomaly".to_string(), 0.7);

        Self {
            thresholds: ClassificationThresholds::default(),
            technique_weights: weights,
            default_prior: 0.05, // 5% prior probability of active threat in standard environment
        }
    }
}

/// Classification threshold boundaries according to specs/garmr.md:
/// < 0.40 -> Benign
/// 0.40 - 0.65 -> Suspicious
/// 0.65 - 0.85 -> Probable
/// >= 0.85 -> Confirmed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationThresholds {
    pub benign_upper: f32,
    pub suspicious_lower: f32,
    pub probable_lower: f32,
    pub confirmed_lower: f32,
}

impl Default for ClassificationThresholds {
    fn default() -> Self {
        Self {
            benign_upper: 0.40,
            suspicious_lower: 0.40,
            probable_lower: 0.65,
            confirmed_lower: 0.85,
        }
    }
}
