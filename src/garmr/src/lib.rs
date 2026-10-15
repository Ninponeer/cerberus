//! Garmr - The Sentinel
//!
//! Verification, correlation, consensus, and Bayesian confidence scoring.
//!
//! Garmr carries the rune Tiwaz (ᛏ) representing Judgment.
//! Garmr ONLY judges. Garmr NEVER collects raw telemetry. Garmr NEVER enforces.

pub mod config;
pub mod consensus;
pub mod correlation;
pub mod engine;
pub mod verdict;

pub use config::GarmrConfig;
pub use consensus::{BayesianScorer, ConsensusEngine, QuorumResult};
pub use correlation::{CorrelationEngine, ObservationCluster};
pub use engine::GarmrEngine;
pub use verdict::VerdictBuilder;

#[cfg(test)]
mod tests {
    use super::*;
    use cerberus_core::crypto::{SigningKeyWrapper, VerifyingKeyWrapper};
    use cerberus_core::observation::{Evidence, Observation, ObservationType};
    use cerberus_core::verdict::{ActionType, Classification};
    use std::collections::HashMap;

    fn make_test_observation(
        agent_id: &str,
        obs_type: ObservationType,
        confidence: f32,
        user: &str,
        host: &str,
    ) -> Observation {
        let mut fields = HashMap::new();
        fields.insert("user".to_string(), user.to_string());
        fields.insert("host".to_string(), host.to_string());
        fields.insert("src_ip".to_string(), "10.0.0.100".to_string());

        let evidence = Evidence {
            fields,
            raw_events: Vec::new(),
            feature_vector: HashMap::new(),
        };

        Observation::new(agent_id, obs_type, confidence, evidence)
    }

    #[test]
    fn test_quorum_formation_and_signature_verification() {
        let signing_key = SigningKeyWrapper::generate();
        let verifying_key = VerifyingKeyWrapper(signing_key.verifying_key());
        let config = GarmrConfig::default();

        let mut engine = GarmrEngine::new(config, signing_key);

        // Calibrate 3 trusted nodes
        engine.update_node_trust("node-alpha".to_string(), 0.9);
        engine.update_node_trust("node-beta".to_string(), 0.85);
        engine.update_node_trust("node-gamma".to_string(), 0.8);

        // Three observations from 3 distinct trusted agents on the same host/user entity
        let obs1 = make_test_observation("node-alpha", ObservationType::IndicatorMatch, 0.95, "admin", "dc-01");
        let obs2 = make_test_observation("node-beta", ObservationType::BehavioralDeviation, 0.90, "admin", "dc-01");
        let obs3 = make_test_observation("node-gamma", ObservationType::AttackChainLink, 0.92, "admin", "dc-01");

        let corr1 = engine.ingest_observation(obs1).unwrap();
        let corr2 = engine.ingest_observation(obs2).unwrap();
        let corr3 = engine.ingest_observation(obs3).unwrap();

        // All 3 should be correlated together
        assert_eq!(corr1, corr2);
        assert_eq!(corr2, corr3);

        // Advance simulated time past temporal window (301 seconds into the future)
        let future_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) + (301 * 1_000_000_000);
        let verdicts = engine.evaluate_mature_clusters(future_ns);

        assert_eq!(verdicts.len(), 1);
        let verdict = &verdicts[0];

        // Quorum satisfied: 3 nodes, high confidence
        assert_eq!(verdict.classification, Classification::Confirmed);
        assert!(verdict.confidence >= 0.85);
        assert_eq!(verdict.participating_nodes.len(), 3);
        assert_eq!(verdict.evidence_trail.len(), 3);

        // Verify cryptographic Ed25519 signature
        let verify_result = VerdictBuilder::verify_verdict(verdict, &verifying_key);
        assert!(verify_result.is_ok(), "Cryptographic signature verification must succeed");

        // Containment action recommendations should be populated for Confirmed threat
        let has_isolate = verdict
            .recommended_actions
            .iter()
            .any(|a| a.action_type == ActionType::NetworkIsolate);
        assert!(has_isolate, "Confirmed verdict must recommend NetworkIsolate");
    }

    #[test]
    fn test_quorum_failure_demotes_to_suspicious() {
        let signing_key = SigningKeyWrapper::generate();
        let config = GarmrConfig::default();
        let mut engine = GarmrEngine::new(config, signing_key);

        engine.update_node_trust("node-lonely-1".to_string(), 0.95);
        engine.update_node_trust("node-lonely-2".to_string(), 0.95);

        // Only 2 distinct agents (min_agents is 3)
        let obs1 = make_test_observation("node-lonely-1", ObservationType::IndicatorMatch, 0.99, "svc_backup", "srv-sql");
        let obs2 = make_test_observation("node-lonely-2", ObservationType::Anomaly, 0.98, "svc_backup", "srv-sql");

        engine.ingest_observation(obs1).unwrap();
        engine.ingest_observation(obs2).unwrap();

        let future_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) + (301 * 1_000_000_000);
        let verdicts = engine.evaluate_mature_clusters(future_ns);

        assert_eq!(verdicts.len(), 1);
        let verdict = &verdicts[0];

        // Must be capped to Suspicious because quorum failed
        assert_eq!(verdict.classification, Classification::Suspicious);
        assert!(verdict.confidence <= 0.60);
        assert!(verdict.rationale.contains("Quorum not achieved"));
    }

    #[test]
    fn test_replay_protection() {
        let signing_key = SigningKeyWrapper::generate();
        let config = GarmrConfig::default();
        let mut engine = GarmrEngine::new(config, signing_key);

        let obs = make_test_observation("node-1", ObservationType::Anomaly, 0.7, "alice", "laptop-01");
        let obs_dup = obs.clone();

        assert!(engine.ingest_observation(obs).is_ok());
        let err = engine.ingest_observation(obs_dup);
        assert!(err.is_err(), "Duplicate observation ID must be rejected as replay");
    }

    #[test]
    fn test_sybil_resistance_filtering() {
        let signing_key = SigningKeyWrapper::generate();
        let mut config = GarmrConfig::default();
        config.consensus.min_trust_for_vote = 0.4;
        let mut engine = GarmrEngine::new(config, signing_key);

        // 5 untrusted / probationary nodes (trust = 0.1, below min_trust_for_vote 0.4)
        for i in 0..5 {
            let id = format!("untrusted-{}", i);
            engine.update_node_trust(id.clone(), 0.1);
            let obs = make_test_observation(&id, ObservationType::Anomaly, 0.9, "mallory", "host-victim");
            let _ = engine.ingest_observation(obs);
        }

        let future_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) + (301 * 1_000_000_000);
        let verdicts = engine.evaluate_mature_clusters(future_ns);

        assert_eq!(verdicts.len(), 1);
        let verdict = &verdicts[0];

        // Sybil cluster cannot attain Confirmed or Probable status because agreeing trusted weight is 0.0
        assert_ne!(verdict.classification, Classification::Confirmed);
        assert_ne!(verdict.classification, Classification::Probable);
        assert!(verdict.confidence < 0.65, "Sybil nodes cannot drive confidence above suspicious threshold");
    }
}
