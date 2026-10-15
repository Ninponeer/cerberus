//! Yggdrasil - The Knowledge Graph and Living Memory
//!
//! Yggdrasil ONLY remembers. Yggdrasil NEVER decides. Yggdrasil NEVER enforces.
//!
//! High-performance append-only knowledge graph, state distribution,
//! behavioral baseline storage, and swarm trust scores.

pub mod models;
pub mod storage;

pub use models::{BehavioralBaseline, DeviceEntity, EntityRecord, ProcessEntity, TrustScoreRecord, UserEntity};
pub use storage::RocksYggdrasilStore;

#[cfg(test)]
mod tests {
    use super::*;
    use cerberus_core::observation::{Evidence, Observation, ObservationType};
    use cerberus_core::verdict::{ActionType, Classification, RecommendedAction, Verdict};
    use std::collections::HashMap;

    #[test]
    fn test_rocks_entities_crud() {
        let (store, _dir) = RocksYggdrasilStore::open_ephemeral().unwrap();

        let device = DeviceEntity {
            id: "device:sentinel-alpha".to_string(),
            hostname: "sentinel-alpha".to_string(),
            ips: vec!["10.0.1.50".to_string(), "10.0.2.50".to_string()],
            os: "Linux 6.x-x86_64".to_string(),
            role: "Tier2-Consensus".to_string(),
            tier: 2,
            trust_score: 0.95,
            first_seen_ns: 1000,
            last_seen_ns: 2000,
        };

        let entity_record = EntityRecord::Device(device.clone());
        store.put_entity("device:sentinel-alpha", &entity_record).unwrap();

        let retrieved = store.get_entity("device:sentinel-alpha").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), entity_record);

        // Non-existent entity
        let missing = store.get_entity("device:unknown").unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn test_rocks_observations_append_and_index() {
        let (store, _dir) = RocksYggdrasilStore::open_ephemeral().unwrap();

        let mut fields = HashMap::new();
        fields.insert("host".to_string(), "srv-db01".to_string());
        fields.insert("user".to_string(), "svc_backup".to_string());

        let obs = Observation::new(
            "agent-alpha",
            ObservationType::IndicatorMatch,
            0.92,
            Evidence {
                fields,
                raw_events: Vec::new(),
                feature_vector: HashMap::new(),
            },
        );

        let obs_id = obs.observation_id.clone();
        store.record_observation(&obs).unwrap();

        // 1. Direct retrieval by ID
        let fetched = store.get_observation(&obs_id).unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().agent_id, "agent-alpha");

        // 2. Secondary index retrieval by agent entity
        let by_agent = store.get_observations_for_entity("agent-alpha", 10).unwrap();
        assert_eq!(by_agent.len(), 1);
        assert_eq!(by_agent[0].observation_id, obs_id);

        // 3. Secondary index retrieval by host entity
        let by_host = store.get_observations_for_entity("host:srv-db01", 10).unwrap();
        assert_eq!(by_host.len(), 1);
        assert_eq!(by_host[0].observation_id, obs_id);
    }

    #[test]
    fn test_rocks_verdicts_append_and_correlation() {
        let (store, _dir) = RocksYggdrasilStore::open_ephemeral().unwrap();

        let corr_id = "corr-test-123".to_string();
        let verdict = Verdict {
            verdict_id: "ver-abc-456".to_string(),
            timestamp_ns: 123456789,
            correlation_id: corr_id.clone(),
            participating_nodes: vec!["agent-alpha".to_string(), "agent-beta".to_string()],
            confidence: 0.94,
            classification: Classification::Confirmed,
            threat_class: "CredentialAbuse".to_string(),
            evidence_trail: vec!["obs-1".to_string(), "obs-2".to_string()],
            recommended_actions: vec![RecommendedAction {
                action_type: ActionType::NetworkIsolate,
                parameters: HashMap::new(),
                urgency: 1.0,
            }],
            rationale: "Multi-agent consensus on credential dumping".to_string(),
            garmr_instance: "garmr-01".to_string(),
            signature: vec![1, 2, 3, 4],
        };

        store.record_verdict(&verdict).unwrap();

        // 1. Direct retrieval
        let fetched = store.get_verdict("ver-abc-456").unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().classification, Classification::Confirmed);

        // 2. Correlation query
        let correlated = store.get_verdicts_for_correlation(&corr_id).unwrap();
        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].verdict_id, "ver-abc-456");
    }

    #[test]
    fn test_rocks_trust_scores_and_export() {
        let (store, _dir) = RocksYggdrasilStore::open_ephemeral().unwrap();

        let record1 = TrustScoreRecord {
            agent_id: "agent-01".to_string(),
            score: 0.88,
            observation_count: 140,
            accurate_verdict_count: 135,
            calibrated_at_ns: 1000,
        };
        let record2 = TrustScoreRecord {
            agent_id: "agent-02".to_string(),
            score: 0.92,
            observation_count: 220,
            accurate_verdict_count: 215,
            calibrated_at_ns: 1000,
        };

        store.update_trust_score(&record1).unwrap();
        store.update_trust_score(&record2).unwrap();

        // Query individual
        assert_eq!(store.get_trust_score("agent-01").unwrap(), Some(0.88));
        assert_eq!(store.get_trust_score("agent-02").unwrap(), Some(0.92));
        assert_eq!(store.get_trust_score("agent-03").unwrap(), None);

        // Bulk export for Garmr consensus engine
        let all_scores = store.get_all_trust_scores().unwrap();
        assert_eq!(all_scores.len(), 2);
        assert_eq!(all_scores.get("agent-01"), Some(&0.88));
        assert_eq!(all_scores.get("agent-02"), Some(&0.92));
    }

    #[test]
    fn test_rocks_behavioral_baseline() {
        let (store, _dir) = RocksYggdrasilStore::open_ephemeral().unwrap();

        let mut feature_means = HashMap::new();
        feature_means.insert("egress_bytes_per_hour".to_string(), 45200.0);
        feature_means.insert("unique_dst_ports".to_string(), 3.5);

        let baseline = BehavioralBaseline {
            entity_id: "host:srv-app01".to_string(),
            entity_type: "HOST".to_string(),
            sample_count: 720,
            feature_means,
            feature_stds: HashMap::new(),
            updated_at_ns: 5000,
        };

        store.put_baseline(&baseline).unwrap();

        let fetched = store.get_baseline("host:srv-app01").unwrap();
        assert!(fetched.is_some());
        let b = fetched.unwrap();
        assert_eq!(b.sample_count, 720);
        assert_eq!(b.feature_means.get("unique_dst_ports"), Some(&3.5));
    }
}
