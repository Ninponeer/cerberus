//! Orthrus - The Active Containment and Response Engine
//!
//! Provides rapid mitigation, network isolation, process containment,
//! traffic redirection, cryptographic operator approval gates, and
//! evidence preservation for Project Cerberus.

pub mod action;
pub mod engine;
pub mod platform;
pub mod policy;

pub use action::{
    action_from_directive, ContainmentAction, CredentialSuspendAction, ForensicCaptureAction,
    NetworkQuarantineAction, ProcessKillAction, TrafficRedirectAction,
};
pub use engine::OrthrusEngine;
pub use platform::{LinuxNetfilterAdapter, MockPlatformAdapter, PlatformAdapter, WindowsNetshAdapter};
pub use policy::{ApprovalToken, ContainmentPolicy, RollbackManager, RollbackRecord};

#[cfg(test)]
mod tests {
    use super::*;
    use cerberus_core::action::{ActionDirective, ActionStatus, TargetSelector};
    use cerberus_core::crypto::SigningKeyWrapper;
    use cerberus_core::verdict::ActionType;
    use chrono::Utc;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::collections::HashMap;
    use std::sync::Arc;
    use uuid::Uuid;

    fn make_test_keys() -> (SigningKeyWrapper, SigningKeyWrapper) {
        let node_signing = SigningKeyWrapper(SigningKey::generate(&mut OsRng));
        let operator_signing = SigningKeyWrapper(SigningKey::generate(&mut OsRng));
        (node_signing, operator_signing)
    }

    #[tokio::test]
    async fn test_network_quarantine_autonomous_and_rollback() {
        let (node_key, _operator_key) = make_test_keys();
        let mock_platform = Arc::new(MockPlatformAdapter::new());
        let policy = ContainmentPolicy::default();

        let engine = OrthrusEngine::new(
            "orthrus-node-01".to_string(),
            node_key,
            mock_platform.clone(),
            policy,
        );

        let directive_id = format!("dir-{}", Uuid::now_v7());
        let mut params = HashMap::new();
        params.insert("target_ip".to_string(), "192.168.1.100".to_string());

        let directive = ActionDirective {
            directive_id: directive_id.clone(),
            verdict_id: Some("verdict-123".to_string()),
            timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0),
            action_type: ActionType::NetworkIsolate,
            target: TargetSelector {
                device_id: None,
                user_id: None,
                process_id: None,
                network: None,
                group_tag: None,
            },
            parameters: params,
            urgency: 0.95,
            requires_confirmation: false,
            rationale: "Autonomous C2 beaconing isolation".to_string(),
            garmr_signature: vec![1, 2, 3],
            shepherd_signature: Vec::new(),
        };

        // 1. Execute autonomously (confidence 0.94 >= 0.85 threshold)
        let result = engine
            .execute_directive(&directive, 0.94, None)
            .await
            .expect("Autonomous containment should succeed");

        assert_eq!(result.status, ActionStatus::Succeeded);
        assert!(!result.signature.is_empty());
        assert!(result.rollback.reversible);
        assert!(mock_platform.is_ip_isolated("192.168.1.100"));

        // 2. Active containments check
        let active = engine.list_active_containments();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].directive_id, directive_id);

        // 3. Roll back containment
        engine
            .rollback_directive(&directive_id)
            .await
            .expect("Rollback should succeed");

        assert!(!mock_platform.is_ip_isolated("192.168.1.100"));
        assert_eq!(mock_platform.active_isolation_count(), 0);
        assert_eq!(engine.list_active_containments().len(), 0);
    }

    #[tokio::test]
    async fn test_operator_approval_gate_and_signature_verification() {
        let (node_key, operator_key) = make_test_keys();
        let operator_verifying = operator_key.verifying_key();
        let (rogue_key, _) = make_test_keys();

        let mock_platform = Arc::new(MockPlatformAdapter::new());
        let mut policy = ContainmentPolicy::default();
        policy.operator_verifying_key = Some(cerberus_core::crypto::VerifyingKeyWrapper(operator_verifying));

        let engine = OrthrusEngine::new(
            "orthrus-node-01".to_string(),
            node_key,
            mock_platform.clone(),
            policy,
        );

        let directive_id = format!("dir-{}", Uuid::now_v7());
        let mut params = HashMap::new();
        params.insert("target_ip".to_string(), "10.0.50.15".to_string());

        let directive = ActionDirective {
            directive_id: directive_id.clone(),
            verdict_id: Some("verdict-456".to_string()),
            timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0),
            action_type: ActionType::NetworkIsolate,
            target: TargetSelector {
                device_id: None,
                user_id: None,
                process_id: None,
                network: None,
                group_tag: None,
            },
            parameters: params,
            urgency: 0.75, // Below autonomous threshold (0.80)
            requires_confirmation: false,
            rationale: "Suspicious lateral movement requiring operator sign-off".to_string(),
            garmr_signature: vec![1, 2, 3],
            shepherd_signature: Vec::new(),
        };

        // 1. Fails without approval token (confidence 0.70 < 0.85)
        let err = engine
            .execute_directive(&directive, 0.70, None)
            .await
            .expect_err("Should require approval token");
        assert!(err.to_string().contains("requires operator approval"));

        // 2. Fails with rogue operator signature
        let now_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let token_id = format!("tok-{}", Uuid::now_v7());
        let rogue_sig = rogue_key.sign(&ApprovalToken::canonical_payload(
            &token_id,
            &directive_id,
            "shepherd:operator:rogue",
            now_ns,
            now_ns + 60_000_000_000,
        ));

        let bad_token = ApprovalToken {
            token_id: token_id.clone(),
            directive_id: directive_id.clone(),
            operator_id: "shepherd:operator:rogue".to_string(),
            granted_at_ns: now_ns,
            expires_at_ns: now_ns + 60_000_000_000,
            signature: rogue_sig.to_bytes().to_vec(),
        };

        let err = engine
            .execute_directive(&directive, 0.70, Some(bad_token))
            .await
            .expect_err("Should reject invalid signature");
        assert!(err.to_string().contains("verification failed"));

        // 3. Succeeds with authentic Shepherd operator signature
        let valid_sig = operator_key.sign(&ApprovalToken::canonical_payload(
            &token_id,
            &directive_id,
            "shepherd:operator:rick",
            now_ns,
            now_ns + 60_000_000_000,
        ));

        let valid_token = ApprovalToken {
            token_id,
            directive_id: directive_id.clone(),
            operator_id: "shepherd:operator:rick".to_string(),
            granted_at_ns: now_ns,
            expires_at_ns: now_ns + 60_000_000_000,
            signature: valid_sig.to_bytes().to_vec(),
        };

        let res = engine
            .execute_directive(&directive, 0.70, Some(valid_token))
            .await
            .expect("Should execute with valid operator approval");
        assert_eq!(res.status, ActionStatus::Succeeded);
        assert!(mock_platform.is_ip_isolated("10.0.50.15"));
    }

    #[tokio::test]
    async fn test_process_kill_action_and_evidence_preservation() {
        let (node_key, _operator_key) = make_test_keys();
        let mock_platform = Arc::new(MockPlatformAdapter::new());
        let policy = ContainmentPolicy::default();

        let engine = OrthrusEngine::new(
            "orthrus-node-01".to_string(),
            node_key,
            mock_platform.clone(),
            policy,
        );

        let directive_id = format!("dir-{}", Uuid::now_v7());
        let directive = ActionDirective {
            directive_id: directive_id.clone(),
            verdict_id: Some("verdict-789".to_string()),
            timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0),
            action_type: ActionType::NetworkIsolate,
            target: TargetSelector {
                device_id: None,
                user_id: None,
                process_id: Some("4242".to_string()),
                network: None,
                group_tag: None,
            },
            parameters: HashMap::new(),
            urgency: 0.99,
            requires_confirmation: false,
            rationale: "Immediate botnet worker process termination".to_string(),
            garmr_signature: vec![1, 2, 3],
            shepherd_signature: Vec::new(),
        };

        let result = engine
            .execute_directive(&directive, 0.98, None)
            .await
            .expect("Process kill should execute");

        assert_eq!(result.status, ActionStatus::Succeeded);
        assert!(mock_platform.was_pid_killed(4242));
        assert!(result.preservation.memory_captured);
        assert_eq!(result.preservation.storage_location, "/DataVolume/cerberus_vault");
    }

    #[tokio::test]
    async fn test_safety_whitelist_protection() {
        let (node_key, _operator_key) = make_test_keys();
        let mock_platform = Arc::new(MockPlatformAdapter::new());
        let policy = ContainmentPolicy::default();

        let engine = OrthrusEngine::new(
            "orthrus-node-01".to_string(),
            node_key,
            mock_platform.clone(),
            policy,
        );

        // 1. Loopback IP containment rejection
        let mut loopback_params = HashMap::new();
        loopback_params.insert("target_ip".to_string(), "127.0.0.1".to_string());

        let loopback_directive = ActionDirective {
            directive_id: "dir-safe-1".to_string(),
            verdict_id: None,
            timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0),
            action_type: ActionType::NetworkIsolate,
            target: TargetSelector {
                device_id: None,
                user_id: None,
                process_id: None,
                network: None,
                group_tag: None,
            },
            parameters: loopback_params,
            urgency: 1.0,
            requires_confirmation: false,
            rationale: "Attempt to isolate localhost".to_string(),
            garmr_signature: vec![],
            shepherd_signature: vec![],
        };

        let err = engine
            .execute_directive(&loopback_directive, 0.99, None)
            .await
            .expect_err("Loopback isolation must fail");
        assert!(err.to_string().contains("whitelisted against containment"));

        // 2. PID 1 protection rejection
        let init_directive = ActionDirective {
            directive_id: "dir-safe-2".to_string(),
            verdict_id: None,
            timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0),
            action_type: ActionType::NetworkIsolate,
            target: TargetSelector {
                device_id: None,
                user_id: None,
                process_id: Some("1".to_string()),
                network: None,
                group_tag: None,
            },
            parameters: HashMap::new(),
            urgency: 1.0,
            requires_confirmation: false,
            rationale: "Attempt to kill init".to_string(),
            garmr_signature: vec![],
            shepherd_signature: vec![],
        };

        let err = engine
            .execute_directive(&init_directive, 0.99, None)
            .await
            .expect_err("Killing init must fail");
        assert!(err.to_string().contains("protected by safety policy whitelist"));
    }

    #[tokio::test]
    async fn test_traffic_redirect_and_ttl_expiration_sweep() {
        let (node_key, _operator_key) = make_test_keys();
        let mock_platform = Arc::new(MockPlatformAdapter::new());
        let policy = ContainmentPolicy::default();

        let engine = OrthrusEngine::new(
            "orthrus-node-01".to_string(),
            node_key,
            mock_platform.clone(),
            policy,
        );

        let directive_id = format!("dir-{}", Uuid::now_v7());
        let mut params = HashMap::new();
        params.insert("source_ip".to_string(), "192.168.1.250".to_string());
        params.insert("destination_ip".to_string(), "192.168.12.140".to_string()); // WeaponX NAS
        params.insert("sink_port".to_string(), "9000".to_string());

        let directive = ActionDirective {
            directive_id: directive_id.clone(),
            verdict_id: Some("verdict-sinkhole".to_string()),
            timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0),
            action_type: ActionType::TrafficRedirect,
            target: TargetSelector {
                device_id: None,
                user_id: None,
                process_id: None,
                network: None,
                group_tag: None,
            },
            parameters: params,
            urgency: 0.95,
            requires_confirmation: false,
            rationale: "Divert suspicious lateral traffic to WeaponX vault dropzone".to_string(),
            garmr_signature: vec![1, 2, 3],
            shepherd_signature: Vec::new(),
        };

        let result = engine
            .execute_directive(&directive, 0.95, None)
            .await
            .expect("Traffic redirection should execute");

        assert_eq!(result.status, ActionStatus::Succeeded);
        assert_eq!(mock_platform.redirected_routes.read().unwrap().len(), 1);

        // Sweep with future timestamp past expiration
        let future_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0) + (10_000 * 1_000_000_000);
        let swept_count = engine
            .sweep_expired_containments(future_ns)
            .await
            .expect("Sweep should succeed");

        assert_eq!(swept_count, 1);
        assert_eq!(mock_platform.redirected_routes.read().unwrap().len(), 0);
        assert_eq!(engine.list_active_containments().len(), 0);
    }
}
