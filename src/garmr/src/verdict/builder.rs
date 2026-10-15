//! Cryptographic verdict generation, action recommendation, and verification

use anyhow::{anyhow, Result};
use cerberus_core::crypto::{SigningKeyWrapper, VerifyingKeyWrapper};
use cerberus_core::verdict::{ActionType, Classification, RecommendedAction, Verdict};
use ed25519_dalek::Signature;
use std::collections::HashMap;

/// Builds and signs immutable Verdict records
pub struct VerdictBuilder {
    instance_id: String,
    signing_key: SigningKeyWrapper,
}

impl VerdictBuilder {
    pub fn new(instance_id: String, signing_key: SigningKeyWrapper) -> Self {
        Self {
            instance_id,
            signing_key,
        }
    }

    /// Verifying key corresponding to this builder's signing identity
    pub fn verifying_key(&self) -> VerifyingKeyWrapper {
        VerifyingKeyWrapper(self.signing_key.verifying_key())
    }

    /// Build and cryptographically sign a verdict
    pub fn build(
        &self,
        correlation_id: String,
        participating_nodes: Vec<String>,
        confidence: f32,
        classification: Classification,
        threat_class: String,
        evidence_trail: Vec<String>,
        rationale: String,
        target_entities: &HashMap<String, String>,
    ) -> Verdict {
        let verdict_id = uuid::Uuid::now_v7().to_string();
        let timestamp_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);

        let recommended_actions = Self::generate_recommended_actions(classification, confidence, target_entities);

        let canonical_bytes = Self::canonical_payload(
            &verdict_id,
            &correlation_id,
            timestamp_ns,
            confidence,
            classification,
            &threat_class,
        );

        let signature = self.signing_key.sign(&canonical_bytes);

        Verdict {
            verdict_id,
            timestamp_ns,
            correlation_id,
            participating_nodes,
            confidence,
            classification,
            threat_class,
            evidence_trail,
            recommended_actions,
            rationale,
            garmr_instance: self.instance_id.clone(),
            signature: signature.to_bytes().to_vec(),
        }
    }

    /// Canonical representation for cryptographic signing and verification
    pub fn canonical_payload(
        verdict_id: &str,
        correlation_id: &str,
        timestamp_ns: i64,
        confidence: f32,
        classification: Classification,
        threat_class: &str,
    ) -> Vec<u8> {
        format!(
            "CERBERUS_GARMR_V1:{}:{}:{}:{:.4}:{:?}:{}",
            verdict_id, correlation_id, timestamp_ns, confidence, classification, threat_class
        )
        .into_bytes()
    }

    /// Verify an emitted verdict against an expected verifying key
    pub fn verify_verdict(verdict: &Verdict, verifying_key: &VerifyingKeyWrapper) -> Result<()> {
        if verdict.signature.len() != 64 {
            return Err(anyhow!("Invalid signature byte length: expected 64, got {}", verdict.signature.len()));
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&verdict.signature);
        let signature = Signature::from_bytes(&sig_bytes);

        let canonical_bytes = Self::canonical_payload(
            &verdict.verdict_id,
            &verdict.correlation_id,
            verdict.timestamp_ns,
            verdict.confidence,
            verdict.classification,
            &verdict.threat_class,
        );

        verifying_key.verify(&canonical_bytes, &signature)
            .map_err(|e| anyhow!("Verdict signature verification failed: {}", e))
    }

    /// Recommend tactical containment and response actions according to threat classification
    fn generate_recommended_actions(
        classification: Classification,
        _confidence: f32,
        target_entities: &HashMap<String, String>,
    ) -> Vec<RecommendedAction> {
        let mut actions = Vec::new();

        match classification {
            Classification::Confirmed => {
                let mut params = HashMap::new();
                if let Some(host) = target_entities.get("host") {
                    params.insert("target_host".to_string(), host.clone());
                }
                if let Some(ip) = target_entities.get("ip") {
                    params.insert("target_ip".to_string(), ip.clone());
                }
                actions.push(RecommendedAction {
                    action_type: ActionType::NetworkIsolate,
                    parameters: params.clone(),
                    urgency: 1.0,
                });
                actions.push(RecommendedAction {
                    action_type: ActionType::ForensicCapture,
                    parameters: params,
                    urgency: 0.9,
                });
                if let Some(user) = target_entities.get("user") {
                    let mut user_params = HashMap::new();
                    user_params.insert("target_user".to_string(), user.clone());
                    actions.push(RecommendedAction {
                        action_type: ActionType::CredentialSuspend,
                        parameters: user_params,
                        urgency: 0.95,
                    });
                }
            }
            Classification::Probable => {
                let mut params = HashMap::new();
                if let Some(ip) = target_entities.get("ip") {
                    params.insert("target_ip".to_string(), ip.clone());
                }
                actions.push(RecommendedAction {
                    action_type: ActionType::Microsegment,
                    parameters: params.clone(),
                    urgency: 0.8,
                });
                actions.push(RecommendedAction {
                    action_type: ActionType::EnhancedMonitoring,
                    parameters: params,
                    urgency: 0.7,
                });
            }
            Classification::Suspicious => {
                let mut params = HashMap::new();
                if let Some(endpoint) = target_entities.get("host").or_else(|| target_entities.get("agent")) {
                    params.insert("target_endpoint".to_string(), endpoint.clone());
                }
                actions.push(RecommendedAction {
                    action_type: ActionType::EnhancedMonitoring,
                    parameters: params.clone(),
                    urgency: 0.5,
                });
                actions.push(RecommendedAction {
                    action_type: ActionType::DecoyActivate,
                    parameters: params,
                    urgency: 0.4,
                });
            }
            Classification::Benign => {
                // No automated containment actions for benign events
            }
        }

        actions
    }
}
