//! Cryptographic mutual challenge-response authentication for Cerberus Pack.

use crate::identity::PackNodeIdentity;
use cerberus_core::crypto::VerifyingKeyWrapper;
use cerberus_core::error::{CerberusError, Result};
use chrono::{Duration, Utc};
use ed25519_dalek::Signature;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Initial cryptographic challenge sent by an initiating node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandshakeChallenge {
    pub initiator_id: Uuid,
    pub nonce: [u8; 32],
    pub timestamp_ns: i64,
}

/// Cryptographic response from the challenged node, signing the challenge nonce.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandshakeResponse {
    pub responder_id: Uuid,
    pub challenge_nonce: [u8; 32],
    pub responder_nonce: [u8; 32],
    pub cert_fingerprint: String,
    pub timestamp_ns: i64,
    #[serde(with = "crate::crypto_serde::sig_serde")]
    pub signature_bytes: [u8; 64],
}

/// Final acknowledgment from the initiator confirming mutual authentication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandshakeAck {
    pub initiator_id: Uuid,
    pub responder_nonce: [u8; 32],
    pub cert_fingerprint: String,
    pub timestamp_ns: i64,
    #[serde(with = "crate::crypto_serde::sig_serde")]
    pub signature_bytes: [u8; 64],
}

/// Mutual authentication protocol driver.
pub struct HandshakeProtocol;

impl HandshakeProtocol {
    /// Step 1: Initiator creates a cryptographic challenge nonce.
    pub fn create_challenge(initiator: &PackNodeIdentity) -> (HandshakeChallenge, [u8; 32]) {
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let timestamp_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);

        let challenge = HandshakeChallenge {
            initiator_id: initiator.node_id,
            nonce,
            timestamp_ns,
        };

        (challenge, nonce)
    }

    /// Step 2: Responder handles the challenge, generates a counter-nonce, and signs the payload.
    pub fn handle_challenge(
        responder: &PackNodeIdentity,
        challenge: &HandshakeChallenge,
        cert_fingerprint: &str,
        max_drift: Duration,
    ) -> Result<HandshakeResponse> {
        // Validate challenge freshness
        let now_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let drift_ns = (now_ns - challenge.timestamp_ns).abs();
        let max_drift_ns = max_drift.num_nanoseconds().unwrap_or(30_000_000_000);

        if drift_ns > max_drift_ns {
            return Err(CerberusError::Validation(format!(
                "Handshake challenge timestamp delta ({} ms) exceeds allowable tolerance",
                drift_ns / 1_000_000
            )));
        }

        let mut responder_nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut responder_nonce);
        let timestamp_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);

        let canonical_bytes = Self::canonical_response_bytes(
            &responder.node_id,
            &challenge.nonce,
            &responder_nonce,
            cert_fingerprint,
            timestamp_ns,
        );

        let signature = responder.sign(&canonical_bytes);

        Ok(HandshakeResponse {
            responder_id: responder.node_id,
            challenge_nonce: challenge.nonce,
            responder_nonce,
            cert_fingerprint: cert_fingerprint.to_string(),
            timestamp_ns,
            signature_bytes: signature.to_bytes(),
        })
    }

    /// Step 3: Initiator verifies the responder's signature and counter-signs with an Ack.
    pub fn handle_response(
        initiator: &PackNodeIdentity,
        original_challenge_nonce: &[u8; 32],
        response: &HandshakeResponse,
        responder_vk: &VerifyingKeyWrapper,
        initiator_cert_fingerprint: &str,
        max_drift: Duration,
    ) -> Result<HandshakeAck> {
        // Verify challenge nonce match
        if original_challenge_nonce != &response.challenge_nonce {
            return Err(CerberusError::Validation(
                "Handshake response challenge nonce mismatch".to_string(),
            ));
        }

        // Verify response freshness
        let now_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let drift_ns = (now_ns - response.timestamp_ns).abs();
        let max_drift_ns = max_drift.num_nanoseconds().unwrap_or(30_000_000_000);

        if drift_ns > max_drift_ns {
            return Err(CerberusError::Validation(format!(
                "Handshake response timestamp delta ({} ms) exceeds allowable tolerance",
                drift_ns / 1_000_000
            )));
        }

        // Verify responder signature
        let canonical_bytes = Self::canonical_response_bytes(
            &response.responder_id,
            &response.challenge_nonce,
            &response.responder_nonce,
            &response.cert_fingerprint,
            response.timestamp_ns,
        );

        let sig = Signature::from_bytes(&response.signature_bytes);
        responder_vk.verify(&canonical_bytes, &sig)?;

        // Counter-sign initiator Ack
        let ack_timestamp_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let ack_bytes = Self::canonical_ack_bytes(
            &initiator.node_id,
            &response.responder_nonce,
            initiator_cert_fingerprint,
            ack_timestamp_ns,
        );

        let ack_sig = initiator.sign(&ack_bytes);

        Ok(HandshakeAck {
            initiator_id: initiator.node_id,
            responder_nonce: response.responder_nonce,
            cert_fingerprint: initiator_cert_fingerprint.to_string(),
            timestamp_ns: ack_timestamp_ns,
            signature_bytes: ack_sig.to_bytes(),
        })
    }

    /// Step 4: Responder verifies the initiator's Ack to complete mutual authentication.
    pub fn verify_ack(
        ack: &HandshakeAck,
        original_responder_nonce: &[u8; 32],
        initiator_vk: &VerifyingKeyWrapper,
        max_drift: Duration,
    ) -> Result<()> {
        if original_responder_nonce != &ack.responder_nonce {
            return Err(CerberusError::Validation(
                "Handshake ack responder nonce mismatch".to_string(),
            ));
        }

        let now_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let drift_ns = (now_ns - ack.timestamp_ns).abs();
        let max_drift_ns = max_drift.num_nanoseconds().unwrap_or(30_000_000_000);

        if drift_ns > max_drift_ns {
            return Err(CerberusError::Validation(format!(
                "Handshake ack timestamp delta ({} ms) exceeds allowable tolerance",
                drift_ns / 1_000_000
            )));
        }

        let ack_bytes = Self::canonical_ack_bytes(
            &ack.initiator_id,
            &ack.responder_nonce,
            &ack.cert_fingerprint,
            ack.timestamp_ns,
        );

        let sig = Signature::from_bytes(&ack.signature_bytes);
        initiator_vk.verify(&ack_bytes, &sig)?;

        Ok(())
    }

    fn canonical_response_bytes(
        responder_id: &Uuid,
        challenge_nonce: &[u8; 32],
        responder_nonce: &[u8; 32],
        cert_fingerprint: &str,
        timestamp_ns: i64,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(responder_id.as_bytes());
        buf.extend_from_slice(challenge_nonce);
        buf.extend_from_slice(responder_nonce);
        buf.extend_from_slice(cert_fingerprint.as_bytes());
        buf.extend_from_slice(&timestamp_ns.to_be_bytes());
        buf
    }

    fn canonical_ack_bytes(
        initiator_id: &Uuid,
        responder_nonce: &[u8; 32],
        cert_fingerprint: &str,
        timestamp_ns: i64,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(initiator_id.as_bytes());
        buf.extend_from_slice(responder_nonce);
        buf.extend_from_slice(cert_fingerprint.as_bytes());
        buf.extend_from_slice(&timestamp_ns.to_be_bytes());
        buf
    }
}
