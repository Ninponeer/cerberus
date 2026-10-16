//! Peer discovery beacons with Ed25519 signatures and replay protection.

use crate::identity::PackNodeIdentity;
use cerberus_core::crypto::VerifyingKeyWrapper;
use cerberus_core::error::{CerberusError, Result};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::Signature;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

/// Broadcast / gossip beacon advertising a Pack node's availability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryBeacon {
    pub node_id: Uuid,
    pub name: String,
    pub spiffe_id: String,
    pub endpoint: SocketAddr,
    pub verifying_key_bytes: [u8; 32],
    pub timestamp_ns: i64,
    pub nonce: [u8; 16],
    #[serde(with = "crate::crypto_serde::sig_serde")]
    pub signature_bytes: [u8; 64],
}

impl DiscoveryBeacon {
    /// Constructs and signs a new discovery beacon using the local node identity.
    pub fn create_signed(identity: &PackNodeIdentity, endpoint: SocketAddr) -> Result<Self> {
        let node_id = identity.node_id;
        let name = identity.name.clone();
        let spiffe_id = identity.spiffe_id.to_string();
        let verifying_key_bytes = identity.verifying_key().to_bytes();
        let timestamp_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);

        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);

        let payload_bytes = Self::canonical_payload(
            &node_id,
            &name,
            &spiffe_id,
            &endpoint,
            timestamp_ns,
            &nonce,
        );

        let signature = identity.sign(&payload_bytes);
        let signature_bytes = signature.to_bytes();

        Ok(Self {
            node_id,
            name,
            spiffe_id,
            endpoint,
            verifying_key_bytes,
            timestamp_ns,
            nonce,
            signature_bytes,
        })
    }

    /// Canonical serialization of beacon fields for signature signing and verification.
    fn canonical_payload(
        node_id: &Uuid,
        name: &str,
        spiffe_id: &str,
        endpoint: &SocketAddr,
        timestamp_ns: i64,
        nonce: &[u8; 16],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(node_id.as_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(spiffe_id.as_bytes());
        buf.extend_from_slice(endpoint.to_string().as_bytes());
        buf.extend_from_slice(&timestamp_ns.to_be_bytes());
        buf.extend_from_slice(nonce);
        buf
    }

    /// Verifies the cryptographic integrity and replay freshness of the beacon.
    pub fn verify(&self, max_drift: Duration) -> Result<()> {
        let now_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let drift_ns = (now_ns - self.timestamp_ns).abs();
        let max_drift_ns = max_drift.num_nanoseconds().unwrap_or(30_000_000_000);

        if drift_ns > max_drift_ns {
            return Err(CerberusError::Validation(format!(
                "Beacon timestamp delta ({} ms) exceeds allowable replay tolerance ({} ms)",
                drift_ns / 1_000_000,
                max_drift_ns / 1_000_000
            )));
        }

        let vk = VerifyingKeyWrapper::from_bytes(&self.verifying_key_bytes)?;
        let payload_bytes = Self::canonical_payload(
            &self.node_id,
            &self.name,
            &self.spiffe_id,
            &self.endpoint,
            self.timestamp_ns,
            &self.nonce,
        );

        let sig = Signature::from_bytes(&self.signature_bytes);
        vk.verify(&payload_bytes, &sig)?;

        Ok(())
    }

    /// Serializes beacon to JSON bytes for network transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Deserializes beacon from network bytes.
    pub fn from_bytes(slice: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(slice)?)
    }

    /// Returns the beacon timestamp as UTC DateTime.
    pub fn timestamp(&self) -> Option<DateTime<Utc>> {
        DateTime::from_timestamp(
            self.timestamp_ns / 1_000_000_000,
            (self.timestamp_ns % 1_000_000_000) as u32,
        )
    }
}
