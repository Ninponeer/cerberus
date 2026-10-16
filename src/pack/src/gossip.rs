//! Prioritized gossip messaging, routing, and deduplication for Cerberus Pack.

use crate::identity::PackNodeIdentity;
use cerberus_core::crypto::VerifyingKeyWrapper;
use cerberus_core::error::Result;
use chrono::Utc;
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use uuid::Uuid;

/// Gossip message type defining routing priority per Cerberus specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GossipType {
    /// Garmr consensus verdict (Priority 0: Highest).
    Verdict = 0,
    /// Orthrus active containment policy update (Priority 0: Highest).
    PolicyUpdate = 1,
    /// Fenrir behavioral threat observation (Priority 1: High).
    Observation = 2,
    /// Node liveness and health telemetry (Priority 2: Normal).
    Health = 3,
    /// Swarm topology and peer view exchange (Priority 3: Background).
    Topology = 4,
}

impl GossipType {
    /// Maps message type to its numeric queue priority tier (0 = highest).
    pub fn priority_tier(&self) -> usize {
        match self {
            Self::Verdict | Self::PolicyUpdate => 0,
            Self::Observation => 1,
            Self::Health => 2,
            Self::Topology => 3,
        }
    }
}

/// Cryptographically signed envelope carrying gossip payloads across the swarm.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GossipEnvelope {
    pub message_id: Uuid,
    pub sender_id: Uuid,
    pub origin_spiffe: String,
    pub msg_type: GossipType,
    pub ttl: u8,
    pub timestamp_ns: i64,
    pub payload: Vec<u8>,
    #[serde(with = "crate::crypto_serde::sig_serde")]
    pub signature_bytes: [u8; 64],
}

impl GossipEnvelope {
    /// Constructs and signs a new gossip envelope with specified TTL hop limit.
    pub fn create_signed(
        identity: &PackNodeIdentity,
        msg_type: GossipType,
        payload: Vec<u8>,
        ttl: u8,
    ) -> Self {
        let message_id = Uuid::new_v4();
        let sender_id = identity.node_id;
        let origin_spiffe = identity.spiffe_id.to_string();
        let timestamp_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);

        let canonical_bytes = Self::canonical_bytes(
            &message_id,
            &sender_id,
            &origin_spiffe,
            msg_type,
            ttl,
            timestamp_ns,
            &payload,
        );

        let signature = identity.sign(&canonical_bytes);

        Self {
            message_id,
            sender_id,
            origin_spiffe,
            msg_type,
            ttl,
            timestamp_ns,
            payload,
            signature_bytes: signature.to_bytes(),
        }
    }

    /// Verifies the cryptographic signature of the gossip envelope against sender public key.
    pub fn verify(&self, sender_vk: &VerifyingKeyWrapper) -> Result<()> {
        let canonical_bytes = Self::canonical_bytes(
            &self.message_id,
            &self.sender_id,
            &self.origin_spiffe,
            self.msg_type,
            self.ttl,
            self.timestamp_ns,
            &self.payload,
        );

        let sig = Signature::from_bytes(&self.signature_bytes);
        sender_vk.verify(&canonical_bytes, &sig)?;
        Ok(())
    }

    /// Decrements the envelope TTL for gossip relay; returns true if message is still live.
    pub fn decrement_ttl(&mut self) -> bool {
        if self.ttl > 0 {
            self.ttl -= 1;
            self.ttl > 0
        } else {
            false
        }
    }

    fn canonical_bytes(
        message_id: &Uuid,
        sender_id: &Uuid,
        origin_spiffe: &str,
        msg_type: GossipType,
        ttl: u8,
        timestamp_ns: i64,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(message_id.as_bytes());
        buf.extend_from_slice(sender_id.as_bytes());
        buf.extend_from_slice(origin_spiffe.as_bytes());
        buf.push(msg_type as u8);
        buf.push(ttl);
        buf.extend_from_slice(&timestamp_ns.to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }
}

/// Prioritized multi-tier queue with LRU deduplication cache for Pack gossip dispatch.
pub struct GossipQueue {
    queues: [VecDeque<GossipEnvelope>; 4],
    seen_cache: HashSet<Uuid>,
    seen_history: VecDeque<Uuid>,
    max_dedup_capacity: usize,
}

impl GossipQueue {
    /// Constructs a new gossip queue with specified deduplication window capacity.
    pub fn new(max_dedup_capacity: usize) -> Self {
        Self {
            queues: [
                VecDeque::new(), // Tier 0: Verdict & Policy
                VecDeque::new(), // Tier 1: Observation
                VecDeque::new(), // Tier 2: Health
                VecDeque::new(), // Tier 3: Topology
            ],
            seen_cache: HashSet::with_capacity(max_dedup_capacity),
            seen_history: VecDeque::with_capacity(max_dedup_capacity),
            max_dedup_capacity,
        }
    }

    /// Default queue sizing: 10,000 message deduplication window.
    pub fn default_pack() -> Self {
        Self::new(10_000)
    }

    /// Ingests an inbound gossip envelope; verifies signature and dedupes.
    /// Returns Ok(true) if admitted, Ok(false) if duplicate or expired TTL.
    pub fn ingress_envelope(
        &mut self,
        envelope: GossipEnvelope,
        sender_vk: &VerifyingKeyWrapper,
    ) -> Result<bool> {
        // Drop expired envelopes
        if envelope.ttl == 0 {
            return Ok(false);
        }

        // Deduplication check
        if self.seen_cache.contains(&envelope.message_id) {
            return Ok(false);
        }

        // Verify cryptographic signature
        envelope.verify(sender_vk)?;

        // Record in deduplication window
        self.record_seen(envelope.message_id);

        // Route into priority queue tier
        let tier = envelope.msg_type.priority_tier();
        self.queues[tier].push_back(envelope);

        Ok(true)
    }

    /// Enqueues a locally generated envelope directly into the outbound queue.
    pub fn enqueue_local(&mut self, envelope: GossipEnvelope) {
        self.record_seen(envelope.message_id);
        let tier = envelope.msg_type.priority_tier();
        self.queues[tier].push_back(envelope);
    }

    /// Pops the next highest priority message available across all tiers.
    pub fn pop_next(&mut self) -> Option<GossipEnvelope> {
        for queue in &mut self.queues {
            if let Some(msg) = queue.pop_front() {
                return Some(msg);
            }
        }
        None
    }

    /// Returns the total count of enqueued messages across all tiers.
    pub fn total_enqueued(&self) -> usize {
        self.queues.iter().map(|q| q.len()).sum()
    }

    /// Checks if a message ID has already been seen in the deduplication window.
    pub fn has_seen(&self, message_id: &Uuid) -> bool {
        self.seen_cache.contains(message_id)
    }

    fn record_seen(&mut self, message_id: Uuid) {
        if self.seen_history.len() >= self.max_dedup_capacity {
            if let Some(evicted_id) = self.seen_history.pop_front() {
                self.seen_cache.remove(&evicted_id);
            }
        }
        self.seen_cache.insert(message_id);
        self.seen_history.push_back(message_id);
    }
}
