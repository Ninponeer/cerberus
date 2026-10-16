//! HyParView peer routing table and state management for Cerberus Pack.

use crate::beacon::DiscoveryBeacon;
use cerberus_core::crypto::VerifyingKeyWrapper;
use cerberus_core::error::{CerberusError, Result};
use cerberus_core::identity::{SpiffeId, TrustDomain};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use uuid::Uuid;

/// Lifecycle state of a peer node in the swarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerState {
    /// Discovered via beacon or static config; not yet cryptographically authenticated.
    Discovered,
    /// Currently undergoing mutual authentication challenge-response.
    Handshaking,
    /// Cryptographically verified and actively participating in pack operations.
    Authenticated,
    /// Experiencing packet loss or degraded latency (> 1000ms).
    Degraded,
    /// Heartbeat timed out; slated for eviction or passive demotion.
    Stale,
}

/// A remote peer endpoint in the Cerberus Pack swarm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerNode {
    pub node_id: Uuid,
    pub name: String,
    pub spiffe_id: SpiffeId,
    pub endpoint: SocketAddr,
    pub verifying_key_bytes: [u8; 32],
    pub cert_fingerprint: Option<String>,
    pub trust_score: f64,
    pub state: PeerState,
    pub latency_ms: u64,
    pub last_seen: DateTime<Utc>,
    pub consecutive_failures: u32,
}

impl PeerNode {
    /// Creates a new peer instance from a verified discovery beacon.
    pub fn from_beacon(beacon: &DiscoveryBeacon) -> Self {
        let trust_domain = TrustDomain::cerberus_local();
        let spiffe_id = SpiffeId::new(&trust_domain, &format!("pack/node/{}", beacon.node_id));

        Self {
            node_id: beacon.node_id,
            name: beacon.name.clone(),
            spiffe_id,
            endpoint: beacon.endpoint,
            verifying_key_bytes: beacon.verifying_key_bytes,
            cert_fingerprint: None,
            trust_score: 0.1, // Initial probation weight per Cerberus specification
            state: PeerState::Discovered,
            latency_ms: 0,
            last_seen: Utc::now(),
            consecutive_failures: 0,
        }
    }

    /// Verifying key wrapper for this peer.
    pub fn verifying_key(&self) -> Result<VerifyingKeyWrapper> {
        VerifyingKeyWrapper::from_bytes(&self.verifying_key_bytes)
    }

    /// Updates peer heartbeat and measured latency.
    pub fn record_heartbeat(&mut self, latency_ms: u64) {
        self.last_seen = Utc::now();
        self.latency_ms = latency_ms;
        self.consecutive_failures = 0;
        if self.state == PeerState::Degraded || self.state == PeerState::Stale {
            self.state = PeerState::Authenticated;
        }
    }

    /// Records a failed connection attempt or missed heartbeat.
    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= 5 {
            self.state = PeerState::Stale;
        } else if self.consecutive_failures >= 3 {
            self.state = PeerState::Degraded;
        }
    }
}

/// HyParView peer tracking structure maintaining active and passive peer views.
#[derive(Debug, Clone)]
pub struct PeerView {
    pub active_view: HashMap<Uuid, PeerNode>,
    pub passive_view: HashMap<Uuid, PeerNode>,
    pub max_active: usize,
    pub max_passive: usize,
}

impl PeerView {
    /// Constructs a new HyParView routing table with specified capacity bounds.
    pub fn new(max_active: usize, max_passive: usize) -> Self {
        Self {
            active_view: HashMap::with_capacity(max_active),
            passive_view: HashMap::with_capacity(max_passive),
            max_active,
            max_passive,
        }
    }

    /// Default HyParView dimensions per Cerberus specification: 12 active, 24 passive.
    pub fn default_pack() -> Self {
        Self::new(12, 24)
    }

    /// Ingests a verified discovery beacon into the peer routing table.
    pub fn upsert_beacon(&mut self, beacon: &DiscoveryBeacon) -> Result<()> {
        let node_id = beacon.node_id;

        // If peer is already in active view, refresh endpoint and heartbeat
        if let Some(peer) = self.active_view.get_mut(&node_id) {
            peer.endpoint = beacon.endpoint;
            peer.record_heartbeat(0);
            return Ok(());
        }

        // If peer is in passive view, refresh metadata
        if let Some(peer) = self.passive_view.get_mut(&node_id) {
            peer.endpoint = beacon.endpoint;
            peer.record_heartbeat(0);
            return Ok(());
        }

        // Newly discovered peer: if active view has space, add directly; otherwise add to passive view
        let peer = PeerNode::from_beacon(beacon);
        if self.active_view.len() < self.max_active {
            self.active_view.insert(node_id, peer);
        } else if self.passive_view.len() < self.max_passive {
            self.passive_view.insert(node_id, peer);
        } else {
            // Evict oldest or stalest passive peer to make room
            if let Some(oldest_id) = self.find_oldest_passive_peer() {
                self.passive_view.remove(&oldest_id);
                self.passive_view.insert(node_id, peer);
            }
        }

        Ok(())
    }

    /// Marks a peer as cryptographically authenticated and promotes it to the active view.
    pub fn mark_authenticated(
        &mut self,
        node_id: &Uuid,
        cert_fingerprint: &str,
        latency_ms: u64,
    ) -> Result<()> {
        // Find peer in active or passive view
        let mut peer = if let Some(p) = self.active_view.remove(node_id) {
            p
        } else if let Some(p) = self.passive_view.remove(node_id) {
            p
        } else {
            return Err(CerberusError::Validation(format!(
                "Node {} not found in active or passive peer tables",
                node_id
            )));
        };

        peer.state = PeerState::Authenticated;
        peer.cert_fingerprint = Some(cert_fingerprint.to_string());
        peer.record_heartbeat(latency_ms);

        // If active view is full, demote an active peer to passive view
        if self.active_view.len() >= self.max_active {
            if let Some(demote_id) = self.find_lowest_scoring_active_peer() {
                if let Some(mut demoted) = self.active_view.remove(&demote_id) {
                    demoted.state = PeerState::Discovered;
                    if self.passive_view.len() >= self.max_passive {
                        if let Some(oldest_passive) = self.find_oldest_passive_peer() {
                            self.passive_view.remove(&oldest_passive);
                        }
                    }
                    self.passive_view.insert(demote_id, demoted);
                }
            }
        }

        self.active_view.insert(*node_id, peer);
        Ok(())
    }

    /// Records a heartbeat for an active peer.
    pub fn record_heartbeat(&mut self, node_id: &Uuid, latency_ms: u64) -> bool {
        if let Some(peer) = self.active_view.get_mut(node_id) {
            peer.record_heartbeat(latency_ms);
            true
        } else if let Some(peer) = self.passive_view.get_mut(node_id) {
            peer.record_heartbeat(latency_ms);
            true
        } else {
            false
        }
    }

    /// Records a failure for a peer, automatically demoting stale nodes.
    pub fn record_failure(&mut self, node_id: &Uuid) {
        if let Some(peer) = self.active_view.get_mut(node_id) {
            peer.record_failure();
            if peer.state == PeerState::Stale {
                if let Some(stale_peer) = self.active_view.remove(node_id) {
                    if self.passive_view.len() < self.max_passive {
                        self.passive_view.insert(*node_id, stale_peer);
                    }
                    self.promote_passive_to_active();
                }
            }
        } else if let Some(peer) = self.passive_view.get_mut(node_id) {
            peer.record_failure();
        }
    }

    /// Prunes stale peers that have exceeded the timeout threshold.
    pub fn prune_stale(&mut self, timeout: Duration) {
        let cutoff = Utc::now() - timeout;

        // Prune active peers that have timed out
        let timed_out_active: Vec<Uuid> = self
            .active_view
            .iter()
            .filter(|(_, peer)| peer.last_seen < cutoff)
            .map(|(id, _)| *id)
            .collect();

        for id in timed_out_active {
            if let Some(mut peer) = self.active_view.remove(&id) {
                peer.state = PeerState::Stale;
                if self.passive_view.len() < self.max_passive {
                    self.passive_view.insert(id, peer);
                }
            }
        }

        // Prune passive peers that have timed out
        self.passive_view.retain(|_, peer| peer.last_seen >= cutoff);

        // Fill vacancies in active view
        self.promote_passive_to_active();
    }

    /// Fills active view vacancies from healthy passive view candidates.
    pub fn promote_passive_to_active(&mut self) {
        while self.active_view.len() < self.max_active && !self.passive_view.is_empty() {
            if let Some(candidate_id) = self.find_best_passive_candidate() {
                if let Some(mut candidate) = self.passive_view.remove(&candidate_id) {
                    candidate.state = PeerState::Handshaking;
                    self.active_view.insert(candidate_id, candidate);
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    fn find_oldest_passive_peer(&self) -> Option<Uuid> {
        self.passive_view
            .iter()
            .min_by_key(|(_, peer)| peer.last_seen)
            .map(|(id, _)| *id)
    }

    fn find_lowest_scoring_active_peer(&self) -> Option<Uuid> {
        self.active_view
            .iter()
            .min_by(|(_, a), (_, b)| {
                a.trust_score
                    .partial_cmp(&b.trust_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(id, _)| *id)
    }

    fn find_best_passive_candidate(&self) -> Option<Uuid> {
        self.passive_view
            .iter()
            .filter(|(_, p)| p.state != PeerState::Stale)
            .max_by_key(|(_, peer)| peer.last_seen)
            .map(|(id, _)| *id)
    }
}
