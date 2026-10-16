//! Cerberus Pack: The Distributed Swarm Defense Layer.
//!
//! Provides sovereign node identity, peer discovery beacons, HyParView routing,
//! zero-trust mutual authentication handshakes, and prioritized gossip messaging.

pub mod beacon;
pub mod crypto_serde;
pub mod gossip;
pub mod handshake;
pub mod identity;
pub mod peer;

pub use beacon::DiscoveryBeacon;
pub use gossip::{GossipEnvelope, GossipQueue, GossipType};
pub use handshake::{HandshakeAck, HandshakeChallenge, HandshakeProtocol, HandshakeResponse};
pub use identity::PackNodeIdentity;
pub use peer::{PeerNode, PeerState, PeerView};

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use std::net::SocketAddr;

    #[test]
    fn test_node_identity_and_mtls_cert_generation() {
        let identity = PackNodeIdentity::generate("sentinel-node-alpha").unwrap();
        assert_eq!(identity.name, "sentinel-node-alpha");
        assert!(identity.spiffe_id.to_string().starts_with("spiffe://cerberus.local/pack/node/"));

        // Generate self-signed mTLS certificate
        let (cert_pem, key_pem) = identity.generate_mtls_cert(30).unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));

        let fingerprint = PackNodeIdentity::compute_cert_fingerprint(&cert_pem);
        assert!(fingerprint.starts_with("sha256:"));

        // Verify signature
        let payload = b"threat-observation-payload";
        let sig = identity.sign(payload);
        let vk = identity.verifying_key();
        assert!(vk.verify(payload, &sig).is_ok());
    }

    #[test]
    fn test_discovery_beacon_signing_and_replay_rejection() {
        let identity = PackNodeIdentity::generate("edge-node-01").unwrap();
        let endpoint: SocketAddr = "10.0.1.50:50053".parse().unwrap();

        let beacon = DiscoveryBeacon::create_signed(&identity, endpoint).unwrap();
        assert_eq!(beacon.node_id, identity.node_id);
        assert_eq!(beacon.endpoint, endpoint);

        // Verification with valid 30s tolerance
        assert!(beacon.verify(Duration::seconds(30)).is_ok());

        // Replay rejection: simulated beacon from 1 hour ago
        let mut stale_beacon = beacon.clone();
        stale_beacon.timestamp_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0) - 3_600_000_000_000;
        let result = stale_beacon.verify(Duration::seconds(30));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds allowable replay tolerance"));

        // Tamper detection: modifying endpoint invalidates signature
        let mut tampered_beacon = beacon.clone();
        tampered_beacon.endpoint = "10.0.1.99:50053".parse().unwrap();
        assert!(tampered_beacon.verify(Duration::seconds(30)).is_err());
    }

    #[test]
    fn test_hyparview_peer_table_lifecycle() {
        let mut peer_view = PeerView::new(2, 4); // Small capacity for deterministic eviction tests

        let id1 = PackNodeIdentity::generate("node-1").unwrap();
        let id2 = PackNodeIdentity::generate("node-2").unwrap();
        let id3 = PackNodeIdentity::generate("node-3").unwrap();

        let b1 = DiscoveryBeacon::create_signed(&id1, "10.0.0.1:50053".parse().unwrap()).unwrap();
        let b2 = DiscoveryBeacon::create_signed(&id2, "10.0.0.2:50053".parse().unwrap()).unwrap();
        let b3 = DiscoveryBeacon::create_signed(&id3, "10.0.0.3:50053".parse().unwrap()).unwrap();

        peer_view.upsert_beacon(&b1).unwrap();
        peer_view.upsert_beacon(&b2).unwrap();
        assert_eq!(peer_view.active_view.len(), 2);
        assert_eq!(peer_view.passive_view.len(), 0);

        // Active view is full; 3rd node goes into passive view
        peer_view.upsert_beacon(&b3).unwrap();
        assert_eq!(peer_view.active_view.len(), 2);
        assert_eq!(peer_view.passive_view.len(), 1);

        // Mark node 3 authenticated; should promote to active and demote lowest scoring peer
        peer_view.mark_authenticated(&id3.node_id, "sha256:abc123cert", 15).unwrap();
        assert!(peer_view.active_view.contains_key(&id3.node_id));
        assert_eq!(peer_view.active_view.len(), 2);
        assert_eq!(peer_view.passive_view.len(), 1);

        // Record consecutive failures on node 3 -> should degrade and then stale
        for _ in 0..5 {
            peer_view.record_failure(&id3.node_id);
        }
        // Node 3 demoted to passive view; vacancy filled from passive view
        assert!(!peer_view.active_view.contains_key(&id3.node_id));
    }

    #[test]
    fn test_mutual_authentication_handshake() {
        let initiator = PackNodeIdentity::generate("initiator-hound").unwrap();
        let responder = PackNodeIdentity::generate("responder-sentinel").unwrap();

        let initiator_fp = "sha256:initiator-fingerprint-001";
        let responder_fp = "sha256:responder-fingerprint-002";

        // Step 1: Initiator generates challenge
        let (challenge, challenge_nonce) = HandshakeProtocol::create_challenge(&initiator);
        assert_eq!(challenge.initiator_id, initiator.node_id);

        // Step 2: Responder handles challenge and signs response
        let response = HandshakeProtocol::handle_challenge(
            &responder,
            &challenge,
            responder_fp,
            Duration::seconds(30),
        )
        .unwrap();

        // Step 3: Initiator verifies response and generates Ack
        let ack = HandshakeProtocol::handle_response(
            &initiator,
            &challenge_nonce,
            &response,
            &responder.verifying_key(),
            initiator_fp,
            Duration::seconds(30),
        )
        .unwrap();

        // Step 4: Responder verifies Ack
        let result = HandshakeProtocol::verify_ack(
            &ack,
            &response.responder_nonce,
            &initiator.verifying_key(),
            Duration::seconds(30),
        );
        assert!(result.is_ok());

        // Tamper test: tampered nonce in response is rejected
        let mut tampered_response = response.clone();
        tampered_response.challenge_nonce[0] ^= 0xFF;
        let tampered_res = HandshakeProtocol::handle_response(
            &initiator,
            &challenge_nonce,
            &tampered_response,
            &responder.verifying_key(),
            initiator_fp,
            Duration::seconds(30),
        );
        assert!(tampered_res.is_err());
    }

    #[test]
    fn test_prioritized_gossip_queue_and_deduplication() {
        let node = PackNodeIdentity::generate("gossip-relay").unwrap();
        let mut queue = GossipQueue::default_pack();

        // Create envelopes across different priority tiers
        let env_health = GossipEnvelope::create_signed(&node, GossipType::Health, b"health-ok".to_vec(), 3);
        let env_obs = GossipEnvelope::create_signed(&node, GossipType::Observation, b"beaconing-alert".to_vec(), 3);
        let env_verdict = GossipEnvelope::create_signed(&node, GossipType::Verdict, b"containment-verdict".to_vec(), 3);

        let vk = node.verifying_key();

        // Ingest out of order (Health first, Observation second, Verdict last)
        assert!(queue.ingress_envelope(env_health.clone(), &vk).unwrap());
        assert!(queue.ingress_envelope(env_obs.clone(), &vk).unwrap());
        assert!(queue.ingress_envelope(env_verdict.clone(), &vk).unwrap());

        assert_eq!(queue.total_enqueued(), 3);

        // Pop order MUST be Verdict (Priority 0) -> Observation (Priority 1) -> Health (Priority 2)
        let first = queue.pop_next().unwrap();
        assert_eq!(first.msg_type, GossipType::Verdict);

        let second = queue.pop_next().unwrap();
        assert_eq!(second.msg_type, GossipType::Observation);

        let third = queue.pop_next().unwrap();
        assert_eq!(third.msg_type, GossipType::Health);

        assert!(queue.pop_next().is_none());

        // Deduplication test: re-submitting an already seen envelope is dropped
        let admitted_again = queue.ingress_envelope(env_verdict, &vk).unwrap();
        assert!(!admitted_again);
        assert_eq!(queue.total_enqueued(), 0);
    }
}
