# Garmr Component Specification

**Head II: The Sentinel**
**Rune:** Tiwaz (ᛏ) - Judgment

---

## Responsibility Boundary

**Garmr ONLY judges. Garmr NEVER collects raw telemetry. Garmr NEVER enforces.**

| In Scope | Out of Scope |
|----------|--------------|
| Observation ingestion (from Fenrir nodes) | Raw telemetry collection |
| Entity correlation (user, host, process, network) | Model inference |
| Consensus quorum assembly | Direct enforcement action |
| Confidence scoring (Bayesian) | Policy distribution |
| Verdict emission (to Yggdrasil + Orthrus) | Pack agent management |

---

## Interface Contracts

### Input: Observation Stream (from Fenrir via Pack Messenger)
```protobuf
message ObservationBatch {
  string batch_id = 1;
  string source_agent = 2;
  int64 received_ns = 3;
  repeated Observation observations = 4;
}
```

### Output: Verdict Record
```protobuf
message Verdict {
  string verdict_id = 1;
  int64 timestamp_ns = 2;
  string correlation_id = 3;
  repeated string participating_nodes = 4;
  float confidence = 5;  // 0.0 - 1.0
  Classification classification = 6;
  repeated string evidence_trail = 7;  // Observation IDs
  repeated RecommendedAction recommended_actions = 8;
  string rationale = 9;  // Human-readable, structured
  bytes signature = 10;  // Ed25519
}

enum Classification {
  BENIGN = 0;
  SUSPICIOUS = 1;
  PROBABLE = 2;
  CONFIRMED = 3;
}

message RecommendedAction {
  ActionType type = 1;
  map<string, string> parameters = 2;
  float urgency = 3;  // 0.0 - 1.0
}

enum ActionType {
  NETWORK_ISOLATE = 1;
  CREDENTIAL_SUSPEND = 2;
  MICROSEGMENT = 3;
  DECOY_ACTIVATE = 4;
  TRAFFIC_REDIRECT = 5;
  ENHANCED_MONITORING = 6;
  FORENSIC_CAPTURE = 7;
}
```

---

## Consensus Protocol (Detailed)

### Phase 1: Ingestion & Validation
```
For each Observation in batch:
  1. Verify Ed25519 signature (public key from SPIFFE identity)
  2. Validate schema (protobuf)
  3. Check replay protection (observation_id seen? → drop)
  4. Enrich: resolve agent_id → trust_score (from Yggdrasil cache)
  5. Deduplicate: semantic hash of evidence → existing correlation?
```

### Phase 2: Correlation Engine
```
Entity Resolution:
  - User: UPN/SID + behavioral baseline fingerprint
  - Host: hostname + MAC + certificate fingerprint
  - Process: exe hash + cmdline template + parent chain
  - Network: 5-tuple + JA3/JA3S + direction

Temporal Clustering:
  - Sliding window: 5 min (configurable)
  - Min observations per cluster: 3
  - Max cluster span: 30 min

Attack Chain Stitching:
  - MITRE ATT&CK technique chaining (T1003 → T1080 → T1021)
  - Precedence graph: Observation A PRECEDES Observation B
  - Confidence propagation: edge weight = min(conf_A, conf_B) * correlation_strength
```

### Phase 3: Quorum Assembly
```
Quorum Requirements:
  - Minimum distinct agents: 3
  - Minimum weighted agreement: 66%
  - Trust weight: node.trust_score ∈ [0.1, 1.0]
    * New nodes (probation): 0.1
    * Calibrated nodes: 0.5 - 1.0
    * Compromised/suspicious: 0.0 (excluded)

Voting:
  Each agent votes: {classification, confidence}
  Weighted tally → consensus classification
  
  If no quorum: → SUSPICIOUS (escalate monitoring, no Orthrus trigger)
  If quorum: → proceed to Confidence Scoring
```

### Phase 4: Confidence Scoring (Bayesian)
```
Prior P(Threat):
  = EnvironmentalBaseline(entity) × ThreatIntelEnrichment(indicators)
  EnvironmentalBaseline: from Yggdrasil (historical false positive rate per entity/type)
  ThreatIntelEnrichment: Hugin feed match → multiplier (1.0 - 3.0)

Likelihood P(Evidence | Threat):
  = ∏ [ weight_i × observation_confidence_i × source_trust_i ]
  weight_i: technique-specific (e.g., credential abuse = 1.5, DNS anomaly = 0.8)

Posterior = Prior × Likelihood / Evidence
  → Normalized to [0.0, 1.0]

Thresholds:
  < 0.40  → BENIGN
  0.40-0.65  → SUSPICIOUS
  0.65-0.85  → PROBABLE
  ≥ 0.85  → CONFIRMED
```

### Phase 5: Verdict Emission
```
1. Construct Verdict protobuf
2. Sign with Garmr instance key (Ed25519)
3. Write to Yggdrasil (append-only)
4. If confidence ≥ 0.65: push to Orthrus (gRPC stream)
5. If confidence ≥ 0.40: push enhanced monitoring policy to Pack
6. Emit metrics: verdicts_total{classification}, confidence_histogram
```

---

## State Management

| State | Storage | Consistency |
|-------|---------|-------------|
| Active correlation clusters | In-memory (LRU, 10k max) | Single-node (leader) |
| Node trust scores | Yggdrasil cache (Redis/Valkey) | Eventually consistent |
| Verdict history (recent) | Local RocksDB | Append-only |
| Consensus round state | In-memory | Ephemeral |

---

## High Availability

- **Leader election:** Raft (per segment): single leader for correlation/quorum
- **Standby replicas:** Hot standby, sync correlation state via Raft log
- **Cross-segment:** Hierarchical: regional Garmr → global Garmr (for multi-segment attacks)
- **Failover:** < 5s (Raft election + state replay)

---

## Configuration Schema

```yaml
garmr:
  consensus:
    min_agents: 3
    agreement_threshold: 0.66
    probation_weight: 0.1
    min_trust_for_vote: 0.3
  
  correlation:
    temporal_window_sec: 300
    min_observations_per_cluster: 3
    max_cluster_span_sec: 1800
    entity_resolution:
      user_fields: ["upn", "sid", "behavioral_fingerprint"]
      host_fields: ["hostname", "mac", "cert_fingerprint"]
      process_fields: ["exe_hash", "cmdline_template", "parent_chain"]
      network_fields: ["5tuple", "ja3", "ja3s", "direction"]
  
  confidence:
    thresholds:
      benign: 0.40
      suspicious: 0.65
      probable: 0.85
    technique_weights:
      credential_abuse: 1.5
      lateral_movement: 1.3
      injection: 1.2
      beaconing: 1.0
      dns_anomaly: 0.8
      binary_anomaly: 0.7
  
  yggdrasil:
    endpoint: "grpc://yggdrasil.cluster:50051"
    trust_cache_ttl_sec: 60
    baseline_cache_ttl_sec: 3600
  
  orthrus:
    endpoints:
      - "grpc://orthrus-1.segment-a:50051"
      - "grpc://orthrus-2.segment-a:50051"
    trigger_threshold: 0.65
  
  ha:
    raft_election_timeout_ms: 5000
    heartbeat_interval_ms: 1000
```

---

## Testing Requirements

| Test | Description |
|------|-------------|
| `test_quorum_formation` | 3+ agents, varied trust → verdict emitted |
| `test_quorum_failure` | 2 agents → SUSPICIOUS, no Orthrus trigger |
| `test_sybil_resistance` | 10 low-trust nodes vs 2 high-trust → high-trust wins |
| `test_correlation_chain` | T1003→T1080→T1021 observations → single correlation_id |
| `test_confidence_calibration` | Known FP/FN cases → confidence matches threshold |
| `test_partition_tolerance` | Network split → regional consensus continues |
| `test_leader_failover` | Leader killed → new leader < 5s, no verdict loss |
| `test_cross_segment` | Attack spans Segment A + B → global verdict |

---

## Open Questions

- **AQ-G01:** Hierarchical vs. flat consensus for cross-segment attacks?
- **AQ-G02:** Trust score algorithm: PageRank on TRUSTS edges vs. simple accuracy?
- **AQ-G03:** Observation deduplication: exact match vs. semantic (embedding)?
- **AQ-G04:** Real-time vs. batch correlation: latency vs. accuracy tradeoff?

---

**Status:** Draft (awaiting ratification)
**Owner:** Garmr Team
**Depends On:** Fenrir observation schema, Yggdrasil trust/baseline API, Orthrus action API