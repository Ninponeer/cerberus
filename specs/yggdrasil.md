# Yggdrasil Component Specification

**The Memory Tree: Knowledge Graph of the Digital Forest**
**Not a management server. A living memory.**

---

## Responsibility Boundary

**Yggdrasil ONLY remembers. Yggdrasil NEVER decides. Yggdrasil NEVER enforces.**

| In Scope | Out of Scope |
|----------|--------------|
| Append-only knowledge graph storage | Threat detection |
| Graph queries (lineage, similarity, trust) | Consensus computation |
| Baseline computation & serving | Policy enforcement |
| Threat pattern library (MITRE mapping) | Agent orchestration |
| Audit log immutability | Real-time verdict emission |

---

## Graph Schema (Complete)

### Node Types

```cypher
// === CORE ENTITIES ===

(:Device {
  id: String,           // SPIFFE ID hash (primary key)
  hostname: String,
  fqdn: String,
  ips: [String],
  macs: [String],
  os: String,           // WINDOWS, LINUX, MACOS, CONTAINER, IOS, ANDROID, FIRMWARE
  os_version: String,
  role: String,         // WORKSTATION, SERVER, DC, DATABASE, IOT, NETWORK, CONTAINER_HOST
  tier: Int,            // 0=untrusted, 1=standard, 2=privileged, 3=critical
  trust_score: Float,   // 0.0 - 1.0 (PageRank on TRUSTS edges)
  first_seen: DateTime,
  last_seen: DateTime,
  status: String,       // ACTIVE, QUIESCENT, QUARANTINED, DECOMMISSIONED, COMPROMISED
  labels: [String],     // e.g., ["segment-a", "vlan-100", "windows", "workstation"]
  cert_fingerprint: String
})

(:User {
  id: String,           // UPN hash (primary key)
  upn: String,
  sid: String,
  display_name: String,
  email: String,
  department: String,
  title: String,
  risk_score: Float,    // 0.0 - 1.0 (behavioral deviation + threat intel)
  behavioral_baseline: Map,  // JSON: typical hours, apps, network, volume
  first_seen: DateTime,
  last_seen: DateTime,
  status: String,       // ACTIVE, SUSPENDED, COMPROMISED, SERVICE_ACCOUNT
  groups: [String],     // AD groups, Entra ID roles
  labels: [String]
})

(:Process {
  id: String,           // Composite: device_id + pid + create_time (or container_id)
  device_id: String,    // → Device
  user_id: String,      // → User
  pid: Int,
  ppid: Int,
  exe_path: String,
  exe_hash_sha256: String,
  cmdline: String,
  parent_exe_hash: String,
  integrity_level: String,  // LOW, MEDIUM, HIGH, SYSTEM, UNTRUSTED
  mitre_techniques: [String],  // e.g., ["T1059.001", "T1003"]
  first_seen: DateTime,
  last_seen: DateTime,
  status: String,       // RUNNING, TERMINATED, INJECTED, SUSPICIOUS
  labels: [String]
})

(:NetworkFlow {
  id: String,           // UUID
  src_device_id: String,  // → Device
  dst_device_id: String,  // → Device
  src_ip: String,
  src_port: Int,
  dst_ip: String,
  dst_port: Int,
  protocol: String,     // TCP, UDP, ICMP, ESP, etc.
  direction: String,    // INBOUND, OUTBOUND, LATERAL, NORTH_SOUTH
  bytes_sent: Long,
  bytes_recv: Long,
  packets_sent: Long,
  packets_recv: Long,
  start_time: DateTime,
  end_time: DateTime,
  ja3: String,
  ja3s: String,
  sni: String,
  labels: [String]
})

// === OBSERVATION & VERDICT ===

(:Observation {
  id: String,           // UUID (primary key)
  agent_id: String,     // → Device (Pack agent)
  timestamp: DateTime,
  type: String,         // ANOMALY, BEHAVIORAL_DEVIATION, INDICATOR_MATCH, ATTACK_CHAIN_LINK
  confidence: Float,    // 0.0 - 1.0
  classification: String,  // Free-text + MITRE tags
  evidence: Map,        // JSON: raw events, features, context
  signature: String,    // Ed25519 hex
  labels: [String]
})

(:Verdict {
  id: String,           // UUID (primary key)
  timestamp: DateTime,
  correlation_id: String,
  participating_nodes: [String],  // → Device (Pack agents)
  confidence: Float,    // 0.0 - 1.0
  classification: String,  // BENIGN, SUSPICIOUS, PROBABLE, CONFIRMED
  threat_class: String,    // LATERAL_MOVEMENT, CREDENTIAL_THEFT, PERSISTENCE, EXFIL, etc.
  evidence_trail: [String],  // → Observation
  recommended_actions: [Map],  // JSON array of action specs
  rationale: String,     // Human-readable explanation
  garmr_instance: String,  // → Device (Garmr node)
  signature: String,     // Ed25519 hex
  labels: [String]
})

(:Action {
  id: String,           // UUID (primary key)
  verdict_id: String,   // → Verdict (empty for Shepherd override)
  timestamp: DateTime,
  type: String,         // NETWORK_ISOLATE, CREDENTIAL_SUSPEND, MICROSEGMENT, DECOY_ACTIVATE, TRAFFIC_REDIRECT
  target: Map,          // JSON: device/user/process/network selector
  parameters: Map,      // JSON: action-specific params
  status: String,       // PENDING, EXECUTING, SUCCEEDED, FAILED, PARTIAL, ROLLED_BACK
  result: Map,          // JSON: ActionResult details
  preservation: Map,    // JSON: EvidencePreservation details
  rollback: Map,        // JSON: RollbackInfo details
  orthrus_instance: String,  // → Device (Orthrus node)
  shepherd_override: Boolean,
  shepherd_operator: String,  // → User (if override)
  signature: String,    // Ed25519 hex
  labels: [String]
})

// === THREAT INTELLIGENCE ===

(:ThreatPattern {
  id: String,           // UUID (primary key)
  name: String,
  description: String,
  mitre_techniques: [String],  // Ordered chain
  signatures: [Map],    // JSON: detection signatures (YARA, Sigma, behavioral)
  confidence_base: Float,  // Prior confidence for this pattern
  first_observed: DateTime,
  last_observed: DateTime,
  source: String,       // HUGIN, MANUAL, COMMUNITY, VENDOR
  labels: [String]
})

(:ThreatActor {
  id: String,           // UUID
  name: String,         // e.g., "APT29", "FIN7", "LOCKBIT"
  aliases: [String],
  motivation: String,   // ESPIONAGE, FINANCIAL, HACKTIVISM, DESTRUCTION
  sophistication: String,  // LOW, MEDIUM, HIGH, ADVANCED
  origin: String,       // Country/region attribution
  known_patterns: [String],  // → ThreatPattern
  first_seen: DateTime,
  last_seen: DateTime,
  labels: [String]
})

// === BASELINE & TRUST ===

(:BehavioralBaseline {
  id: String,           // entity_type + entity_id + window
  entity_type: String,  // DEVICE, USER, PROCESS
  entity_id: String,
  window_start: DateTime,
  window_end: DateTime,
  features: Map,        // JSON: statistical profile (mean, std, percentiles)
  sample_count: Long,
  labels: [String]
})

(:TrustScore {
  id: String,           // device_id (primary key)
  device_id: String,
  score: Float,         // 0.0 - 1.0
  components: Map,      // JSON: {accuracy: 0.9, tenure: 0.8, attestation: 1.0, ...}
  computed_at: DateTime,
  version: Int
})
```

### Edge Types

```cypher
// === OBSERVATION RELATIONSHIPS ===

(:Observation)-[:OBSERVED_ON {confidence: Float}]->(:Device)
(:Observation)-[:OBSERVED_BY {confidence: Float}]->(:User)
(:Observation)-[:OBSERVED_IN {confidence: Float}]->(:Process)
(:Observation)-[:CORRELATES_TO {strength: Float, technique: String}]->(:Observation)
(:Observation)-[:MATCHES_PATTERN {confidence: Float}]->(:ThreatPattern)

// === VERDICT RELATIONSHIPS ===

(:Verdict)-[:DERIVES_FROM {weight: Float}]->(:Observation)
(:Verdict)-[:CLASSIFIES_AS]->(:ThreatPattern)
(:Verdict)-[:TRIGGERS]->(:Action)
(:Verdict)-[:ATTRIBUTED_TO {confidence: Float}]->(:ThreatActor)

// === ACTION RELATIONSHIPS ===

(:Action)-[:EXECUTED_ON]->(:Device)
(:Action)-[:EXECUTED_FOR]->(:User)
(:Action)-[:EXECUTED_IN]->(:Process)
(:Action)-[:ROLLBACK_OF]->(:Action)

// === ENTITY RELATIONSHIPS ===

(:Device)-[:RUNS {pid: Int, start: DateTime}]->(:Process)
(:User)-[:OWNS {session: String, start: DateTime}]->(:Process)
(:Process)-[:SPAWNED {pid: Int, time: DateTime}]->(:Process)
(:Process)-[:INJECTED_INTO {technique: String}]->(:Process)
(:Device)-[:CONNECTED_TO {protocol: String, port: Int, bytes: Long}]->(:Device)
(:User)-[:LOGGED_ONTO {session: String, start: DateTime, end: DateTime}]->(:Device)
(:User)-[:MEMBER_OF]->(:User)  // Group membership
(:Device)-[:MEMBER_OF]->(:Device)  // Segment/VLAN membership

// === TRUST & SIMILARITY ===

(:Device)-[:TRUSTS {weight: Float, basis: String}]->(:Device)  // basis: ATTESTATION, HISTORY, PEER
(:User)-[:TRUSTS {weight: Float, basis: String}]->(:User)
(:Device)-[:RESEMBLES {score: Float, features: [String]}]->(:Device)  // Behavioral similarity
(:User)-[:RESEMBLES {score: Float, features: [String]}]->(:User)

// === THREAT LINEAGE ===

(:ThreatPattern)-[:PRECEDES {probability: Float, count: Int}]->(:ThreatPattern)
(:ThreatPattern)-[:VARIANT_OF {similarity: Float}]->(:ThreatPattern)
(:ThreatActor)-[:USES {frequency: Float}]->(:ThreatPattern)
(:ThreatActor)-[:TARGETS {sector: String, confidence: Float}]->(:Device)
```

---

## Storage Backend

### Primary: Apache AGE (PostgreSQL Extension)
- **Why:** ACID, SQL + Cypher, mature ecosystem, horizontal read scaling
- **Deployment:** Patroni cluster (3+ nodes), async replicas for read
- **Schema:** `cerberus` namespace, partitioned by time (monthly)

### Alternative: Neo4j Enterprise
- **Why:** Native graph, better traversal performance, Bloom visualization
- **Tradeoff:** Licensing, single-writer (causal clustering for HA)

### Tiered Storage
| Tier | Data | Retention | Storage | Access Pattern |
|------|------|-----------|---------|----------------|
| **Hot** | Last 30 days (Observations, Verdicts, Actions, Flows) | 30d | NVMe SSD, replicated | Real-time queries, dashboards |
| **Warm** | 30d - 1 year (all nodes/edges) | 1yr | SSD, erasure-coded | Investigations, hunting |
| **Cold** | 1yr - 7yr (aggregated, sampled) | 7yr | Object storage (S3/MinIO) | Compliance, long-term trends |

### Partitioning Strategy
```sql
-- Observations partitioned by month
CREATE TABLE cerberus.observation (
  id UUID,
  agent_id UUID,
  timestamp TIMESTAMPTZ,
  -- ... other columns
) PARTITION BY RANGE (timestamp);

CREATE TABLE cerberus.observation_2026_01 PARTITION OF cerberus.observation
  FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');

-- Indexes
CREATE INDEX ON cerberus.observation (agent_id, timestamp DESC);
CREATE INDEX ON cerberus.observation USING GIN (evidence jsonb_path_ops);
CREATE INDEX ON cerberus.observation (type, confidence DESC);
```

---

## API Contracts

### gRPC Service (Primary)
```protobuf
service Yggdrasil {
  // === MUTATIONS (Append-only) ===
  rpc IngestObservations(ObservationBatch) returns (IngestResult);
  rpc IngestVerdicts(VerdictBatch) returns (IngestResult);
  rpc IngestActions(ActionBatch) returns (IngestResult);
  rpc UpsertDevice(Device) returns (Device);
  rpc UpsertUser(User) returns (User);
  rpc UpsertProcess(Process) returns (Process);
  rpc UpsertNetworkFlow(NetworkFlowBatch) returns (IngestResult);
  rpc UpsertThreatPattern(ThreatPattern) returns (ThreatPattern);
  rpc UpsertThreatActor(ThreatActor) returns (ThreatActor);
  rpc UpdateTrustScores(TrustScoreBatch) returns (IngestResult);
  rpc UpdateBaselines(BaselineBatch) returns (IngestResult);

  // === QUERIES ===
  rpc QueryCypher(CypherQuery) returns (stream CypherResult);
  rpc GetLineage(LineageRequest) returns (stream LineagePath);
  rpc GetSimilarEntities(SimilarityRequest) returns (stream SimilarEntity);
  rpc GetBaseline(BaselineRequest) returns (Baseline);
  rpc GetTrustScore(TrustScoreRequest) returns (TrustScore);
  rpc GetThreatPatterns(PatternRequest) returns (stream ThreatPattern);
  rpc SearchThreatActors(ActorRequest) returns (stream ThreatActor);

  // === SUBSCRIPTIONS (Real-time) ===
  rpc SubscribeObservations(SubscriptionFilter) returns (stream Observation);
  rpc SubscribeVerdicts(SubscriptionFilter) returns (stream Verdict);
  rpc SubscribeActions(SubscriptionFilter) returns (stream Action);
  rpc SubscribeTrustScores(SubscriptionFilter) returns (stream TrustScore);
}
```

### GraphQL API (Secondary, for UI/Exploration)
```graphql
type Query {
  # Entity lookup
  device(id: ID!): Device
  user(id: ID!): User
  process(id: ID!): Process
  
  # Graph traversal
  lineage(
    from: ID!
    to: ID
    maxDepth: Int = 5
    edgeTypes: [String!]
  ): [LineagePath!]!
  
  similarEntities(
    entity: ID!
    type: EntityType!
    limit: Int = 10
    minScore: Float = 0.7
  ): [SimilarEntity!]!
  
  # Threat intel
  threatPatterns(
    mitreTechnique: String
    search: String
    limit: Int = 50
  ): [ThreatPattern!]!
  
  threatActor(name: String!): ThreatActor
  
  # Analytics
  trustScore(device: ID!): TrustScore
  baseline(entity: ID!, type: EntityType!, window: Duration): Baseline
  
  # Aggregations
  verdictStats(
    from: DateTime!
    to: DateTime!
    groupBy: [String!]
  ): [StatBucket!]!
}

type Subscription {
  observations(filter: SubscriptionFilter): Observation!
  verdicts(filter: SubscriptionFilter): Verdict!
  actions(filter: SubscriptionFilter): Action!
}
```

---

## Baseline Computation

### Scheduled Jobs (Airflow/Temporal)

| Job | Schedule | Input | Output |
|-----|----------|-------|--------|
| `compute_device_baselines` | Hourly | NetworkFlow, Process, Observation (last 14d) | BehavioralBaseline (DEVICE) |
| `compute_user_baselines` | Hourly | Auth, Process, NetworkFlow (last 14d) | BehavioralBaseline (USER) |
| `compute_trust_scores` | 15min | Verdict accuracy, attestation, tenure | TrustScore (DEVICE) |
| `detect_baseline_drift` | Daily | Current vs. previous baselines | Drift alerts → Hugin |
| `update_threat_patterns` | Daily | Hugin feed, Verdicts, Community | ThreatPattern (new/updated) |

### Baseline Features (Device)
```json
{
  "process_exec_rate": {"mean": 12.3, "std": 5.1, "p99": 45},
  "network_connect_rate": {"mean": 156, "std": 89, "p99": 890},
  "dns_query_rate": {"mean": 450, "std": 200, "p99": 2000},
  "unique_destinations": {"mean": 45, "std": 20, "p99": 180},
  "rare_ports_accessed": {"count": 3, "ports": [135, 445, 3389]},
  "unsigned_binary_exec": {"count": 2, "hashes": ["...", "..."]},
  "typical_hours": [8,9,10,11,12,13,14,15,16,17],
  "typical_processes": ["explorer.exe", "chrome.exe", "outlook.exe", "teams.exe"],
  "typical_destinations": ["10.0.0.0/8", "172.16.0.0/12", "office365.com"]
}
```

---

## Trust Score Algorithm

```
TrustScore(d) = PageRank(TRUSTS graph, personalization=d) × AttestationWeight(d) × TenureWeight(d)

Where:
  - TRUSTS graph edges: weight ∈ [0,1], basis ∈ {ATTESTATION, HISTORY, PEER}
  - AttestationWeight: 1.0 (TPM/TEE), 0.7 (Cloud), 0.5 (JoinToken), 0.1 (None)
  - TenureWeight: min(1.0, days_since_first_seen / 90)
  - PageRank: α=0.85, max_iter=50, tolerance=1e-6
  - Personalization: restart vector = 1.0 for target device, 0 else

Output: Normalized to [0.1, 1.0] (0.1 = probation floor)
```

---

## Configuration Schema

```yaml
yggdrasil:
  database:
    primary: "postgresql://postgres:pass@pg-primary:5432/cerberus?sslmode=verify-full"
    replicas:
      - "postgresql://postgres:pass@pg-replica-1:5432/cerberus?sslmode=verify-full"
      - "postgresql://postgres:pass@pg-replica-2:5432/cerberus?sslmode=verify-full"
    pool_size: 100
    max_overflow: 20
    pool_timeout: 30
  
  storage_tiers:
    hot:
      retention_days: 30
      tablespace: "pg_nvme"
    warm:
      retention_days: 365
      tablespace: "pg_ssd"
    cold:
      retention_days: 2555  # 7 years
      bucket: "s3://cerberus-yggdrasil-cold"
      format: "parquet"
      compression: "zstd"
  
  graph:
    age_namespace: "cerberus"
    cypher_timeout_ms: 30000
    max_path_depth: 10
    similarity_vector_dim: 256
  
  api:
    grpc:
      listen: "0.0.0.0:50051"
      max_message_size_mb: 64
      keepalive_ms: 10000
    graphql:
      listen: "0.0.0.0:8080"
      playground: true
      complexity_limit: 1000
    rest:
      listen: "0.0.0.0:8081"
      openapi: true
  
  auth:
    spiffe_trust_domain: "cerberus.local"
    allowed_audiences:
      - "cerberus-fenrir"
      - "cerberus-garmr"
      - "cerberus-orthrus"
      - "cerberus-pack"
      - "cerberus-shepherd"
  
  jobs:
    scheduler: "temporal"  # or "airflow"
    temporal_namespace: "cerberus"
    baseline_window_days: 14
    trust_recompute_interval_min: 15
    drift_threshold: 0.3  # KL divergence
  
  backup:
    schedule: "0 2 * * *"  # Daily 02:00 UTC
    retention: 30
    destination: "s3://cerberus-backups/yggdrasil"
    encryption: "AES-256-GCM"
    verify_restore: true
```

---

## Query Patterns (Optimized)

### 1. Lineage Walk (Attack Chain)
```cypher
// Given Observation ID, find full attack chain to Verdict
MATCH path = (o:Observation {id: $obs_id})-[:CORRELATES_TO*1..5]-(v:Verdict)
WHERE all(r IN relationships(path) WHERE r.strength > 0.5)
RETURN path
ORDER BY length(path), reduce(s=0, r IN relationships(path) | s + r.strength) DESC
LIMIT 10;
```

### 2. Behavioral Similarity (k-NN)
```cypher
// Find devices behaviorally similar to compromised device
MATCH (d:Device {id: $device_id})-[:RESEMBLES]-(similar:Device)
WHERE similar.trust_score > 0.5 AND similar.status = 'ACTIVE'
RETURN similar.id, similar.hostname, similar.trust_score,
       [(d)-[:RESEMBLES]-(similar) | properties(r).score] AS similarity
ORDER BY similarity DESC
LIMIT 20;
```

### 3. Threat Hunt (MITRE Technique)
```cypher
// All devices with observations matching T1003 (Credential Dumping) in last 24h
MATCH (d:Device)-[:OBSERVED_ON]-(o:Observation)
WHERE o.timestamp > datetime() - duration('P1D')
  AND 'T1003' IN o.evidence.mitre_techniques
  AND o.confidence > 0.6
RETURN d.id, d.hostname, d.trust_score, count(o) AS obs_count, max(o.confidence) AS max_conf
ORDER BY max_conf DESC, obs_count DESC;
```

### 4. Trust Propagation
```cypher
// Compute trust for new device based on peers
MATCH (new:Device {id: $new_device_id})
MATCH (peer:Device)-[:TRUSTS {basis: 'PEER'}]->(new)
WHERE peer.trust_score > 0.7
WITH peer, peer.trust_score * 0.5 AS contribution
RETURN sum(contribution) AS propagated_trust;
```

---

## Testing Requirements

| Test | Description |
|------|-------------|
| `test_ingest_observation_batch` | 10k observations → ingested < 5s, queryable |
| `test_ingest_verdict_batch` | 1k verdicts → ingested, triggers Orthrus webhook |
| `test_lineage_walk_depth` | 5-hop chain → returns in < 500ms |
| `test_similarity_knn` | 10k devices → k-NN < 1s (with vector index) |
| `test_trust_score_pagerank` | 100k nodes → converges < 30s |
| `test_baseline_computation` | 14d data → baseline computed < 10min |
| `test_partition_tolerance` | Primary down → replica serves reads, writes queue |
| `test_cold_storage_retrieval` | 1yr old data → restored from S3, queryable |
| `test_backup_restore` | Full restore → data integrity verified |
| `test_concurrent_ingest` | 50 clients × 1k/sec → no deadlocks, no data loss |

---

## Open Questions

- **AQ-Y01:** AGE vs. Neo4j: final decision criteria (cost, performance, team expertise)?
- **AQ-Y02:** Vector similarity: pgvector vs. external (Milvus, Qdrant) vs. AGE native?
- **AQ-Y03:** Temporal vs. Airflow for job orchestration: team standard?
- **AQ-Y04:** Graph partition strategy: by time, by segment, by entity type?
- **AQ-Y05:** Schema evolution: migration strategy for node/edge property changes?
- **AQ-Y06:** Real-time subscriptions: gRPC streaming vs. Kafka/CDC outbox pattern?
- **AQ-Y07:** Multi-tenancy: single graph with labels vs. separate databases?

---

**Status:** Draft (awaiting ratification)
**Owner:** Yggdrasil Team
**Depends On:** All components (ingestion), Hugin (threat patterns), Shepherd (audit)