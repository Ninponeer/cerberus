# Cerberus Technical Specification v0.1

**Status:** Draft (Architecture Ratification Phase)
**Classification:** Research Initiative (Not a Product)

---

## 1. System Invariants (Non-Negotiable)

| Invariant | Description | Enforcement Layer |
|-----------|-------------|-------------------|
| **I-01** | No agent self-propagation | Pack deployment orchestrator |
| **I-02** | No autonomous offensive action | Orthrus policy engine (deny-by-default) |
| **I-03** | Human override authority | Shepherd CLI + API (highest privilege) |
| **I-04** | Consensus quorum before containment | Garmr consensus protocol |
| **I-05** | Full decision explainability | Yggdrasil audit log + Garmr rationale |

---

## 2. Component Specifications

### 2.1 Fenrir: The Hunter (Head I)

**Rune:** Algiz (ᚨ) - Protection / Vigilance
**Role:** Stateless threat discovery, behavioral analysis, anomaly detection, attack chain pathfinding

#### 2.1.1 Inputs
- Raw telemetry from Pack Watchers (process exec, network flows, DNS, auth events, file ops)
- Yggdrasil behavioral baselines (cached locally)
- Threat intel feeds (Project Hugin)

#### 2.1.2 Outputs
- **Observation Records**: Structured, signed, timestamped:
  ```json
  {
    "observation_id": "uuid",
    "agent_id": "pack-node-<hash>",
    "timestamp": "ISO8601",
    "type": "anomaly|behavioral|indicator|chain",
    "confidence": 0.0-1.0,
    "evidence": { ... },
    "yggdrasil_refs": ["node-uuid-1", "node-uuid-2"],
    "signature": "ed25519"
  }
  ```
- No enforcement actions. Ever.

#### 2.1.3 Detection Domains
| Domain | Indicators |
|--------|------------|
| **DNS Anomaly** | DGA, fast-flux, NXDOMAIN bursts, rare TLDs, entropy |
| **Binary Anomaly** | Unsigned, unknown hash, masquerading, memory-only, living-off-land |
| **Beaconing** | Periodic C2, jitter analysis, domain generation, protocol tunneling |
| **Process Injection** | Cross-process memory ops, thread hijacking, APC queue, ETW bypass |
| **Credential Abuse** | Pass-the-hash, token replay, Kerberos delegation, golden ticket |
| **Lateral Movement** | SMB/WMI/WinRM/PsExec, RDP traversal, container escape, trust abuse |

#### 2.1.4 Model Management
- Local inference only (ONNX/TFLite/llama.cpp GGUF)
- Model updates via signed artifacts from Yggdrasil (Rule 1 compliant)
- Federated learning rounds coordinated by Yggdrasil (opt-in, not autonomous)

---

### 2.2 Garmr: The Sentinel (Head II)

**Rune:** Tiwaz (ᛏ) - Judgment
**Role:** Verification, correlation, consensus, confidence scoring

#### 2.2.1 Consensus Protocol

```
┌────────────────────────────────────────────────────────────┐
│                    GAMR CONSENSUS FLOW                       │
└────────────────────────────────────────────────────────────┘

  Fenrir Observations (from multiple Pack nodes)
         │
         ▼
  ┌─────────────┐
  │  INGESTION  │  ← Deduplication, schema validation, signature verify
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │ CORRELATION │  ← Entity resolution (user, host, process, network)
  │   ENGINE    │     Temporal clustering, attack chain stitching
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │  QUORUM     │  ← Weighted voting by node trust score
  │  ASSEMBLY   │     Minimum quorum: 3 nodes, 66% agreement
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │  CONFIDENCE │  ← Bayesian update: prior + evidence likelihood
  │  SCORING    │     Output: 0.0-1.0 with evidence trail
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │  VERDICT    │  ← Structured decision record to Yggdrasil
  │  EMISSION   │     Triggers Orthrus if threshold exceeded
  └─────────────┘
```

#### 2.2.2 Quorum Rules
- **Minimum nodes:** 3 distinct Pack agents
- **Agreement threshold:** 66% weighted by trust score
- **Trust scoring:** Based on historical accuracy (Yggdrasil), hardware attestation, deployment tenure
- **Sybil resistance:** Hardware-bound identity (TPM/TEE), certificate pinning

#### 2.2.3 Confidence Scoring
```
Confidence = BayesianPosterior(prior, evidence_likelihood)

Prior = Environmental baseline (Yggdrasil) × Threat intel enrichment (Hugin)
Evidence = Σ (weighted_observation_i × source_trust_i)

Thresholds:
  0.00-0.40  → Benign / Noise (logged only)
  0.40-0.65  → Suspicious (enhanced monitoring, no action)
  0.65-0.85  → Probable (alert Shepherd, prep containment)
  0.85-1.00  → Confirmed (Orthrus containment authorized)
```

#### 2.2.4 Output: Verdict Record
```json
{
  "verdict_id": "uuid",
  "timestamp": "ISO8601",
  "correlation_id": "uuid",
  "participating_nodes": ["node-1", "node-2", "node-3"],
  "confidence": 0.88,
  "classification": "lateral_movement|credential_theft|persistence|exfil|...",
  "evidence_trail": ["obs-uuid-1", "obs-uuid-2", "obs-uuid-3"],
  "recommended_actions": ["isolate_network", "suspend_credential", "activate_decoy"],
  "rationale": "Human-readable explanation with evidence references",
  "signature": "ed25519"
}
```

---

### 2.3 Orthrus: The Shepherd (Head III)

**Rune:** Eihwaz (ᛇ) - Defense / Endurance
**Role:** Response, containment, recovery, evidence preservation

#### 2.3.1 Action Catalog

| Action | Description | Reversibility | Evidence Impact |
|--------|-------------|---------------|-----------------|
| **network_isolate** | VLAN/ACL quarantine, host firewall deny-all | ✅ Reversible | Preserves memory/disk |
| **credential_suspend** | AD disable, token revocation, Kerberos purge | ✅ Reversible | Preserves auth logs |
| **microsegment** | Zero-trust policy push, east-west block | ✅ Reversible | Full netflow capture |
| **decoy_activate** | Honeytoken/decoy deployment, lure engagement | ✅ Reversible | Attacker interaction logged |
| **traffic_redirect** | DNS sinkhole, proxy intercept, mirror port | ✅ Reversible | PCAP + metadata |

#### 2.3.2 Execution Guarantees
- **Idempotent:** Replay-safe (re-apply = no-op)
- **Auditable:** Every action logged to Yggdrasil with Garmr verdict reference
- **Reversible:** Rollback procedure defined per action type
- **Non-destructive:** Never wipes, encrypts, or destroys data

#### 2.3.3 Policy Engine
- Declarative policy (OPA/Rego or Cedar)
- Garmr verdict → policy evaluation → action set
- Human override: `shepherd override --verdict <id> --action <allow|deny|modify>`

---

### 2.4 The Pack: Swarm Layer

**Role:** Distributed sensing, gossip communication, local policy enforcement

#### 2.4.1 Agent Architecture (per endpoint)

```
┌────────────────────────────────────────────┐
│              PACK AGENT                      │
├────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ WATCHER  │  │MESSENGER │  │ CONSENSUS│  │
│  │          │  │          │  │  CLIENT  │  │
│  │• ETW     │  │• Gossip  │  │• Vote    │  │
│  │• Sysmon  │  │  (SWIM/  │  │  (weight │  │
│  │• eBPF    │  │   HyPar) │  │   by     │  │
│  │• Auditd  │  │• mTLS    │  │   trust) │  │
│  │• Kernel  │  │• NAT     │  │• Verify  │  │
│  │  callbacks│ │  traverse│  │  sigs    │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│       │             │             │        │
│       └─────────────┼─────────────┘        │
│                     ▼                      │
│            ┌──────────────┐                │
│            │ POLICY ENGINE│                │
│            │              │                │
│            │• Orthrus     │                │
│            │  directives  │                │
│            │• Local allow/│                │
│            │  deny lists  │                │
│            │• Fallback    │                │
│            │  (offline)   │                │
│            └──────────────┘                │
└────────────────────────────────────────────┘
```

#### 2.4.2 Gossip Protocol (Messenger)
- **Protocol:** HyParView (hybrid partial view): resilient, scalable
- **Transport:** mTLS over UDP (QUIC) + TCP fallback
- **NAT traversal:** ICE/STUN for cross-segment visibility
- **Message types:** Observation broadcast, verdict sync, policy update, health/heartbeat

#### 2.4.3 Trust Bootstrapping
1. **Deployment:** Orchestrator provisions agent + identity cert (short-lived, auto-rotate)
2. **Attestation:** TPM/TEE quote → Yggdrasil registration
3. **Probation:** New nodes observe only (weight = 0.1) for N verdicts
4. **Graduation:** Trust score calibrated by Garmr based on accuracy
5. **Revocation:** Compromise detection → immediate cert revocation + quarantine

---

### 2.5 Yggdrasil: The Memory Tree

**Role:** Append-only knowledge graph: behavioral lineage, trust, baselines, threat patterns

#### 2.5.1 Graph Schema

**Node Types:**
| Type | Properties | Example |
|------|------------|---------|
| `Device` | hostname, IP, MAC, OS, role, trust_score, last_seen | `Device{id:"ws-14", trust:0.92}` |
| `User` | UPN, SID, roles, risk_score, behavioral_baseline | `User{id:"jdoe", risk:0.15}` |
| `Process` | pid, exe, cmdline, parent, hashes, MITRE tags | `Process{id:"powershell.exe", tags:[T1059]}` |
| `NetworkFlow` | src, dst, proto, port, bytes, direction, timestamp | `Flow{src:ws-14, dst:svr-22, port:445}` |
| `Observation` | (from Fenrir) (linked to Device/User/Process) | `Obs{id:"obs-72", type:"beaconing", conf:0.78}` |
| `Verdict` | (from Garmr) (linked to Observations) | `Verdict{id:"ver-11", conf:0.88, class:"lateral"}` |
| `Action` | (from Orthrus) (linked to Verdict) | `Action{id:"act-5", type:"isolate", status:"applied"}` |
| `ThreatPattern` | MITRE ATT&CK mapping, signatures, lineage | `Pattern{id:"apt29-chain", technique:[T1003,T1080]}` |

**Edge Types:**
- `OBSERVED_ON` (Observation → Device/User/Process)
- `CORRELATES_TO` (Observation ↔ Observation)
- `DERIVES_FROM` (Verdict → Observations)
- `TRIGGERS` (Verdict → Action)
- `RESEMBLES` (Device ↔ Device, behavioral similarity)
- `PRECEDES` (ThreatPattern → ThreatPattern, temporal)
- `TRUSTS` (Device → Device, weighted)

#### 2.5.2 Storage Backend
- **Primary:** Apache AGE (PostgreSQL extension) or Neo4j: ACID, Cypher/Gremlin
- **Append-only:** Immutable nodes/edges; updates = new version nodes
- **Retention:** Hot (30d), Warm (1yr), Cold (7yr): tiered by access pattern
- **Replication:** Multi-master with conflict-free replicated data types (CRDTs) for trust scores

#### 2.5.3 Query Patterns
- **Lineage walk:** `MATCH (a:Observation)-[:CORRELATES_TO*]->(b:Verdict) RETURN path`
- **Behavioral similarity:** Vector embedding on behavioral baseline → k-NN in graph
- **Threat hunting:** `MATCH (d:Device)-[:OBSERVED_ON]->(o:Observation) WHERE o.confidence > 0.7`
- **Trust propagation:** PageRank-style on `TRUSTS` edges with decay

---

### 2.6 Hati: The Shadow Hound (Offensive Arm)

**Rune:** Nauthiz (ᚾ) - Need / Constraint; and Thurisaz (ᚦ) - The Reactive Thorn  
**Role:** Automated adversary emulation, black-box penetration probing, cognitive credential auditing, and continuous verification of Fenrir's detection models.

- **The Leashed Warhound:** Operates strictly under human-signed Ed25519 authorization tokens from Shepherd (`StrikeMandate`), bounded strictly to declared IP targets.
- **Cognitive Attack Modeling:** Infers target-specific credentials and configuration vulnerabilities using Bayesian and contextual LLM reasoning rather than brute force.
- **Purple Validation:** Probes internal assets to verify that Fenrir catches intrusions; detection gaps trigger automated weight tuning.
- **Reference Spec:** [hati.md](file:///C:/bitbucket/cerberus/specs/hati.md)

---

### 2.7 Vidar: The Reclaimer (Purge & Subversion)

**Rune:** Dagaz (ᛞ) - Dawn / Breakthrough; and Eihwaz (ᛇ) - Resilience  
**Role:** Deep autonomous remediation, persistence scrubbing, immutable snapshot rollback, and honeypot / turncoat subversion.

- **The Surgical Purge:** Eradicates malware process lineages, memory hooks, scheduled tasks, registry Run keys, systemd units, and re-flashes verified firmware over Bifröst/PXE.
- **The Turncoat (Honey-Puppet):** Transmutes compromised endpoints into active sovereign sensor taps, sinkholing adversary C2 traffic into deception sandboxes and harvesting enemy tools and lateral movement intelligence.
- **Reference Spec:** [vidar.md](file:///C:/bitbucket/cerberus/specs/vidar.md)

---

## 3. Communication & Security

### 3.1 Transport Security
- **All inter-component:** mTLS 1.3 (mutual auth, forward secrecy)
- **Certificate management:** SPIFFE/SPIRE: short-lived X.509, automatic rotation
- **Pack ↔ Garmr:** gRPC over mTLS
- **Pack ↔ Pack (gossip):** QUIC with mTLS
- **Yggdrasil API:** GraphQL over mTLS + JWT (short-lived, audience-scoped)

### 3.2 Identity Model
```
┌─────────────────────────────────────────┐
│         SPIFFE ID HIERARCHY             │
├─────────────────────────────────────────┤
│ spiffe://cerberus.local/                │
│   ├── fenrir/                           │
│   │     └── detector/<instance-id>      │
│   ├── garmr/                            │
│   │     ├── consensus/<instance-id>     │
│   │     └── correlation/<instance-id>   │
│   ├── orthrus/                          │
│   │     └── executor/<instance-id>      │
│   ├── hati/                             │
│   │     └── striker/<instance-id>       │
│   ├── vidar/                            │
│   │     └── reclaimer/<instance-id>     │
│   ├── pack/                             │
│   │     └── agent/<node-id>             │
│   ├── yggdrasil/                        │
│   │     ├── graph/<instance-id>         │
│   │     └── api/<instance-id>           │
│   └── shepherd/                         │
│         └── cli/<operator-id>           │
└─────────────────────────────────────────┘
```

---

## 4. Deployment Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                    MANAGEMENT PLANE (Air-gapped)                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │ Shepherd │  │  Yggdrasil│  │  Fenrir  │  │  Garmr   │        │
│  │   CLI    │  │  Cluster │  │  Model   │  │  Cluster │        │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │
└─────────────────────────────────────────────────────────────────┘
                              │ mTLS, controlled egress
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      DATA PLANE (Customer Network)              │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  Segment A  │  │  Segment B  │  │  Segment C  │   ...       │
│  │ (Workstn)   │  │ (Servers)   │  │ (IoT/OT)    │             │
│  │             │  │             │  │             │             │
│  │ ████████    │  │ ████████    │  │ ████████    │             │
│  │ █ PACK █    │  │ █ PACK █    │  │ █ PACK █    │             │
│  │ █ AGENT █   │  │ █ AGENT █   │  │ █ AGENT █   │             │
│  │ ████████    │  │ ████████    │  │ ████████    │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         │                │                │                     │
│         └────────────────┼────────────────┘                     │
│                          ▼                                     │
│              ┌─────────────────────┐                           │
│              │   GAMR REGIONAL     │  (Per-segment or         │
│              │   CONSENSUS NODES   │   cross-segment)         │
│              └─────────────────────┘                           │
└─────────────────────────────────────────────────────────────────┘
```

- **Management plane:** Operated by defender team, air-gapped from data plane
- **Data plane:** Customer-owned, Pack agents deployed via existing tooling (SCCM, Intune, Ansible, DaemonSet)
- **Regional Garmr:** Deployed per network segment for latency; cross-segment for global view

---

## 5. Research Branches: Technical Seeds

| Project | Technical Seed |
|---------|----------------|
| **Hugin** | STIX/TAXII ingestion → Yggdrasil `ThreatPattern` nodes; MITRE ATT&CK graph mapping |
| **Munin** | Behavioral embedding drift detection; long-term trend analysis on `Device`/`User` baselines |
| **Sköll** | Active hunt queries → Fenrir directed collection; hypothesis-driven telemetry |
| **Hati** | Graph neural nets on Yggdrasil → attack path probability; Monte Carlo simulation |
| **Heimdall** | Network flow aggregation (NetFlow/IPFIX) and edge bridge observation → `NetworkFlow` nodes; anomaly baselines |
| **Sleipnir** | QUIC-based gossip fabric; priority lanes (verdict > observation > heartbeat) |

---

## 6. Open Architectural Questions (Ratification Blockers)

| # | Question | Impact | Status |
|---|----------|--------|--------|
| **AQ-01** | Consensus latency bound for ransomware-speed threats | Containment SLA | ⬜ Open |
| **AQ-02** | Pack agent trust bootstrapping vs. Sybil resistance | Swarm integrity | ⬜ Open |
| **AQ-03** | Yggdrasil partition tolerance: local fallback policies | Availability | ⬜ Open |
| **AQ-04** | Fenrir model drift / federated learning orchestration | Detection efficacy | ⬜ Open |
| **AQ-05** | Orthrus action idempotency & rollback verification | Safety | ⬜ Open |
| **AQ-06** | Cross-segment Garmr consensus: hierarchical vs. flat | Scalability | ⬜ Open |
| **AQ-07** | Shepherd override protocol: break-glass vs. audit | Operational safety | ⬜ Open |

---

## 7. Ratification Checklist

- [ ] **Invariants I-01 through I-05** accepted as architectural axioms
- [ ] **Component boundaries** (Fenrir/Garmr/Orthrus/Pack/Yggdrasil) ratified
- [ ] **Consensus protocol** (quorum, trust weighting, confidence math) approved
- [ ] **Graph schema** (nodes, edges, query patterns) validated
- [ ] **Identity/transport model** (SPIFFE, mTLS, gossip) confirmed
- [ ] **Deployment topology** (management vs. data plane) aligned
- [ ] **Open questions** (AQ-01 through AQ-07) assigned owners + target dates

---

**Next Step:** Resolve AQ-01 through AQ-07 → produce v0.2 with concrete protocols → begin scaffolding `src/` implementations.