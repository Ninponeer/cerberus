# Hati Component Specification

**The Shadow Hound: Adversary Emulation & Infiltration Engine**  
**Rune:** Nauthiz (ᚾ) - Need / Constraint; and Thurisaz (ᚦ) - The Reactive Thorn  

---

## Responsibility Boundary

**Hati ONLY probes, tests, and audits under explicit human authorization. Hati NEVER self-propagates. Hati NEVER acts autonomously.**

| In Scope | Out of Scope |
|----------|--------------|
| Automated Adversary Emulation (CART / BAS) | Autonomous un-scoped network propagation |
| Black-box asset probing & legacy protocol analysis | Unauthorized / un-scoped denial of service |
| Cognitive / context-aware credential auditing | Permanent destruction of host telemetry |
| Validation loop testing for Fenrir anomaly detection | Bypassing Shepherd operator signatures |
| Lateral movement and trust relationship pathfinding | Deployment outside signed target bounds |

---

## Interface Contracts

### Input: Strike Mandate (from Shepherd)

```protobuf
message StrikeMandate {
  string mandate_id = 1;
  int64 timestamp_ns = 2;
  int64 expires_at_ns = 3;
  TargetScope target_scope = 4;
  StrikeProfile profile = 5;
  RateConstraint rate_limits = 6;
  bytes shepherd_signature = 7;  // Ed25519 operator signature (required)
}

message TargetScope {
  repeated string target_ips = 1;      // e.g. ["10.20.0.1/32"]
  repeated string target_subnets = 2;
  repeated uint32 allowed_ports = 3;   // e.g. [443, 500, 4500]
  string excluded_cidr = 4;
}

message StrikeProfile {
  enum Mode {
    MODE_UNSPECIFIED = 0;
    RECON_ONLY = 1;           // Banner, TLS, port mapping, protocol audit
    CREDENTIAL_AUDIT = 2;     // Cognitive / Bayesian password testing
    VULN_VERIFY = 3;          // Known CVE exposure verification
    PURPLE_SIMULATION = 4;    // Synthetic attack chain to train Fenrir
  }
  Mode mode = 1;
  string target_fingerprint = 2;
  map<string, string> contextual_seeds = 3;
}

message RateConstraint {
  uint32 max_requests_per_second = 1;
  uint32 max_concurrency = 2;
  uint32 max_jitter_ms = 3;
  uint32 backoff_latency_threshold_ms = 4;
}
```

### Output: Strike Observation & Breach Report (to Yggdrasil & Fenrir)

```protobuf
message StrikeReport {
  string report_id = 1;
  string mandate_id = 2;
  string target_ip = 3;
  int64 timestamp_ns = 4;
  bool breach_successful = 5;
  BreachVector vector = 6;
  repeated string discovered_vulnerabilities = 7;
  map<string, string> captured_artifacts = 8;  // e.g. running-config, banners
  bytes hati_signature = 9;
}

enum BreachVector {
  VECTOR_UNSPECIFIED = 0;
  WEAK_CREDENTIAL = 1;
  LEGACY_CIPHER = 2;
  KNOWN_VULNERABILITY = 3;
  PROTOCOL_CONFUSION = 4;
  MISCONFIGURATION = 5;
}
```

---

## Architectural Mechanics

### 1. The Validation Loop (Purple Swarm)
Hati serves as the adversarial whetstone for Cerberus:
- When Hati executes an emulation against an internal asset, the Pack Watchers on that node emit events to Fenrir.
- Fenrir must classify Hati's probe as an anomaly with confidence >= 0.85.
- If Fenrir fails to detect Hati's reconnaissance, Fenrir generates a detection gap observation, updating its local inference weights via Yggdrasil.

### 2. Cognitive Credential Generation
Unlike brute-force tools that blindly spray wordlists:
- Hati ingests operator context seeds, target device class (e.g. Cisco ASA, embedded Linux, MIPS router), and temporal markers (e.g. system clock, firmware vintage).
- Generates probabilistic candidate trees combining vendor default idioms with contextual operator patterns.
- Applies latency-adaptive pacing to prevent CPU starvation on low-power legacy hardware (e.g. AMD Geode LX on ASA 5505).

### 3. The Leash Protocol
- Every strike mandate must verify against the Shepherd operator Ed25519 public key.
- Unsigned mandates or mandates with expired `expires_at_ns` timestamps are rejected immediately.
- Hati runs with target boundaries hardcoded into its network filter: requests outside `TargetScope` return fatal policy errors.

---

## Configuration Schema

```yaml
hati:
  execution:
    default_timeout_sec: 120
    max_active_mandates: 5
    telemetry_interval_ms: 250
  safety:
    require_shepherd_signature: true
    enforce_scope_boundaries: true
    max_concurrency_limit: 10
  pacing:
    default_rps: 5
    latency_headroom_ms: 150
```
