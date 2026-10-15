# Pack Component Specification

**The Swarm Layer: Every Endpoint a Watchdog**
**Collective:** "Many Eyes. One Pack. One Flock. Zero Trust Between Them."

---

## Responsibility Boundary

**Pack agents are the sensory and effector layer. They do not decide globally.**

| In Scope | Out of Scope |
|----------|--------------|
| Local telemetry collection (Watcher) | Global correlation |
| Gossip communication (Messenger) | Consensus authority |
| Consensus participation (Consensus Client) | Model training |
| Local policy enforcement (Policy Engine) | Cross-segment coordination |
| Health/heartbeat reporting | Verdict emission |

---

## Agent Architecture (Per Endpoint)

```
┌─────────────────────────────────────────────────────────────────┐
│                         PACK AGENT                                │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                        SUPERVISOR                            │ │
│  │  • Process lifecycle  • Health checks  • Config reload      │ │
│  │  • Crash recovery     • Metrics export   • Secret rotation  │ │
│  └────────────────────────────┬────────────────────────────────┘ │
│                               │                                  │
│   ┌───────────────┬───────────┼───────────┬───────────────┐     │
│   ▼               ▼           ▼           ▼               ▼     │
│ ┌─────────┐  ┌──────────┐ ┌────────┐ ┌──────────┐ ┌─────────┐  │
│ │ WATCHER │  │MESSENGER │ │CONSENSUS│ │ POLICY   │ │ IDENTITY│  │
│ │         │  │          │ │ CLIENT │ │ ENGINE   │ │  VAULT  │  │
│ └────┬────┘  └────┬─────┘ └────┬───┘ └────┬─────┘ └────┬────┘  │
│      │            │            │            │            │       │
│      └────────────┴────────────┴────────────┴────────────┘       │
│                               │                                  │
│                    ┌──────────┴──────────┐                       │
│                    │   LOCAL STATE STORE  │                       │
│                    │   (LMDB / RocksDB)   │                       │
│                    └──────────────────────┘                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 1. Watcher: Telemetry Collection

### Supported Sources

| Platform | Mechanism | Events |
|----------|-----------|--------|
| **Windows** | ETW (real-time), Sysmon (14.x), Kernel Callbacks (PsSetCreateProcessNotifyRoutine, etc.), WMI | Process, Network, DNS, File, Registry, Image Load, Thread, Auth |
| **Linux** | eBPF (CO-RE), Auditd, Netlink, Fanotify | Process, Network, DNS, File, Cred, Socket, BPF_MAP |
| **macOS** | EndpointSecurity, OpenBSM, NetworkExtension | Process, Network, File, Auth |
| **Containers** | CRI-O/containerd shim, eBPF (cgroup), Falco rules | Container lifecycle, exec, network, file |
| **Network** | NetFlow/IPFIX, sFlow, SPAN/TAP (via collector) | Flow records, metadata |

### Event Schema (Canonical)
```protobuf
message TelemetryEvent {
  string event_id = 1;           // UUID v7 (time-ordered)
  string agent_id = 2;           // SPIFFE ID hash
  int64 timestamp_ns = 3;        // Nanoseconds since epoch
  EventType type = 4;
  Platform platform = 5;         // WINDOWS, LINUX, MACOS, CONTAINER
  bytes payload = 6;             // Type-specific (see below)
  map<string, string> tags = 7;  // Enrichment: MITRE, host info, etc.
}

message ProcessCreate {
  int32 pid = 1;
  int32 ppid = 2;
  string exe_path = 3;
  string cmdline = 4;
  string user_sid = 5;
  string session_id = 6;
  bytes exe_hash_sha256 = 7;
  bytes parent_exe_hash = 8;
  string integrity_level = 9;
  map<string, string> env_vars = 10;  // Filtered (no secrets)
}

message NetworkConnect {
  string src_ip = 1;
  int32 src_port = 2;
  string dst_ip = 3;
  int32 dst_port = 4;
  string protocol = 5;  // TCP, UDP, ICMP
  int32 pid = 6;
  string process_exe = 7;
  string ja3 = 8;       // TLS fingerprint
  string ja3s = 9;      // Server hello fingerprint
  int64 bytes_sent = 10;
  int64 bytes_recv = 11;
}

message DnsQuery {
  string query = 1;
  int32 qtype = 2;       // A, AAAA, TXT, MX, etc.
  string response = 3;   // Empty if pending
  int32 rcode = 4;       // NXDOMAIN, NOERROR, etc.
  int32 pid = 5;
  string process_exe = 6;
  string server_ip = 7;
}
```

### Collection Policies
```yaml
watcher:
  windows:
    etw_providers:
      - "{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}"  # Microsoft-Windows-Kernel-Process
      - "{9B1E0F53-0F64-43A4-981A-0D383B0A2B41}"  # Microsoft-Windows-Kernel-Network
      - Sysmon  # If installed
    kernel_callbacks: true
    wmi_polling: false  # Prefer push
  
  linux:
    ebpf_programs:
      - "process_exec"
      - "network_connect"
      - "dns_query"
      - "file_open"
      - "cred_access"
    auditd_rules: "/etc/audit/rules.d/cerberus.rules"
    netlink_groups: [1, 5, 9]  # NETLINK_KOBJECT_UEVENT, NETLINK_NETFILTER, NETLINK_AUDIT
  
  containers:
    cri_socket: "/run/containerd/containerd.sock"
    falco_rules: "/etc/falco/rules.d/cerberus.yaml"
  
  network:
    netflow:
      - collector: "10.0.1.50:2055"
        version: 10  # IPFIX
    sflow:
      - collector: "10.0.1.50:6343"
  
  output:
    fenrir_endpoint: "grpc://localhost:50052"  # Local Fenrir (sidecar)
    batch_size: 1000
    flush_interval_ms: 100
    backpressure:
      max_queue_mb: 256
      drop_policy: "oldest"  # or "newest", "random"
```

---

## 2. Messenger: Gossip Communication

### Protocol: HyParView (Hybrid Partial View)
- **Active view:** √N peers (configurable, default 12)
- **Passive view:** 2× active view
- **Shuffle interval:** 30s
- **Message types:** Observation, Verdict, Policy, Health, Topology

### Transport
```yaml
messenger:
  listen:
    - "quic://0.0.0.0:50053"  # Primary (mTLS)
    - "tcp://0.0.0.0:50054"   # Fallback
  peer_discovery:
    bootstrap_nodes:
      - "spiffe://cerberus.local/pack/agent/bootstrap-1"
      - "spiffe://cerberus.local/pack/agent/bootstrap-2"
    dns_sd: "_cerberus-pack._tcp.local"
    kubernetes:
      label_selector: "app=cerberus-pack"
  nat_traversal:
    stun_servers:
      - "stun.l.google.com:19302"
      - "stun.cloudflare.com:3478"
    turn_servers: []  # Optional, for restrictive NATs
  message_queues:
    observation: { priority: 1, max_size: 10000 }
    verdict: { priority: 0, max_size: 1000 }  # Highest
    policy: { priority: 0, max_size: 500 }
    health: { priority: 2, max_size: 100 }
    topology: { priority: 3, max_size: 100 }
```

### Message Formats
```protobuf
message GossipMessage {
  string message_id = 1;
  string sender_id = 2;
  int64 timestamp_ns = 3;
  MessageType type = 4;
  int32 ttl = 5;  // Hop limit
  bytes payload = 6;  // Type-specific
  bytes signature = 7;  // Ed25519
}

enum MessageType {
  OBSERVATION = 1;
  VERDICT = 2;
  POLICY_UPDATE = 3;
  HEALTH = 4;
  TOPOLOGY = 5;
  CONSENSUS_VOTE = 6;
  CONSENSUS_RESULT = 7;
}
```

---

## 3. Consensus Client: Garmr Participation

### Role
- Receives consensus vote requests from Garmr
- Evaluates local observations against request
- Votes with local confidence + trust weight
- Verifies consensus result signatures

### Vote Flow
```
Garmr → (gRPC) → Pack Consensus Client
  1. Receive VoteRequest { correlation_id, observations[], question }
  2. For each observation:
       - Verify signature
       - Check local cache (have we seen this?)
       - Compute local agreement (0.0-1.0)
  3. Aggregate → local_vote { classification, confidence }
  4. Sign vote with agent key
  5. Return VoteResponse
  6. Later: Receive ConsensusResult → verify → cache
```

### Configuration
```yaml
consensus_client:
  garmr_endpoints:
    - "grpc://garmr-1.segment-a:50051"
    - "grpc://garmr-2.segment-a:50051"
  vote_timeout_sec: 10
  local_evaluation:
    use_cached_observations: true
    cache_ttl_sec: 300
    min_observations_for_vote: 1
  trust_weight:  # Static (dynamic from Yggdrasil via policy)
    base: 0.5
    probation_multiplier: 0.2
```

---

## 4. Policy Engine: Local Enforcement

### Input Sources
1. **Orthrus directives** (via Messenger, priority 0)
2. **Garmr enhanced monitoring policies** (priority 1)
3. **Local static policies** (fallback, priority 2)
4. **Shepherd CLI direct commands** (priority 0, signed)

### Policy Format (OPA/Rego)
```rego
package cerberus.pack.policy

# Input: { action: { type, target, parameters }, context: { device, user, process } }

default allow = false
default actions = []

# Orthrus directives (highest priority)
allow {
  input.action.source == "orthrus"
  verify_orthrus_signature(input.action)
}

actions[action] {
  allow
  action := input.action
}

# Enhanced monitoring from Garmr
allow {
  input.action.source == "garmr"
  input.action.type == "enhanced_monitoring"
  verify_garmr_signature(input.action)
}

actions[action] {
  allow
  action := enhanced_monitoring_actions(input.action.parameters)
}

# Local fallback (offline mode)
allow {
  input.action.source == "local"
  input.action.type == "block_process"
  is_malicious_hash(input.action.parameters.hash)
}

actions[action] {
  allow
  action := local_block_action(input.action.parameters)
}

# Helpers
enhanced_monitoring_actions(params) = [
  {"type": "increase_telemetry", "target": params.target, "level": "verbose"},
  {"type": "capture_memory", "target": params.target, "trigger": "on_next_anomaly"}
]

local_block_action(params) = {
  "type": "block_process",
  "target": params.target,
  "parameters": {"hash": params.hash, "reason": "local_policy"}
}
```

### Enforcement Actions (Local)
| Action | Implementation |
|--------|----------------|
| `block_process` | Windows: AppLocker/WDAC; Linux: eBPF LSM; macOS: EndpointSecurity |
| `isolate_network` | Host firewall (netsh/nftables/pf) + notify Messenger |
| `capture_memory` | Windows: procdump/COM; Linux: gcore; macOS: lldb |
| `increase_telemetry` | Watcher config reload (verbose mode) |
| `suspend_credential` | Local cache purge + notify domain controller via Messenger |
| `execute_script` | Signed script execution (PowerShell/Bash) (audited) |

---

## 5. Identity Vault: SPIFFE/SPIRE Integration

### Certificate Lifecycle
```
┌─────────────────────────────────────────────────────────────┐
│                    SPIRE AGENT (Sidecar)                      │
│  • Attestation: TPM / TEE / Cloud Provider / Join Token      │
│  • X.509-SVID rotation: 1h TTL, 30min renew                  │
│  • JWT-SVID: 5min TTL, audience-scoped                       │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                    PACK AGENT IDENTITY VAULT                  │
│  • Stores: X.509-SVID, JWT-SVID, CA bundle                   │
│  • Provides: mTLS config for all outbound connections        │
│  • Signs: All outbound messages (Ed25519 derived from SVID)  │
│  • Verifies: All inbound messages                            │
└─────────────────────────────────────────────────────────────┘
```

### Configuration
```yaml
identity:
  spire_socket: "unix:///run/spire/sockets/agent.sock"
  svid_ttl_sec: 3600
  renew_before_sec: 1800
  jwt_audiences:
    - "cerberus-fenrir"
    - "cerberus-garmr"
    - "cerberus-orthrus"
    - "cerberus-yggdrasil"
    - "cerberus-pack"
  signing_key: "ed25519"  # Derived from X.509-SVID
  trust_domain: "cerberus.local"
```

---

## 6. Supervisor: Lifecycle Management

### State Machine
```
STOPPED → STARTING → HEALTHY ↔ DEGRADED → STOPPING → STOPPED
                    ↑          │
                    │          ▼
                    │      UNHEALTHY → RESTARTING → HEALTHY
                    │          │
                    └──────────┘ (max 3 restarts/5min)
```

### Health Checks
```yaml
supervisor:
  health_checks:
    - name: "watcher_alive"
      interval_sec: 10
      timeout_sec: 5
      command: "grpc_health_check fenrir:50052"
    - name: "messenger_connected"
      interval_sec: 15
      timeout_sec: 5
      check: "peer_count >= 3"
    - name: "identity_valid"
      interval_sec: 60
      timeout_sec: 10
      check: "svid_expiry > 300s"
    - name: "disk_space"
      interval_sec: 300
      threshold_pct: 80
    - name: "memory_usage"
      interval_sec: 60
      threshold_mb: 1024
  
  metrics:
    prometheus_port: 9090
    path: "/metrics"
  
  logging:
    level: "info"
    format: "json"
    output: "stdout"
    structured_fields: ["agent_id", "segment", "version"]
```

---

## Deployment

### Packaging
| Format | Target |
|--------|--------|
| MSI / NuGet | Windows (SCCM/Intune) |
| DEB / RPM / APK | Linux (Ansible/Apt/Yum/Dnf) |
| PKG / DMG | macOS (Jamf/Munki) |
| OCI Image | Containers (DaemonSet/K8s) |
| Raw binary + systemd | Air-gapped / custom |

### Installation
```bash
# Windows (PowerShell)
Invoke-WebRequest -Uri "https://cerberus.example.com/install.ps1" | Invoke-Expression
# → Installs to C:\Program Files\Cerberus\Pack\
# → Registers service "CerberusPack"
# → Configures SPIRE agent (if domain-joined)

# Linux (bash)
curl -fsSL https://cerberus.example.com/install.sh | sudo bash
# → Installs to /opt/cerberus/pack/
# → systemd unit: cerberus-pack.service
# → SPIRE agent via package manager

# Kubernetes
kubectl apply -f https://cerberus.example.com/manifests/pack-daemonset.yaml
# → DaemonSet with SPIRE agent sidecar
# → HostPath mounts for /proc, /sys, /var/log
```

---

## Configuration Schema (Complete)

```yaml
pack:
  agent:
    id: ""  # Auto-generated from SPIFFE ID
    segment: "auto"  # From network topology or config
    tags: []  # e.g., ["tier-1", "windows", "workstation"]
  
  watcher:
    # ... (see Watcher section)
  
  messenger:
    # ... (see Messenger section)
  
  consensus_client:
    # ... (see Consensus Client section)
  
  policy_engine:
    opa_bundle_path: "/opt/cerberus/pack/policies/bundle.tar.gz"
    orthrus_endpoint: "grpc://localhost:50055"  # Local Orthrus sidecar (optional)
    fallback_policies:
      - "/opt/cerberus/pack/policies/fallback.rego"
  
  identity:
    # ... (see Identity Vault section)
  
  supervisor:
    # ... (see Supervisor section)
  
  updates:
    channel: "stable"  # stable, beta, alpha
    check_interval_hours: 6
    auto_apply: false  # Requires Shepherd approval
    verify_signatures: true
```

---

## Testing Requirements

| Test | Description |
|------|-------------|
| `test_watcher_windows_etw` | Process create → event emitted < 100ms |
| `test_watcher_linux_ebpf` | Execve → event emitted < 50ms |
| `test_watcher_container` | Container exec → event with container metadata |
| `test_messenger_gossip` | 10 nodes → full mesh < 30s, message delivery > 99.9% |
| `test_messenger_nat` | Behind NAT → peer discovery via STUN/TURN |
| `test_consensus_vote` | Vote request → signed response < 5s |
| `test_policy_engine_orthrus` | Directive → local action executed, logged |
| `test_policy_engine_fallback` | No Garmr/Orthrus → local policy triggers |
| `test_identity_rotation` | SVID renew → all connections re-establish seamlessly |
| `test_supervisor_restart` | Crash → restart < 10s, state recovered |
| `test_update_verify` | Unsigned update → rejected, logged |

---

## Open Questions

- **AQ-P01:** eBPF CO-RE compatibility matrix: kernel versions supported?
- **AQ-P02:** Windows kernel callback vs. ETW: which as primary, which fallback?
- **AQ-P03:** MacOS EndpointSecurity entitlements: deployment friction?
- **AQ-P04:** Messenger peer count scaling: √N vs. fixed vs. adaptive?
- **AQ-P05:** Offline operation: how long can Pack operate without Garmr/Yggdrasil?
- **AQ-P06:** Resource limits: hard caps for CPU/memory/disk per platform?

---

**Status:** Draft (awaiting ratification)
**Owner:** Pack Team
**Depends On:** SPIRE deployment, Fenrir sidecar (or remote), Garmr endpoints, Orthrus sidecar (optional)