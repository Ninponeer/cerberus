# Orthrus Component Specification

**Head III: The Shepherd**
**Rune:** Eihwaz (ᛇ) - Defense / Endurance

---

## Responsibility Boundary

**Orthrus ONLY executes approved actions. Orthrus NEVER decides. Orthrus NEVER collects.**

| In Scope | Out of Scope |
|----------|--------------|
| Action execution (isolation, suspension, segmentation, decoys, redirect) | Threat detection |
| Action idempotency & rollback | Confidence scoring |
| Evidence preservation during response | Consensus participation |
| Audit logging to Yggdrasil | Policy authoring |
| Human override handling | Pack agent management |

---

## Interface Contracts

### Input: Action Directive (from Garmr or Shepherd Override)
```protobuf
message ActionDirective {
  string directive_id = 1;
  string verdict_id = 2;  // Empty for Shepherd override
  int64 timestamp_ns = 3;
  ActionType type = 4;
  TargetSelector target = 5;
  map<string, string> parameters = 6;
  float urgency = 7;  // 0.0 - 1.0
  bool requires_confirmation = 8;  // Shepherd override bypasses
  string rationale = 9;
  bytes garmr_signature = 10;  // Empty for Shepherd override
  bytes shepherd_signature = 11;  // Present for override
}

message TargetSelector {
  // Exactly one of:
  string device_id = 1;
  string user_id = 2;
  string process_id = 3;
  NetworkSelector network = 4;
  string group_tag = 5;  // e.g., "segment-a", "tier-1"
}

message NetworkSelector {
  string cidr = 1;
  int32 vlan = 2;
  string switch_id = 3;
}
```

### Output: Action Result
```protobuf
message ActionResult {
  string result_id = 1;
  string directive_id = 2;
  int64 started_ns = 3;
  int64 completed_ns = 4;
  ActionStatus status = 5;
  string details = 6;
  EvidencePreservation preservation = 7;
  RollbackInfo rollback = 8;
  bytes signature = 9;
}

enum ActionStatus {
  PENDING = 0;
  EXECUTING = 1;
  SUCCEEDED = 2;
  FAILED = 3;
  PARTIAL = 4;
  ROLLED_BACK = 5;
}

message EvidencePreservation {
  bool memory_captured = 1;
  bool disk_imaged = 2;
  bool netflow_captured = 3;
  bool logs_preserved = 4;
  string storage_location = 5;  // S3/MinIO path, signed URL
}

message RollbackInfo {
  bool reversible = 1;
  string rollback_procedure = 2;  // Human-readable steps
  map<string, string> rollback_parameters = 3;
  int64 expires_ns = 4;  // Auto-rollback deadline (0 = no auto)
}
```

---

## Action Catalog (Implementation Specs)

### 1. NETWORK_ISOLATE
**Purpose:** Quarantine device at network layer
**Targets:** Device, NetworkSelector (CIDR/VLAN)

```yaml
parameters:
  mode: "vlan" | "acl" | "host_firewall" | "switch_port"
  isolation_vlan: 999  # For VLAN mode
  deny_rules:
    - "0.0.0.0/0"  # Default deny all
  allow_rules: []  # Exception list (DNS, management)
  duration_sec: 0  # 0 = indefinite until rollback
  
preservation:
  - Mirror port capture (PCAP) 5 min before + during
  - NetFlow/IPFIX export continued
  - Host firewall logs forwarded
  
rollback:
  - Restore original VLAN/ACL/port config
  - Verify connectivity (ICMP/TCP to gateway)
  - TTL: 24h auto-rollback if not confirmed
```

**Idempotency:** Re-apply = verify current state matches desired, no-op if so

### 2. CREDENTIAL_SUSPEND
**Purpose:** Revoke authentication tokens, disable account
**Targets:** User, Device (for local creds)

```yaml
parameters:
  scope: "domain" | "local" | "cloud" | "all"
  actions:
    - "ad_disable"  # Disable AD account
    - "token_revoke"  # Revoke Kerberos/OAuth/JWT tokens
    - "session_kill"  # Terminate active sessions (RDP, SSH, VPN)
    - "password_reset"  # Force reset on next logon
  preserve_forensics: true  # Don't delete, disable only
  
preservation:
  - Export all auth logs (Security, 4624/4625/4768/4769)
  - Capture token artifacts (kirbi, ccache, JWT)
  - Memory dump of LSASS (if authorized)
  
rollback:
  - Re-enable AD account
  - Restore previous password hash (from backup)
  - Notify user (secure channel)
  - TTL: 4h auto-rollback if not confirmed
```

### 3. MICROSEGMENT
**Purpose:** Enforce zero-trust east-west policy
**Targets:** Group tag, NetworkSelector, Device

```yaml
parameters:
  policy_id: "cerberus-containment-<verdict_id>"
  default_action: "deny"
  rules:
    - src: "tag:quarantined"
      dst: "any"
      action: "deny"
      log: true
    - src: "tag:quarantined"
      dst: "tag:decoy"
      action: "allow"
      log: true
    - src: "tag:management"
      dst: "tag:quarantined"
      action: "allow"  # Forensic access
      log: true
  enforcement_point: "firewall" | "sase" | "host_agent" | "switch_acl"
  
preservation:
  - Full flow logs (allow + deny)
  - Policy change audit trail
  
rollback:
  - Delete containment policy
  - Restore previous policy version
  - Verify connectivity restored
  - TTL: 8h auto-rollback
```

### 4. DECOY_ACTIVATE
**Purpose:** Deploy honeytokens/decoys to engage attacker
**Targets:** Device, NetworkSelector, Group tag

```yaml
parameters:
  decoy_type: "filesystem" | "network" | "credential" | "process" | "registry"
  placement: "target_host" | "adjacent_host" | "decoy_segment"
  profile: "windows_workstation" | "linux_server" | "ad_controller" | "database"
  lure_data:
    - "fake_credentials.txt"
    - "ssh_keys/"
    - "config.yaml"
    - "backup.zip"
  monitoring:
    - file_access_alert
    - process_execution_alert
    - network_connection_alert
  
preservation:
  - All interaction logged (who, what, when, how)
  - Attacker tooling captured (if file dropped)
  - Network traffic to decoy mirrored
  
rollback:
  - Remove decoy artifacts
  - Disable decoy monitoring
  - Preserve interaction logs (never rolled back)
```

### 5. TRAFFIC_REDIRECT
**Purpose:** Sinkhole, proxy, or mirror suspicious traffic
**Targets:** NetworkSelector, Device

```yaml
parameters:
  mode: "dns_sinkhole" | "proxy_intercept" | "port_mirror" | "tcp_proxy"
  redirect_target: "sinkhole.local" | "proxy:8080" | "collector:443"
  protocols: ["dns", "http", "https", "smb", "rdp", "ssh"]
  tls_intercept: false  # Requires CA deployment
  
preservation:
  - Full PCAP of redirected traffic
  - TLS keys (if intercept authorized)
  - DNS query/response logs
  
rollback:
  - Restore original DNS/routing
  - Flush proxy connections
  - TTL: 1h auto-rollback
```

---

## Execution Engine

### Policy Language (OPA/Rego)
```rego
package cerberus.orthrus

# Input: { directive, target, context }
# Output: { allowed, actions, rollback }

default allow = false

allow {
  input.directive.garmr_signature != ""
  verify_signature(input.directive.garmr_signature, input.directive)
  input.directive.confidence >= 0.65
}

allow {
  input.directive.shepherd_signature != ""
  verify_signature(input.directive.shepherd_signature, input.directive)
  is_shepherd(input.directive.shepherd_identity)
}

# Action generation
actions[action] {
  allow
  action := generate_action(input.directive.type, input.target, input.directive.parameters)
}

# Rollback generation
rollback[rb] {
  allow
  rb := generate_rollback(input.directive.type, input.target, input.directive.parameters)
}
```

### Execution Guarantees

| Guarantee | Mechanism |
|-----------|-----------|
| **Idempotency** | Desired-state reconciliation; re-apply = converge |
| **Atomicity** | Per-target transaction log; compensation on failure |
| **Ordering** | Directed acyclic graph (DAG) of dependencies |
| **Observability** | Structured logs + metrics + Yggdrasil audit |
| **Reversibility** | Every action has defined rollback procedure |

---

## State Management

| State | Storage | Notes |
|-------|---------|-------|
| Active directives | In-memory + Raft log | Leader executes |
| Action results | Yggdrasil (append-only) | Immutable |
| Rollback procedures | Local filesystem (signed) | Versioned per action type |
| Target inventory | Yggdrasil cache + local | Refreshed per directive |

---

## Human Override (Shepherd Protocol)

```
Shepherd Override Flow:
  1. Operator: `shepherd override --verdict <id> --action <allow|deny|modify>`
  2. CLI: MFA challenge (WebAuthn/FIDO2)
  3. CLI: Signs override directive with operator key
  4. Orthrus: Verifies operator identity (SPIFFE: shepherd/cli/<operator>)
  5. Orthrus: Checks override policy (allow/deny/modify per classification)
  6. Orthrus: Executes or cancels per override
  7. Yggdrasil: Records override with full rationale + operator identity
  
Break-Glass (Emergency):
  - Pre-provisioned emergency keys (split custody, 2-of-3)
  - Logged as CRITICAL audit event
  - Auto-expires in 1 hour
  - Requires post-incident review
```

---

## Configuration Schema

```yaml
orthrus:
  execution:
    max_concurrent_actions: 50
    action_timeout_sec: 300
    retry_attempts: 3
    retry_backoff_sec: 5
  
  network_isolate:
    default_mode: "vlan"
    isolation_vlan: 999
    management_cidrs:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
    pcap_duration_sec: 300
  
  credential_suspend:
    default_scope: "domain"
    preserve_forensics: true
    memory_capture_authorized: false  # Requires separate approval
  
  microsegment:
    enforcement_points:
      - type: "firewall"
        api_endpoint: "https://fw-mgmt:443"
        credentials: "${FIREWALL_API_KEY}"
      - type: "host_agent"
        # Via Pack agent policy engine
  
  decoy:
    profiles_dir: "/opt/cerberus/decoys/profiles"
    artifact_store: "s3://cerberus-decoys/artifacts"
  
  traffic_redirect:
    sinkhole_domain: "sinkhole.cerberus.local"
    proxy_endpoint: "https://proxy.cerberus.local:8443"
    collector_endpoint: "grpc://collector:50051"
  
  shepherd_override:
    mfa_required: true
    allowed_operators: ["spiffe://cerberus.local/shepherd/cli/admin-*"]
    break_glass_keys:
      - "spiffe://cerberus.local/shepherd/breakglass/key-1"
      - "spiffe://cerberus.local/shepherd/breakglass/key-2"
      - "spiffe://cerberus.local/shepherd/breakglass/key-3"
    threshold: 2
  
  yggdrasil:
    endpoint: "grpc://yggdrasil.cluster:50051"
    audit_batch_size: 100
    audit_flush_interval_sec: 10
```

---

## Testing Requirements

| Test | Description |
|------|-------------|
| `test_network_isolate_idempotent` | Apply 2x → second is no-op, state verified |
| `test_credential_suspend_rollback` | Suspend → rollback → account functional, logs intact |
| `test_microsegment_policy` | Policy applied → east-west blocked, mgmt allowed, rollback restores |
| `test_decoy_activation` | Decoy deployed → access triggers alert, artifacts captured |
| `test_traffic_redirect_pcap` | Redirect → PCAP captured with full payload |
| `test_shepherd_override_allow` | Garmr says CONFIRMED, Shepherd denies → action cancelled |
| `test_shepherd_override_deny` | Garmr says SUSPICIOUS, Shepherd allows → action executed |
| `test_break_glass` | 2-of-3 keys → emergency action, audit CRITICAL |
| `test_action_dag` | Multiple actions with deps → correct order, rollback reverses |
| `test_evidence_preservation` | Every action → preservation artifacts created, signed, stored |

---

## Open Questions

- **AQ-O01:** Network enforcement point abstraction: vendor-specific vs. generic?
- **AQ-O02:** Memory capture authorization: separate workflow or embedded?
- **AQ-O03:** Decoy profile management: GitOps vs. API-driven?
- **AQ-O04:** TLS intercept for traffic_redirect: CA deployment model?
- **AQ-O05:** Rollback expiration: auto-rollback after TTL or manual only?

---

**Status:** Draft (awaiting ratification)
**Owner:** Orthrus Team
**Depends On:** Garmr verdict schema, Yggdrasil audit API, Pack policy engine, network infra APIs