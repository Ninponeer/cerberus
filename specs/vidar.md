# Vidar Component Specification

**The Reclaimer: Autonomous Purge, Exorcism & Subversion Engine**  
**Rune:** Dagaz (ᛞ) - Breakthrough / Dawn / Total Renewal; and Eihwaz (ᛇ) - Resilience  

---

## Responsibility Boundary

**Vidar ONLY cleanses, purges, and reclaims compromised nodes under Garmr consensus or Shepherd directive. Vidar NEVER initiates independent attacks.**

| In Scope | Out of Scope |
|----------|--------------|
| Deep malware and process lineage eradication | Initial threat detection (Fenrir's job) |
| Persistence vector removal (services, registry, cron, WMI) | Consensus deliberation (Garmr's job) |
| Immutable state rollback (ZFS/VSS snapshots, firmware PXE) | Perimeter network isolation (Orthrus's job) |
| Compromised node subversion (Honey-Puppet conversion) | Policy authoring (Pack's job) |
| Deception sandbox telemetry extraction & reverse pivoting | Destruction of forensics evidence |

---

## Interface Contracts

### Input: Reclamation Directive (from Orthrus or Shepherd)

```protobuf
message ReclamationDirective {
  string directive_id = 1;
  string target_node_id = 2;
  int64 timestamp_ns = 3;
  ReclamationStrategy strategy = 4;
  map<string, string> parameters = 5;
  bytes authorization_signature = 6;  // Garmr quorum or Shepherd Ed25519
}

enum ReclamationStrategy {
  STRATEGY_UNSPECIFIED = 0;
  SURGICAL_PURGE = 1;       // Process tree termination + persistence cleanup
  SNAPSHOT_ROLLBACK = 2;    // CoW filesystem / VSS rollback to clean checkpoint
  FIRMWARE_REFLASH = 3;     // Network PXE golden image write
  HONEY_PUPPET_TURN = 4;    // Subvert node into decoy tap and sandbox adversary C2
}
```

### Output: Reclamation Audit Record (to Yggdrasil)

```protobuf
message ReclamationAudit {
  string audit_id = 1;
  string directive_id = 2;
  string node_id = 3;
  int64 completed_at_ns = 4;
  bool success = 5;
  repeated string scrubbed_persistence_points = 6;
  string restored_checkpoint_hash = 7;
  DeceptionTapStatus decoy_status = 8;
  bytes vidar_signature = 9;
}

message DeceptionTapStatus {
  bool active = 1;
  string sinkhole_address = 2;
  uint64 captured_adversary_bytes = 3;
  repeated string intercepted_c2_endpoints = 4;
}
```

---

## Architectural Mechanics

### 1. The Surgical Purge (Exorcism)
When a node is compromised, Vidar executes a multi-phase hygiene protocol:
1. **Lineage Tree Freeze:** Traverses the kernel process tree via ETW / eBPF callbacks and suspends malicious thread groups before memory wiping.
2. **Persistence Scrub:** Enumerates and purges all known persistence vectors:
   - Windows: Registry Run/RunOnce keys, scheduled tasks, WMI event consumers, service binpaths, DLL hijack locations.
   - Linux: systemd service drop-ins, crontabs, `/etc/init.d/`, `/etc/rc.local`, shell profile hooks, authorized_keys modifications.
3. **Memory Unhooking:** Scans system DLLs and kernel dispatch tables against golden baseline binaries in Yggdrasil to detect inline hooks and unhook them.

### 2. Snapshot & Firmware Rollback
If surgical purge is insufficient:
- Reverts local block storage or container overlays to an immutable pre-incident snapshot verified against Yggdrasil's Merkle tree.
- For embedded routers and edge gateways (e.g. Heimdall, Cisco ASA), triggers network boot recovery to re-flash verified golden ROM images over Bifröst.

### 3. The Reclamation (Honey-Puppet Subversion)
Instead of alerting the adversary to discovery:
- **C2 Sinkholing:** Transparently diverts all command-and-control traffic from the compromised node into a local Cerberus Deception Proxy.
- **Canary Injection:** Generates high-entropy dynamic honeytokens (fake database strings, fake SSH private keys, decoy documents) to observe adversary exfiltration workflows.
- **Reverse Pivot:** Converts the compromised host into a high-fidelity observation post. Every keystroke, command, and dropped tool is ingested into Fenrir, weaponizing the adversary's own foothold for defense telemetry.

---

## Configuration Schema

```yaml
vidar:
  purge:
    preserve_memory_dump_before_kill: true
    max_scrub_depth: 10
    auto_rollback_on_purge_failure: true
  deception:
    default_sinkhole_port: 8443
    honeytoken_ttl_hours: 24
    telemetry_capture_level: "full_pcap_and_syscalls"
  safety:
    require_quorum_for_destructive_reflash: true
    min_snapshot_retention_count: 5
```
