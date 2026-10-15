# Fenrir Component Specification

**Head I: The Hunter**
**Rune:** Algiz (ᚨ) - Protection / Vigilance

---

## Responsibility Boundary

**Fenrir ONLY discovers. Fenrir NEVER acts.**

| In Scope | Out of Scope |
|----------|--------------|
| Telemetry ingestion (ETW, Sysmon, eBPF, Auditd, kernel callbacks) | Any enforcement action |
| Behavioral inference (local ML models) | Network modification |
| Anomaly scoring (0.0-1.0) | Credential manipulation |
| Attack chain stitching (local) | Process termination |
| Observation emission (signed, structured) | Policy distribution |

---

## Interface Contracts

### Input: Pack Telemetry Stream
```protobuf
message TelemetryEvent {
  string event_id = 1;
  string agent_id = 2;
  int64 timestamp_ns = 3;
  EventType type = 4;
  bytes payload = 5;  // Schema varies by EventType
}

enum EventType {
  PROCESS_CREATE = 1;
  PROCESS_TERMINATE = 2;
  NETWORK_CONNECT = 3;
  NETWORK_ACCEPT = 4;
  DNS_QUERY = 5;
  DNS_RESPONSE = 6;
  FILE_CREATE = 7;
  FILE_MODIFY = 8;
  FILE_DELETE = 9;
  REGISTRY_SET = 10;
  IMAGE_LOAD = 11;
  THREAD_CREATE = 12;
  MEMORY_ALLOC = 13;
  AUTH_LOGON = 14;
  AUTH_LOGOFF = 15;
  KERNEL_CALLBACK = 16;
}
```

### Output: Observation Record
```protobuf
message Observation {
  string observation_id = 1;
  string agent_id = 2;
  int64 timestamp_ns = 3;
  ObservationType type = 4;
  float confidence = 5;  // 0.0 - 1.0
  Evidence evidence = 6;
  repeated string yggdrasil_refs = 7;
  bytes signature = 8;  // Ed25519 over canonical JSON
}

enum ObservationType {
  ANOMALY = 1;
  BEHAVIORAL_DEVIATION = 2;
  INDICATOR_MATCH = 3;
  ATTACK_CHAIN_LINK = 4;
}

message Evidence {
  map<string, string> fields = 1;  // Flexible key-value
  repeated TelemetryEvent raw_events = 2;
  map<string, float> feature_vector = 3;  // For model debugging
}
```

---

## Detection Modules (Pluggable)

| Module | Input | Primary Model | Fallback Models | Output |
|--------|-------|---------------|-----------------|--------|
| `dns_anomaly` | DNS_QUERY/RESPONSE | Isolation Forest (ONNX) | BitNet 1B (DGA reasoning) | ANOMALY / INDICATOR_MATCH |
| `binary_reputation` | IMAGE_LOAD, PROCESS_CREATE | Hash lookup + PE features (ONNX) | BitNet 1B (binary reasoning) | INDICATOR_MATCH |
| `beaconing_detector` | NETWORK_CONNECT (time-series) | BitNet 1B (sequence) | LSTM / Fourier + statistical | BEHAVIORAL_DEVIATION |
| `injection_detector` | MEMORY_ALLOC, THREAD_CREATE, KERNEL_CALLBACK | BitNet 3B (code reasoning) | Rule-based + graph NN | ANOMALY |
| `credential_abuse` | AUTH_LOGON, PROCESS_CREATE (lsass) | BitNet 1B (command reasoning) | Behavioral baseline + MITRE | ATTACK_CHAIN_LINK |
| `lateral_movement` | NETWORK_CONNECT (SMB/WMI/WinRM/RDP) | BitNet 1B (graph reasoning) | Graph traversal + rare-edge | ATTACK_CHAIN_LINK |

---

## Adaptive Inference Engine

### Endpoint Capability Detection
On startup, Fenrir probes the endpoint and classifies its **compute tier**:

| Tier | RAM Available | CPU Cores | GPU/NPU | Backends Enabled |
|------|---------------|-----------|---------|------------------|
| **T0 - Constrained** | < 2 GB | 1-2 | None | ONNX (classical), BitNet 1B (quantized) |
| **T1 - Standard** | 2-8 GB | 4-8 | Optional | ONNX, BitNet 1B-3B, GGUF 4-bit (≤7B) |
| **T2 - Enhanced** | 8-32 GB | 8-16 | GPU/NPU | All above + GGUF 4-bit (7B-30B), Candle |
| **T3 - Maximum** | > 32 GB | 16+ | GPU (CUDA/ROCm/Metal) | All backends, full precision, batch inference |

### Model Selection Policy (Per Detection Domain)
```yaml
# Resolved at startup based on tier
model_selection:
  dns_anomaly:
    T0: { backend: "onnx", model: "isolation_forest.onnx" }
    T1: { backend: "bitnet", model: "bitnet-dga-1b.bin", reason: "reasoning > entropy" }
    T2: { backend: "bitnet", model: "bitnet-dga-3b.bin" }
    T3: { backend: "gguf", model: "codellama-7b-dga.Q4_K_M.gguf" }
  
  beaconing_detector:
    T0: { backend: "bitnet", model: "bitnet-beacon-1b.bin", seq_len: 256 }
    T1: { backend: "bitnet", model: "bitnet-beacon-3b.bin", seq_len: 512 }
    T2: { backend: "gguf", model: "mistral-7b-beacon.Q4_K_M.gguf", seq_len: 1024 }
    T3: { backend: "gguf", model: "llama3-8b-beacon.Q4_K_M.gguf", seq_len: 2048 }
  
  injection_detector:
    T0: { backend: "bitnet", model: "bitnet-inject-1b.bin" }
    T1: { backend: "bitnet", model: "bitnet-inject-3b.bin" }
    T2: { backend: "gguf", model: "codellama-7b-inject.Q4_K_M.gguf" }
    T3: { backend: "gguf", model: "codellama-34b-inject.Q4_K_M.gguf" }
  
  credential_abuse:
    T0: { backend: "bitnet", model: "bitnet-cmd-1b.bin", seq_len: 128 }
    T1: { backend: "bitnet", model: "bitnet-cmd-3b.bin", seq_len: 256 }
    T2: { backend: "gguf", model: "codellama-7b-cmd.Q4_K_M.gguf", seq_len: 512 }
    T3: { backend: "gguf", model: "codellama-13b-cmd.Q4_K_M.gguf", seq_len: 1024 }
  
  lateral_movement:
    T0: { backend: "onnx", model: "graph_rare_edge.onnx" }
    T1: { backend: "bitnet", model: "bitnet-graph-1b.bin" }
    T2: { backend: "bitnet", model: "bitnet-graph-3b.bin" }
    T3: { backend: "gguf", model: "mistral-7b-graph.Q4_K_M.gguf" }
```

### Backend Priority Order (Per Tier)
```
T0: ONNX (classical) → BitNet (1.58-bit) → Rule-based
T1: BitNet (1.58-bit) → GGUF (4-bit, ≤7B) → ONNX → Rule-based
T2: GGUF (4-bit, 7B-30B) → BitNet (3B) → Candle → ONNX
T3: GGUF (full/4-bit, any) → Candle (GPU) → ONNX (GPU) → BitNet
```

---

## Local State

| State | Storage | TTL | Notes |
|-------|---------|-----|-------|
| Behavioral baselines (per user/host/process) | LMDB / RocksDB | 30d rolling | Updated via Yggdrasil sync |
| Model artifacts (ONNX/GGUF/BitNet) | Filesystem (signed) | Versioned | Verified at load, tier-indexed |
| Endpoint capability profile | Memory + config | Persistent | Re-evaluated on config change |
| Observation cache (recent, for correlation) | Ring buffer (memory) | 1hr | Flushed to Garmr |
| Yggdrasil baseline cache | SQLite / LMDB | 24h | Read-only, refreshed periodically |
| Active model handles | Memory | Runtime | Reference counted, hot-swappable |

---

## Model Management

### Update Flow (Rule 1 Compliant)
```
Yggdrasil (Management Plane)
       │
       ▼  Signed model artifact + manifest (cosign/sigstore) PER TIER
┌──────────────────┐
│  PACK AGENT      │  ← Verifies signature, checks version, matches tier
│  (Fenrir module) │
└────────┬─────────┘
         │
         ▼  Atomic swap per backend (new model loaded, old kept for rollback)
    Inference Engine (per backend)
```

### Tier-Aware Model Manifest
```json
{
  "version": "2026.10.13.01",
  "models": {
    "bitnet-beacon": {
      "1b": { "url": "s3://.../bitnet-beacon-1b.bin", "sha256": "...", "tiers": ["T0", "T1"], "seq_len": 512 },
      "3b": { "url": "s3://.../bitnet-beacon-3b.bin", "sha256": "...", "tiers": ["T1", "T2"], "seq_len": 1024 }
    },
    "gguf-beacon": {
      "7b-q4": { "url": "s3://.../mistral-7b-beacon.Q4_K_M.gguf", "sha256": "...", "tiers": ["T2", "T3"], "seq_len": 2048 },
      "8b-q4": { "url": "s3://.../llama3-8b-beacon.Q4_K_M.gguf", "sha256": "...", "tiers": ["T3"], "seq_len": 4096 }
    }
  }
}
```

### Federated Learning (Optional, Opt-In)
1. Yggdrasil coordinates FL round (sends global model hash per tier)
2. Pack nodes compute local gradients (differential privacy applied)
3. Gradients submitted to Yggdrasil (encrypted, aggregated per tier)
4. New global model signed and distributed to matching tiers

---

## Performance Targets (Per Tier)

| Metric | T0 (Constrained) | T1 (Standard) | T2 (Enhanced) | T3 (Maximum) |
|--------|------------------|---------------|---------------|--------------|
| Telemetry ingestion rate | ≥ 50k events/sec | ≥ 100k events/sec | ≥ 200k events/sec | ≥ 500k events/sec |
| Inference latency (p99) | ≤ 20ms | ≤ 10ms | ≤ 5ms | ≤ 2ms |
| Observation emission rate | ≤ 50/sec | ≤ 100/sec | ≤ 200/sec | ≤ 500/sec |
| Memory footprint | ≤ 256MB | ≤ 512MB | ≤ 2GB | ≤ 8GB |
| CPU (idle) | ≤ 1% | ≤ 2% | ≤ 3% | ≤ 5% |
| CPU (under load) | ≤ 10% | ≤ 15% | ≤ 25% | ≤ 50% |

---

## Configuration Schema

```yaml
fenrir:
  # Endpoint capability (auto-detected, can be overridden)
  endpoint_tier: "auto"  # auto, T0, T1, T2, T3
  force_tier: false      # If true, skip auto-detection
  
  # Inference backends (enabled based on tier)
  backends:
    onnx:
      enabled: true
      intra_op_threads: 2
      inter_op_threads: 1
    bitnet:
      enabled: true
      n_threads: 2
      models_dir: "models/bitnet"
    gguf:
      enabled: true
      n_threads: 4
      n_gpu_layers: 0  # 0 = CPU, -1 = all, N = specific
      models_dir: "models/gguf"
      max_ram_gb: 8
    candle:
      enabled: false  # Requires GPU, opt-in
      device: "cuda"  # cuda, metal, cpu
  
  modules:
    dns_anomaly:
      enabled: true
      entropy_threshold: 3.5
      nxdomain_burst_window_sec: 60
      model_override: null  # e.g., "bitnet-dga-3b" to force
    binary_reputation:
      enabled: true
      vt_api_key: "${VT_API_KEY}"
      local_model: "models/binary_reputation.onnx"
    beaconing_detector:
      enabled: true
      min_beacons: 6
      max_jitter_pct: 0.3
    injection_detector:
      enabled: true
      kernel_callbacks: true
    credential_abuse:
      enabled: true
      baseline_window_days: 14
    lateral_movement:
      enabled: true
      rare_edge_threshold: 0.01
  
  yggdrasil_sync:
    interval_sec: 300
    baseline_cache_ttl_sec: 86400
    model_manifest_ttl_sec: 3600
  
  output:
    garmr_endpoints:
      - "grpc://garmr-1.segment-a:50051"
      - "grpc://garmr-2.segment-a:50051"
    batch_size: 50
    flush_interval_sec: 5
```

---

## Adaptive Inference API (Rust)

```rust
// cerberus-fenrir/src/inference/mod.rs

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComputeTier { T0, T1, T2, T3 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointCapabilities {
    pub tier: ComputeTier,
    pub total_ram_gb: f32,
    pub available_ram_gb: f32,
    pub cpu_cores: usize,
    pub gpu: Option<GpuInfo>,
    pub instruction_sets: Vec<String>,  // avx2, avx512, neon, etc.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    pub vendor: String,      // nvidia, amd, intel, apple
    pub memory_gb: f32,
    pub compute_capability: Option<String>,
    pub driver_version: String,
}

pub trait InferenceBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn tier(&self) -> ComputeTier;
    fn load_model(&mut self, model_spec: &ModelSpec) -> Result<ModelHandle>;
    fn infer(&self, handle: &ModelHandle, input: &Tensor) -> Result<Tensor>;
    fn unload_model(&mut self, handle: ModelHandle) -> Result<()>;
    fn memory_usage(&self) -> usize;
}

pub struct ModelRouter {
    capabilities: EndpointCapabilities,
    backends: HashMap<BackendType, Box<dyn InferenceBackend>>,
    model_selection: ModelSelectionPolicy,
    active_models: HashMap<DetectionDomain, ActiveModel>,
}

impl ModelRouter {
    pub fn new(capabilities: EndpointCapabilities, policy: ModelSelectionPolicy) -> Result<Self> {
        let mut backends: HashMap<_, _> = HashMap::new();
        
        // Initialize available backends based on tier
        if capabilities.tier >= ComputeTier::T0 {
            backends.insert(BackendType::Onnx, Box::new(OnnxRuntime::new()?));
            backends.insert(BackendType::BitNet, Box::new(BitNetCpp::new()?));
        }
        if capabilities.tier >= ComputeTier::T1 {
            backends.insert(BackendType::Gguf, Box::new(LlamaCpp::new()?));
        }
        if capabilities.tier >= ComputeTier::T2 {
            backends.insert(BackendType::Candle, Box::new(CandleRuntime::new()?));
        }
        
        Ok(Self { capabilities, backends, model_selection: policy, active_models: HashMap::new() })
    }
    
    pub async fn infer(&mut self, domain: DetectionDomain, input: Tensor) -> Result<InferenceOutput> {
        let model_key = self.model_selection.select(domain, self.capabilities.tier);
        
        // Load model if not cached
        if !self.active_models.contains_key(&domain) {
            let backend = self.backends.get_mut(&model_key.backend).ok_or_else(|| anyhow!("Backend not available"))?;
            let handle = backend.load_model(&model_key.spec)?;
            self.active_models.insert(domain, ActiveModel { backend: model_key.backend, handle, spec: model_key.spec });
        }
        
        let active = self.active_models.get(&domain).unwrap();
        let backend = self.backends.get(&active.backend).unwrap();
        let output = backend.infer(&active.handle, &input)?;
        
        Ok(InferenceOutput { domain, output, model: active.spec.name.clone(), backend: active.backend })
    }
    
    pub fn tier(&self) -> ComputeTier { self.capabilities.tier }
    pub fn capabilities(&self) -> &EndpointCapabilities { &self.capabilities }
}
```

---

## Testing Requirements

| Test | Description |
|------|-------------|
| `test_dns_dga_detection` | Known DGA families (Necurs, Gozi, etc.) → confidence > 0.8 |
| `test_beaconing_periodicity` | Synthetic beacons with jitter → detected at ≥ 6 beacons |
| `test_injection_chain` | Process hollowing + APC queue → attack chain linked |
| `test_credential_replay` | Pass-the-hash simulation → behavioral deviation |
| `test_lateral_smb` | PsExec/WMI lateral movement → rare edge detected |
| `test_model_hot_swap` | Model update → zero-downtime swap, rollback on failure |
| `test_yggdrasil_cache_stale` | Partition from Yggdrasil → local baselines used, sync on reconnect |

---

## Open Questions

- **AQ-F01:** Model format standardization: ONNX vs GGUF vs custom?
- **AQ-F02:** Hardware acceleration (GPU/NPU) for inference: required or optional?
- **AQ-F03:** eBPF vs kernel callback coverage on Windows: parity gap?
- **AQ-F04:** Observation deduplication strategy: exact match vs. semantic?

---

**Status:** Draft (awaiting ratification)
**Owner:** Fenrir Team
**Depends On:** Pack telemetry schema, Yggdrasil baseline API, Garmr ingestion API