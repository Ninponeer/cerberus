//! Inference Engine - Core Traits and Types
//!
//! Defines the abstraction layer for all inference backends (ONNX, BitNet, GGUF, Candle)

pub use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Compute tier classification for endpoint capability
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComputeTier {
    T0,  // Constrained: <2GB RAM, 1-2 cores, no GPU
    T1,  // Standard: 2-8GB RAM, 4-8 cores, optional GPU
    T2,  // Enhanced: 8-32GB RAM, 8-16 cores, GPU/NPU
    T3,  // Maximum: >32GB RAM, 16+ cores, GPU (CUDA/ROCm/Metal)
}

impl fmt::Display for ComputeTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComputeTier::T0 => write!(f, "T0"),
            ComputeTier::T1 => write!(f, "T1"),
            ComputeTier::T2 => write!(f, "T2"),
            ComputeTier::T3 => write!(f, "T3"),
        }
    }
}

impl Default for ComputeTier {
    fn default() -> Self {
        ComputeTier::T1
    }
}

/// GPU information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    pub vendor: String,                    // nvidia, amd, intel, apple
    pub memory_gb: f32,
    pub compute_capability: Option<String>,
    pub driver_version: String,
}

/// Endpoint capabilities detected at startup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointCapabilities {
    pub tier: ComputeTier,
    pub total_ram_gb: f32,
    pub available_ram_gb: f32,
    pub cpu_cores: usize,
    pub gpu: Option<GpuInfo>,
    pub instruction_sets: Vec<String>,  // avx2, avx512, neon, etc.
    pub os: String,
    pub arch: String,
}

impl EndpointCapabilities {
    /// Auto-detect endpoint capabilities
    pub fn detect() -> Result<Self> {
        let total_ram_gb = Self::detect_total_ram_gb()?;
        let available_ram_gb = Self::detect_available_ram_gb()?;
        let cpu_cores = num_cpus::get();
        let gpu = Self::detect_gpu()?;
        let instruction_sets = Self::detect_instruction_sets();
        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();
        
        let tier = Self::classify_tier(total_ram_gb, cpu_cores, gpu.as_ref());
        
        Ok(Self {
            tier,
            total_ram_gb,
            available_ram_gb,
            cpu_cores,
            gpu,
            instruction_sets,
            os,
            arch,
        })
    }
    
    fn detect_total_ram_gb() -> Result<f32> {
        #[cfg(target_os = "linux")]
        {
            let content = std::fs::read_to_string("/proc/meminfo")?;
            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    let kb: f32 = line.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0.0);
                    return Ok(kb / 1024.0 / 1024.0);
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
            let mut mem_info = MEMORYSTATUSEX::default();
            mem_info.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
            unsafe { GlobalMemoryStatusEx(&mut mem_info)?; }
            return Ok(mem_info.ullTotalPhys as f32 / 1024.0 / 1024.0 / 1024.0);
        }
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            let output = Command::new("sysctl").args(["-n", "hw.memsize"]).output()?;
            let bytes: f32 = String::from_utf8_lossy(&output.stdout).trim().parse().unwrap_or(0.0);
            return Ok(bytes / 1024.0 / 1024.0 / 1024.0);
        }
        Ok(8.0) // Default fallback
    }
    
    fn detect_available_ram_gb() -> Result<f32> {
        // Conservative estimate: 50% of total for application use
        Ok(Self::detect_total_ram_gb()? * 0.5)
    }
    
    fn detect_gpu() -> Result<Option<GpuInfo>> {
        #[cfg(target_os = "linux")]
        {
            // Try nvidia-smi first
            if let Ok(output) = std::process::Command::new("nvidia-smi")
                .args(["--query-gpu=name,memory.total,driver_version", "--format=csv,noheader"])
                .output()
            {
                if output.status.success() {
                    let info = String::from_utf8_lossy(&output.stdout);
                    let parts: Vec<&str> = info.trim().split(',').map(|s| s.trim()).collect();
                    if parts.len() >= 3 {
                        return Ok(Some(GpuInfo {
                            vendor: "nvidia".to_string(),
                            memory_gb: parts[1].parse().unwrap_or(0.0),
                            compute_capability: None,
                            driver_version: parts[2].to_string(),
                        }));
                    }
                }
            }
            // Try rocm-smi for AMD
            // ... similar logic
        }
        #[cfg(target_os = "windows")]
        {
            // WMI query for GPU
            // ... implementation
        }
        #[cfg(target_os = "macos")]
        {
            // system_profiler for Metal GPU
            // ... implementation
        }
        Ok(None)
    }
    
    fn detect_instruction_sets() -> Vec<String> {
        let mut sets = Vec::new();
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") { sets.push("avx2".to_string()); }
            if is_x86_feature_detected!("avx512f") { sets.push("avx512f".to_string()); }
            if is_x86_feature_detected!("avx512vnni") { sets.push("avx512vnni".to_string()); }
            if is_x86_feature_detected!("fma") { sets.push("fma".to_string()); }
        }
        #[cfg(target_arch = "aarch64")]
        {
            sets.push("neon".to_string());
            // Check for SVE, SME via auxiliary vectors
        }
        sets
    }
    
    fn classify_tier(total_ram_gb: f32, cpu_cores: usize, gpu: Option<&GpuInfo>) -> ComputeTier {
        let has_gpu = gpu.is_some();
        let gpu_mem = gpu.map(|g| g.memory_gb).unwrap_or(0.0);
        
        if total_ram_gb < 2.0 || cpu_cores < 2 {
            ComputeTier::T0
        } else if total_ram_gb >= 32.0 && cpu_cores >= 16 && has_gpu && gpu_mem >= 8.0 {
            ComputeTier::T3
        } else if total_ram_gb >= 8.0 && cpu_cores >= 8 && has_gpu && gpu_mem >= 4.0 {
            ComputeTier::T2
        } else {
            ComputeTier::T1
        }
    }
}

/// Backend types available
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendType {
    Onnx,
    BitNet,
    Gguf,
    Candle,
}

/// Detection domains that map to models
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionDomain {
    DnsAnomaly,
    BinaryReputation,
    BeaconingDetector,
    InjectionDetector,
    CredentialAbuse,
    LateralMovement,
}

/// Model specification for loading
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSpec {
    pub name: String,
    pub backend: BackendType,
    pub path: String,
    pub sha256: String,
    pub tier_min: ComputeTier,
    pub tier_max: ComputeTier,
    pub sequence_length: Option<usize>,
    pub parameters: HashMap<String, String>,
}

/// Opaque handle to a loaded model
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModelHandle(pub u64);

/// Tensor abstraction (backend-agnostic)
#[derive(Debug, Clone)]
pub struct Tensor {
    pub data: Vec<f32>,
    pub shape: Vec<usize>,
    pub dtype: TensorDtype,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TensorDtype {
    F32,
    F16,
    I32,
    I64,
    U8,
}

/// Inference output
#[derive(Debug, Clone)]
pub struct InferenceOutput {
    pub domain: DetectionDomain,
    pub output: Tensor,
    pub model: String,
    pub backend: BackendType,
    pub latency_ms: f32,
}

/// Active model reference
#[derive(Debug, Clone)]
pub struct ActiveModel {
    pub backend: BackendType,
    pub handle: ModelHandle,
    pub spec: ModelSpec,
}

/// Model selection policy entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSelectionEntry {
    pub backend: BackendType,
    pub model_name: String,
    pub spec: ModelSpec,
}

/// Trait for all inference backends
pub trait InferenceBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn backend_type(&self) -> BackendType;
    fn min_tier(&self) -> ComputeTier;
    fn load_model(&mut self, spec: &ModelSpec) -> Result<ModelHandle>;
    fn infer(&self, handle: ModelHandle, input: &Tensor) -> Result<Tensor>;
    fn infer_batch(&self, handle: ModelHandle, inputs: &[Tensor]) -> Result<Vec<Tensor>>;
    fn unload_model(&mut self, handle: ModelHandle) -> Result<()>;
    fn memory_usage(&self) -> usize;
    fn supports_gpu(&self) -> bool { false }
    fn set_gpu_layers(&mut self, _layers: i32) -> Result<()> { Ok(()) }
}

/// Model selection policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSelectionPolicy {
    pub selections: HashMap<DetectionDomain, HashMap<ComputeTier, ModelSelectionEntry>>,
    pub fallback_order: HashMap<ComputeTier, Vec<BackendType>>,
}

impl Default for ModelSelectionPolicy {
    fn default() -> Self {
        let mut fallback_order = HashMap::new();
        fallback_order.insert(ComputeTier::T0, vec![BackendType::Onnx, BackendType::BitNet]);
        fallback_order.insert(ComputeTier::T1, vec![BackendType::BitNet, BackendType::Gguf, BackendType::Onnx]);
        fallback_order.insert(ComputeTier::T2, vec![BackendType::Gguf, BackendType::BitNet, BackendType::Candle, BackendType::Onnx]);
        fallback_order.insert(ComputeTier::T3, vec![BackendType::Gguf, BackendType::Candle, BackendType::Onnx, BackendType::BitNet]);
        
        Self {
            selections: HashMap::new(),
            fallback_order,
        }
    }
}

impl ModelSelectionPolicy {
    pub fn select(&self, domain: DetectionDomain, tier: ComputeTier) -> Option<&ModelSelectionEntry> {
        self.selections.get(&domain)?.get(&tier)
    }
    
    pub fn fallback_backends(&self, tier: ComputeTier) -> &[BackendType] {
        self.fallback_order.get(&tier).map(|v| v.as_slice()).unwrap_or(&[])
    }
}