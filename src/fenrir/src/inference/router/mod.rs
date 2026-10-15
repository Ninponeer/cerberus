//! Model Router - Adaptive Inference Engine
//!
//! Routes inference requests to appropriate backend based on endpoint tier and domain

use cerberus_core::inference::{
    ActiveModel, BackendType, ComputeTier, DetectionDomain, InferenceBackend, InferenceOutput,
    ModelHandle, ModelSelectionEntry, ModelSelectionPolicy, ModelSpec, Result, Tensor,
};
use cerberus_core::{CerberusError, Result as CoreResult};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::inference::backends::{bitnet::BitNetBackend, candle::CandleBackend, gguf::GgufBackend, onnx::OnnxRuntime};

pub struct ModelRouter {
    capabilities: cerberus_core::inference::EndpointCapabilities,
    policy: ModelSelectionPolicy,
    backends: HashMap<BackendType, Arc<RwLock<Box<dyn InferenceBackend>>>>,
    active_models: Arc<RwLock<HashMap<DetectionDomain, ActiveModel>>>,
    handle_counter: u64,
}

impl ModelRouter {
    pub fn new(
        capabilities: cerberus_core::inference::EndpointCapabilities,
        policy: ModelSelectionPolicy,
    ) -> CoreResult<Self> {
        let mut backends: HashMap<BackendType, Arc<RwLock<Box<dyn InferenceBackend>>>> = HashMap::new();
        
        // Initialize ONNX (always available)
        backends.insert(BackendType::Onnx, Arc::new(RwLock::new(Box::new(OnnxRuntime::new()?))));
        
        // Initialize BitNet (T0+)
        if capabilities.tier >= ComputeTier::T0 {
            backends.insert(BackendType::BitNet, Arc::new(RwLock::new(Box::new(BitNetBackend::new(2)?))));
        }
        
        // Initialize GGUF (T1+)
        if capabilities.tier >= ComputeTier::T1 {
            backends.insert(BackendType::Gguf, Arc::new(RwLock::new(Box::new(GgufBackend::new(4, 0, 8)?))));
        }
        
        // Initialize Candle (T2+)
        if capabilities.tier >= ComputeTier::T2 {
            if let Ok(candle) = CandleBackend::cuda() {
                backends.insert(BackendType::Candle, Arc::new(RwLock::new(Box::new(candle))));
            } else if let Ok(candle) = CandleBackend::metal() {
                backends.insert(BackendType::Candle, Arc::new(RwLock::new(Box::new(candle))));
            } else if let Ok(candle) = CandleBackend::cpu() {
                backends.insert(BackendType::Candle, Arc::new(RwLock::new(Box::new(candle))));
            }
        }
        
        Ok(Self {
            capabilities,
            policy,
            backends,
            active_models: Arc::new(RwLock::new(HashMap::new())),
            handle_counter: 1,
        })
    }
    
    pub fn with_config(config: &crate::config::FenrirConfig) -> CoreResult<Self> {
        let capabilities = if config.endpoint_tier == "auto" {
            cerberus_core::inference::EndpointCapabilities::detect()?
        } else {
            let tier = match config.endpoint_tier.as_str() {
                "T0" => ComputeTier::T0,
                "T1" => ComputeTier::T1,
                "T2" => ComputeTier::T2,
                "T3" => ComputeTier::T3,
                _ => ComputeTier::T1,
            };
            cerberus_core::inference::EndpointCapabilities {
                tier,
                total_ram_gb: 0.0,
                available_ram_gb: 0.0,
                cpu_cores: 0,
                gpu: None,
                instruction_sets: Vec::new(),
                os: std::env::consts::OS.to_string(),
                arch: std::env::consts::ARCH.to_string(),
            }
        };
        
        let policy = Self::build_policy(config)?;
        Self::new(capabilities, policy)
    }
    
    fn build_policy(config: &crate::config::FenrirConfig) -> CoreResult<ModelSelectionPolicy> {
        let mut policy = ModelSelectionPolicy::default();
        
        // DNS Anomaly
        policy.selections.insert(DetectionDomain::DnsAnomaly, [
            (ComputeTier::T0, ModelSelectionEntry {
                backend: BackendType::Onnx,
                model_name: "isolation_forest".to_string(),
                spec: ModelSpec {
                    name: "isolation_forest.onnx".to_string(),
                    backend: BackendType::Onnx,
                    path: "models/onnx/isolation_forest.onnx".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T0,
                    tier_max: ComputeTier::T3,
                    sequence_length: None,
                    parameters: Default::default(),
                },
            }),
            (ComputeTier::T1, ModelSelectionEntry {
                backend: BackendType::BitNet,
                model_name: "bitnet-dga-1b".to_string(),
                spec: ModelSpec {
                    name: "bitnet-dga-1b.bin".to_string(),
                    backend: BackendType::BitNet,
                    path: "models/bitnet/bitnet-dga-1b.bin".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T0,
                    tier_max: ComputeTier::T1,
                    sequence_length: Some(512),
                    parameters: Default::default(),
                },
            }),
            (ComputeTier::T2, ModelSelectionEntry {
                backend: BackendType::BitNet,
                model_name: "bitnet-dga-3b".to_string(),
                spec: ModelSpec {
                    name: "bitnet-dga-3b.bin".to_string(),
                    backend: BackendType::BitNet,
                    path: "models/bitnet/bitnet-dga-3b.bin".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T1,
                    tier_max: ComputeTier::T2,
                    sequence_length: Some(1024),
                    parameters: Default::default(),
                },
            }),
            (ComputeTier::T3, ModelSelectionEntry {
                backend: BackendType::Gguf,
                model_name: "codellama-7b-dga".to_string(),
                spec: ModelSpec {
                    name: "codellama-7b-dga.Q4_K_M.gguf".to_string(),
                    backend: BackendType::Gguf,
                    path: "models/gguf/codellama-7b-dga.Q4_K_M.gguf".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T2,
                    tier_max: ComputeTier::T3,
                    sequence_length: Some(2048),
                    parameters: Default::default(),
                },
            }),
        ].into());
        
        // Beaconing Detector
        policy.selections.insert(DetectionDomain::BeaconingDetector, [
            (ComputeTier::T0, ModelSelectionEntry {
                backend: BackendType::BitNet,
                model_name: "bitnet-beacon-1b".to_string(),
                spec: ModelSpec {
                    name: "bitnet-beacon-1b.bin".to_string(),
                    backend: BackendType::BitNet,
                    path: "models/bitnet/bitnet-beacon-1b.bin".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T0,
                    tier_max: ComputeTier::T1,
                    sequence_length: Some(256),
                    parameters: Default::default(),
                },
            }),
            (ComputeTier::T1, ModelSelectionEntry {
                backend: BackendType::BitNet,
                model_name: "bitnet-beacon-3b".to_string(),
                spec: ModelSpec {
                    name: "bitnet-beacon-3b.bin".to_string(),
                    backend: BackendType::BitNet,
                    path: "models/bitnet/bitnet-beacon-3b.bin".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T1,
                    tier_max: ComputeTier::T2,
                    sequence_length: Some(512),
                    parameters: Default::default(),
                },
            }),
            (ComputeTier::T2, ModelSelectionEntry {
                backend: BackendType::Gguf,
                model_name: "mistral-7b-beacon".to_string(),
                spec: ModelSpec {
                    name: "mistral-7b-beacon.Q4_K_M.gguf".to_string(),
                    backend: BackendType::Gguf,
                    path: "models/gguf/mistral-7b-beacon.Q4_K_M.gguf".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T2,
                    tier_max: ComputeTier::T3,
                    sequence_length: Some(1024),
                    parameters: Default::default(),
                },
            }),
            (ComputeTier::T3, ModelSelectionEntry {
                backend: BackendType::Gguf,
                model_name: "llama3-8b-beacon".to_string(),
                spec: ModelSpec {
                    name: "llama3-8b-beacon.Q4_K_M.gguf".to_string(),
                    backend: BackendType::Gguf,
                    path: "models/gguf/llama3-8b-beacon.Q4_K_M.gguf".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T3,
                    tier_max: ComputeTier::T3,
                    sequence_length: Some(2048),
                    parameters: Default::default(),
                },
            }),
        ].into());
        
        // Injection Detector
        policy.selections.insert(DetectionDomain::InjectionDetector, [
            (ComputeTier::T0, ModelSelectionEntry {
                backend: BackendType::BitNet,
                model_name: "bitnet-inject-1b".to_string(),
                spec: ModelSpec {
                    name: "bitnet-inject-1b.bin".to_string(),
                    backend: BackendType::BitNet,
                    path: "models/bitnet/bitnet-inject-1b.bin".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T0,
                    tier_max: ComputeTier::T1,
                    sequence_length: Some(512),
                    parameters: Default::default(),
                },
            }),
            (ComputeTier::T1, ModelSelectionEntry {
                backend: BackendType::BitNet,
                model_name: "bitnet-inject-3b".to_string(),
                spec: ModelSpec {
                    name: "bitnet-inject-3b.bin".to_string(),
                    backend: BackendType::BitNet,
                    path: "models/bitnet/bitnet-inject-3b.bin".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T1,
                    tier_max: ComputeTier::T2,
                    sequence_length: Some(1024),
                    parameters: Default::default(),
                },
            }),
            (ComputeTier::T2, ModelSelectionEntry {
                backend: BackendType::Gguf,
                model_name: "codellama-7b-inject".to_string(),
                spec: ModelSpec {
                    name: "codellama-7b-inject.Q4_K_M.gguf".to_string(),
                    backend: BackendType::Gguf,
                    path: "models/gguf/codellama-7b-inject.Q4_K_M.gguf".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T2,
                    tier_max: ComputeTier::T3,
                    sequence_length: Some(2048),
                    parameters: Default::default(),
                },
            }),
            (ComputeTier::T3, ModelSelectionEntry {
                backend: BackendType::Gguf,
                model_name: "codellama-34b-inject".to_string(),
                spec: ModelSpec {
                    name: "codellama-34b-inject.Q4_K_M.gguf".to_string(),
                    backend: BackendType::Gguf,
                    path: "models/gguf/codellama-34b-inject.Q4_K_M.gguf".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T3,
                    tier_max: ComputeTier::T3,
                    sequence_length: Some(4096),
                    parameters: Default::default(),
                },
            }),
        ].into());
        
        // Credential Abuse
        policy.selections.insert(DetectionDomain::CredentialAbuse, [
            (ComputeTier::T0, ModelSelectionEntry {
                backend: BackendType::BitNet,
                model_name: "bitnet-cmd-1b".to_string(),
                spec: ModelSpec {
                    name: "bitnet-cmd-1b.bin".to_string(),
                    backend: BackendType::BitNet,
                    path: "models/bitnet/bitnet-cmd-1b.bin".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T0,
                    tier_max: ComputeTier::T1,
                    sequence_length: Some(128),
                    parameters: Default::default(),
                },
            }),
            (ComputeTier::T1, ModelSelectionEntry {
                backend: BackendType::BitNet,
                model_name: "bitnet-cmd-3b".to_string(),
                spec: ModelSpec {
                    name: "bitnet-cmd-3b.bin".to_string(),
                    backend: BackendType::BitNet,
                    path: "models/bitnet/bitnet-cmd-3b.bin".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T1,
                    tier_max: ComputeTier::T2,
                    sequence_length: Some(256),
                    parameters: Default::default(),
                },
            }),
            (ComputeTier::T2, ModelSelectionEntry {
                backend: BackendType::Gguf,
                model_name: "codellama-7b-cmd".to_string(),
                spec: ModelSpec {
                    name: "codellama-7b-cmd.Q4_K_M.gguf".to_string(),
                    backend: BackendType::Gguf,
                    path: "models/gguf/codellama-7b-cmd.Q4_K_M.gguf".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T2,
                    tier_max: ComputeTier::T3,
                    sequence_length: Some(512),
                    parameters: Default::default(),
                },
            }),
            (ComputeTier::T3, ModelSelectionEntry {
                backend: BackendType::Gguf,
                model_name: "codellama-13b-cmd".to_string(),
                spec: ModelSpec {
                    name: "codellama-13b-cmd.Q4_K_M.gguf".to_string(),
                    backend: BackendType::Gguf,
                    path: "models/gguf/codellama-13b-cmd.Q4_K_M.gguf".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T3,
                    tier_max: ComputeTier::T3,
                    sequence_length: Some(1024),
                    parameters: Default::default(),
                },
            }),
        ].into());
        
        // Lateral Movement
        policy.selections.insert(DetectionDomain::LateralMovement, [
            (ComputeTier::T0, ModelSelectionEntry {
                backend: BackendType::Onnx,
                model_name: "graph_rare_edge".to_string(),
                spec: ModelSpec {
                    name: "graph_rare_edge.onnx".to_string(),
                    backend: BackendType::Onnx,
                    path: "models/onnx/graph_rare_edge.onnx".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T0,
                    tier_max: ComputeTier::T3,
                    sequence_length: None,
                    parameters: Default::default(),
                },
            }),
            (ComputeTier::T1, ModelSelectionEntry {
                backend: BackendType::BitNet,
                model_name: "bitnet-graph-1b".to_string(),
                spec: ModelSpec {
                    name: "bitnet-graph-1b.bin".to_string(),
                    backend: BackendType::BitNet,
                    path: "models/bitnet/bitnet-graph-1b.bin".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T0,
                    tier_max: ComputeTier::T1,
                    sequence_length: Some(512),
                    parameters: Default::default(),
                },
            }),
            (ComputeTier::T2, ModelSelectionEntry {
                backend: BackendType::BitNet,
                model_name: "bitnet-graph-3b".to_string(),
                spec: ModelSpec {
                    name: "bitnet-graph-3b.bin".to_string(),
                    backend: BackendType::BitNet,
                    path: "models/bitnet/bitnet-graph-3b.bin".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T1,
                    tier_max: ComputeTier::T2,
                    sequence_length: Some(1024),
                    parameters: Default::default(),
                },
            }),
            (ComputeTier::T3, ModelSelectionEntry {
                backend: BackendType::Gguf,
                model_name: "mistral-7b-graph".to_string(),
                spec: ModelSpec {
                    name: "mistral-7b-graph.Q4_K_M.gguf".to_string(),
                    backend: BackendType::Gguf,
                    path: "models/gguf/mistral-7b-graph.Q4_K_M.gguf".to_string(),
                    sha256: String::new(),
                    tier_min: ComputeTier::T2,
                    tier_max: ComputeTier::T3,
                    sequence_length: Some(2048),
                    parameters: Default::default(),
                },
            }),
        ].into());
        
        Ok(policy)
    }
    
    pub fn infer(&self, domain: DetectionDomain, input: Tensor) -> Result<InferenceOutput> {
        let start = std::time::Instant::now();
        
        // Check if model already loaded for this domain
        {
            let models = self.active_models.read().unwrap();
            if let Some(active) = models.get(&domain) {
                if let Some(backend) = self.backends.get(&active.backend) {
                    let b = backend.read().map_err(|e| CerberusError::Internal(e.to_string()))?;
                    let output = b.infer(active.handle, &input)?;
                    return Ok(InferenceOutput {
                        domain,
                        output,
                        model: active.spec.name.clone(),
                        backend: active.backend,
                        latency_ms: start.elapsed().as_millis() as f32,
                    });
                }
            }
        }
        
        // Load model for this domain
        let selection = self.policy.select(domain, self.capabilities.tier)
            .ok_or_else(|| CerberusError::Validation(
                format!("No model configured for domain {:?} at tier {:?}", domain, self.capabilities.tier)
            ))?;
        
        let backend = self.backends.get(&selection.backend)
            .ok_or_else(|| CerberusError::Internal(
                format!("Backend {:?} not available", selection.backend)
            ))?;
        
        let handle = backend.write().map_err(|e| CerberusError::Internal(e.to_string()))?.load_model(&selection.spec)?;
        
        // Cache the active model
        {
            let mut models = self.active_models.write().unwrap();
            models.insert(domain, ActiveModel {
                backend: selection.backend,
                handle,
                spec: selection.spec.clone(),
            });
        }
        
        let output = backend.read().map_err(|e| CerberusError::Internal(e.to_string()))?.infer(handle, &input)?;
        
        Ok(InferenceOutput {
            domain,
            output,
            model: selection.spec.name.clone(),
            backend: selection.backend,
            latency_ms: start.elapsed().as_millis() as f32,
        })
    }
    
    pub fn infer_with_fallback(&self, domain: DetectionDomain, input: Tensor) -> Result<InferenceOutput> {
        let primary = self.infer(domain, input);
        if primary.is_ok() {
            return primary;
        }
        
        // Try fallback backends
        for fallback_backend in self.policy.fallback_backends(self.capabilities.tier) {
            if *fallback_backend == self.policy.select(domain, self.capabilities.tier).map(|s| s.backend).unwrap_or(BackendType::Onnx) {
                continue; // Skip primary
            }
            
            // Try to load model with fallback backend (would need fallback model specs)
            // For now, just return primary error
        }
        
        primary
    }
    
    pub fn tier(&self) -> ComputeTier {
        self.capabilities.tier
    }
    
    pub fn capabilities(&self) -> &cerberus_core::inference::EndpointCapabilities {
        &self.capabilities
    }
    
    pub fn available_backends(&self) -> Vec<BackendType> {
        self.backends.keys().copied().collect()
    }
    
    pub fn loaded_models(&self) -> Vec<(DetectionDomain, String, BackendType)> {
        self.active_models.read().unwrap()
            .iter()
            .map(|(domain, active)| (*domain, active.spec.name.clone(), active.backend))
            .collect()
        }
    
    pub fn unload_model(&mut self, domain: DetectionDomain) -> Result<()> {
        let mut models = self.active_models.write().unwrap();
        if let Some(active) = models.remove(&domain) {
            if let Some(backend) = self.backends.get(&active.backend) {
                backend.write().map_err(|e| CerberusError::Internal(e.to_string()))?.unload_model(active.handle)?;
            }
        }
        Ok(())
    }
    
    pub fn memory_usage(&self) -> usize {
        self.backends.values().map(|b| b.read().map(|b| b.memory_usage()).unwrap_or(0)).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tier_classification() {
        // Test T0 classification
        assert_eq!(ComputeTier::T0, ComputeTier::T0);
        assert!(ComputeTier::T0 < ComputeTier::T1);
        assert!(ComputeTier::T3 > ComputeTier::T2);
    }
}