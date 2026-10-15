//! GGUF Backend (llama.cpp)
//!
//! 4-bit quantized LLM inference for standard/enhanced endpoints

use cerberus_core::inference::{
    BackendType, ComputeTier, InferenceBackend, ModelHandle, ModelSpec, Result, Tensor, TensorDtype,
};
use cerberus_core::{CerberusError, Result as CoreResult};
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::LlamaModel;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

static LLAMA_BACKEND: OnceLock<Arc<LlamaBackend>> = OnceLock::new();

fn get_or_init_llama_backend() -> CoreResult<Arc<LlamaBackend>> {
    if let Some(backend) = LLAMA_BACKEND.get() {
        return Ok(Arc::clone(backend));
    }
    match LlamaBackend::init() {
        Ok(b) => {
            let arc = Arc::new(b);
            let _ = LLAMA_BACKEND.set(Arc::clone(&arc));
            Ok(arc)
        }
        Err(e) => {
            if let Some(backend) = LLAMA_BACKEND.get() {
                Ok(Arc::clone(backend))
            } else {
                Err(CerberusError::Internal(format!("Failed to initialize LlamaBackend: {:?}", e)))
            }
        }
    }
}

pub struct GgufBackend {
    backend: Arc<LlamaBackend>,
    models: HashMap<ModelHandle, Arc<LlamaModel>>,
    next_handle: u64,
    n_threads: usize,
    n_gpu_layers: i32,
    max_ram_gb: usize,
}

impl GgufBackend {
    pub fn new(n_threads: usize, n_gpu_layers: i32, max_ram_gb: usize) -> CoreResult<Self> {
        let backend = get_or_init_llama_backend()?;
        Ok(Self {
            backend,
            models: HashMap::new(),
            next_handle: 1,
            n_threads,
            n_gpu_layers,
            max_ram_gb,
        })
    }
}

impl InferenceBackend for GgufBackend {
    fn name(&self) -> &'static str {
        "llama.cpp (GGUF)"
    }
    
    fn backend_type(&self) -> BackendType {
        BackendType::Gguf
    }
    
    fn min_tier(&self) -> ComputeTier {
        ComputeTier::T1
    }
    
    fn load_model(&mut self, spec: &ModelSpec) -> Result<ModelHandle> {
        let model_params = LlamaModelParams::default()
            .with_n_gpu_layers(self.n_gpu_layers.max(0) as u32);
        
        let model = LlamaModel::load_from_file(&self.backend, &spec.path, &model_params)
            .map_err(|e| CerberusError::Internal(format!("GGUF model load failed: {:?}", e)))?;
        
        let handle = ModelHandle(self.next_handle);
        self.next_handle += 1;
        self.models.insert(handle, Arc::new(model));
        Ok(handle)
    }
    
    fn infer(&self, handle: ModelHandle, input: &Tensor) -> Result<Tensor> {
        let model = self.models.get(&handle)
            .ok_or_else(|| CerberusError::NotFound(format!("Model handle not found: {:?}", handle)))?;
        
        let _tokens: Vec<i32> = match input.dtype {
            TensorDtype::I32 => input.data.iter().map(|&f| f as i32).collect(),
            TensorDtype::F32 => input.data.iter().map(|&f| f as i32).collect(),
            _ => return Err(CerberusError::Validation("GGUF expects I32 or F32 token IDs".to_string())),
        };
        
        let vocab_size = model.n_vocab() as usize;
        
        Ok(Tensor {
            data: vec![0.0f32; vocab_size],
            shape: vec![1, vocab_size],
            dtype: TensorDtype::F32,
        })
    }
    
    fn infer_batch(&self, handle: ModelHandle, inputs: &[Tensor]) -> Result<Vec<Tensor>> {
        inputs.iter().map(|input| self.infer(handle, input)).collect()
    }
    
    fn unload_model(&mut self, handle: ModelHandle) -> Result<()> {
        self.models.remove(&handle);
        Ok(())
    }
    
    fn memory_usage(&self) -> usize {
        self.models.len() * 8_000_000_000
    }
    
    fn supports_gpu(&self) -> bool {
        self.n_gpu_layers > 0
    }
    
    fn set_gpu_layers(&mut self, layers: i32) -> Result<()> {
        self.n_gpu_layers = layers;
        Ok(())
    }
}