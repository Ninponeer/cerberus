//! ONNX Runtime Backend
//!
//! Classical ML models (Isolation Forest, XGBoost, Logistic Regression, etc.)

use cerberus_core::inference::{
    BackendType, ComputeTier, InferenceBackend, ModelHandle, ModelSpec, Result, Tensor, TensorDtype,
};
use cerberus_core::{CerberusError, Result as CoreResult};
use ort::environment::Environment;
use ort::session::{builder::GraphOptimizationLevel, Session};
use std::collections::HashMap;
use std::sync::Mutex;

pub struct OnnxRuntime {
    environment: Environment,
    sessions: HashMap<ModelHandle, Mutex<Session>>,
    next_handle: u64,
}

impl OnnxRuntime {
    pub fn new() -> CoreResult<Self> {
        let environment = ort::init()
            .with_name("fenrir")
            .build()
            .map_err(|e| CerberusError::Internal(format!("Failed to create ONNX environment: {}", e)))?;
        Ok(Self {
            environment,
            sessions: HashMap::new(),
            next_handle: 1,
        })
    }
}

impl Default for OnnxRuntime {
    fn default() -> Self {
        Self::new().expect("ONNX Runtime initialization failed")
    }
}

impl InferenceBackend for OnnxRuntime {
    fn name(&self) -> &'static str {
        "onnx"
    }
    
    fn backend_type(&self) -> BackendType {
        BackendType::Onnx
    }
    
    fn min_tier(&self) -> ComputeTier {
        ComputeTier::T0
    }
    
    fn load_model(&mut self, spec: &ModelSpec) -> Result<ModelHandle> {
        let session = Session::builder(&self.environment)
            .map_err(|e| CerberusError::Internal(format!("SessionBuilder failed: {}", e)))?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(|e| CerberusError::Internal(format!("Optimization level failed: {}", e)))?
            .with_intra_threads(2)
            .map_err(|e| CerberusError::Internal(format!("Intra threads failed: {}", e)))?
            .commit_from_file(&spec.path)
            .map_err(|e| CerberusError::Internal(format!("Model load failed: {}", e)))?;
        
        let handle = ModelHandle(self.next_handle);
        self.next_handle += 1;
        self.sessions.insert(handle, Mutex::new(session));
        Ok(handle)
    }
    
    fn infer(&self, handle: ModelHandle, input: &Tensor) -> Result<Tensor> {
        let session_mutex = self.sessions.get(&handle)
            .ok_or_else(|| CerberusError::NotFound(format!("Model handle not found: {:?}", handle)))?;
        let mut session = session_mutex.lock()
            .map_err(|e| CerberusError::Internal(format!("Session mutex poisoned: {}", e)))?;
        
        // Get input/output names
        let input_names: Vec<String> = session.inputs().iter().map(|i| i.name().to_string()).collect();
        let output_names: Vec<String> = session.outputs().iter().map(|o| o.name().to_string()).collect();
        
        if input_names.is_empty() || output_names.is_empty() {
            return Err(CerberusError::Internal("Model has no inputs or outputs".to_string()));
        }
        
        // Prepare input tensor
        let input_tensor = ort::value::Tensor::from_array((input.shape.as_slice(), input.data.clone().into_boxed_slice()))
            .map_err(|e| CerberusError::Internal(format!("Tensor creation failed: {}", e)))?;
        
        // Run inference
        let outputs = session.run(ort::inputs![input_names[0].as_str() => input_tensor])
            .map_err(|e| CerberusError::Internal(format!("Inference failed: {}", e)))?;
        
        // Extract output (assume single output for now)
        let output_tensor = outputs.get(&output_names[0])
            .ok_or_else(|| CerberusError::Internal("Output not found".to_string()))?;
        
        let (shape, data) = output_tensor.try_extract_tensor::<f32>()
            .map_err(|e| CerberusError::Internal(format!("Output extraction failed: {}", e)))?;
        
        Ok(Tensor {
            data: data.to_vec(),
            shape: shape.iter().map(|&x| x as usize).collect(),
            dtype: TensorDtype::F32,
        })
    }
    
    fn infer_batch(&self, handle: ModelHandle, inputs: &[Tensor]) -> Result<Vec<Tensor>> {
        inputs.iter().map(|input| self.infer(handle, input)).collect()
    }
    
    fn unload_model(&mut self, handle: ModelHandle) -> Result<()> {
        self.sessions.remove(&handle);
        Ok(())
    }
    
    fn memory_usage(&self) -> usize {
        self.sessions.len() * 50_000_000 // 50MB per session estimate
    }
    
    fn supports_gpu(&self) -> bool {
        false
    }
}