//! Binary Reputation Detection Module

use cerberus_core::inference::{DetectionDomain, InferenceOutput, Result, Tensor, TensorDtype};
use cerberus_core::{CerberusError, Result as CoreResult};
use std::collections::HashMap;
use std::sync::Arc;

pub struct BinaryReputationDetector {
    known_malicious: Arc<HashMap<String, f32>>, // hash -> confidence
    known_benign: Arc<HashMap<String, f32>>,
    unknown_threshold: f32,
}

impl BinaryReputationDetector {
    pub fn new(
        malicious: HashMap<String, f32>,
        benign: HashMap<String, f32>,
        unknown_threshold: f32,
    ) -> Self {
        Self {
            known_malicious: Arc::new(malicious),
            known_benign: Arc::new(benign),
            unknown_threshold,
        }
    }
    
    pub fn check(&self, file_hash: &str) -> Result<Option<InferenceOutput>> {
        if let Some(&confidence) = self.known_malicious.get(file_hash) {
            return Ok(Some(InferenceOutput {
                domain: DetectionDomain::BinaryReputation,
                output: Tensor {
                    data: vec![confidence, 1.0], // [confidence, is_malicious]
                    shape: vec![1, 2],
                    dtype: TensorDtype::F32,
                },
                model: "binary_reputation".to_string(),
                backend: cerberus_core::inference::BackendType::Onnx,
                latency_ms: 0.0,
            }));
        }
        
        if let Some(&confidence) = self.known_benign.get(file_hash) {
            return Ok(Some(InferenceOutput {
                domain: DetectionDomain::BinaryReputation,
                output: Tensor {
                    data: vec![confidence, 0.0], // [confidence, is_malicious]
                    shape: vec![1, 2],
                    dtype: TensorDtype::F32,
                },
                model: "binary_reputation".to_string(),
                backend: cerberus_core::inference::BackendType::Onnx,
                latency_ms: 0.0,
            }));
        }
        
        // Unknown binary - could trigger ML analysis
        Ok(Some(InferenceOutput {
            domain: DetectionDomain::BinaryReputation,
            output: Tensor {
                data: vec![self.unknown_threshold, 0.5],
                shape: vec![1, 2],
                dtype: TensorDtype::F32,
            },
            model: "binary_reputation".to_string(),
            backend: cerberus_core::inference::BackendType::Onnx,
            latency_ms: 0.0,
        }))
    }
    
    pub fn update_reputation(&mut self, hash: String, malicious: bool, confidence: f32) {
        // In production, this would persist to Yggdrasil
        // For now, we'd need Arc<Mutex<...>> for mutability
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_known_malicious() {
        let mut malicious = HashMap::new();
        malicious.insert("badhash123".to_string(), 0.95);
        let detector = BinaryReputationDetector::new(malicious, HashMap::new(), 0.5);
        
        let result = detector.check("badhash123").unwrap().unwrap();
        assert_eq!(result.output.data[1], 1.0);
    }
}