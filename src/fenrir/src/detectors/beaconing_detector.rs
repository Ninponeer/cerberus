//! Beaconing Detection Module

use cerberus_core::inference::{DetectionDomain, InferenceOutput, Result, Tensor, TensorDtype};
use cerberus_core::{CerberusError, Result as CoreResult};
use std::collections::HashMap;

pub struct BeaconingDetector {
    interval_tolerance: f64,      // seconds
    min_beacons: usize,
    connection_history: HashMap<String, Vec<u64>>, // dest_ip:port -> timestamps
}

impl BeaconingDetector {
    pub fn new(interval_tolerance: f64, min_beacons: usize) -> Self {
        Self {
            interval_tolerance,
            min_beacons,
            connection_history: HashMap::new(),
        }
    }
    
    pub fn observe(&mut self, src_ip: &str, dst_ip: &str, dst_port: u16, timestamp_ns: u64) -> Result<Option<InferenceOutput>> {
        let key = format!("{}:{}->{}", src_ip, dst_ip, dst_port);
        self.connection_history.entry(key.clone()).or_default().push(timestamp_ns);
        
        // Clean old entries (keep last hour)
        let cutoff = timestamp_ns.saturating_sub(3600 * 1_000_000_000);
        if let Some(timestamps) = self.connection_history.get_mut(&key) {
            timestamps.retain(|&ts| ts > cutoff);
        }
        
        if let Some(timestamps) = self.connection_history.get(&key) {
            if timestamps.len() >= self.min_beacons {
                let regularity = self.calculate_regularity(timestamps);
                if regularity > 0.7 {
                    return Ok(Some(InferenceOutput {
                        domain: DetectionDomain::BeaconingDetector,
                        output: Tensor {
                            data: vec![regularity as f32, timestamps.len() as f32],
                            shape: vec![1, 2],
                            dtype: TensorDtype::F32,
                        },
                        model: "beaconing_detector".to_string(),
                        backend: cerberus_core::inference::BackendType::Onnx,
                        latency_ms: 0.0,
                    }));
                }
            }
        }
        
        Ok(None)
    }
    
    fn calculate_regularity(&self, timestamps: &[u64]) -> f64 {
        if timestamps.len() < 2 {
            return 0.0;
        }
        
        let mut intervals = Vec::new();
        for i in 1..timestamps.len() {
            intervals.push((timestamps[i] - timestamps[i-1]) as f64 / 1_000_000_000.0);
        }
        
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if mean == 0.0 {
            return 0.0;
        }
        
        let variance = intervals.iter()
            .map(|&x| (x - mean).powi(2))
            .sum::<f64>() / intervals.len() as f64;
        
        let std_dev = variance.sqrt();
        let cv = std_dev / mean; // Coefficient of variation
        
        // Low CV = high regularity (beaconing)
        (1.0 - cv.min(1.0)).max(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_regular_beaconing() {
        let mut detector = BeaconingDetector::new(1.0, 5);
        let base = 1_000_000_000_000u64; // 1000 seconds in ns
        
        for i in 0..10 {
            let _ = detector.observe("10.0.0.1", "10.0.0.100", 443, base + i * 60_000_000_000);
        }
        
        let result = detector.observe("10.0.0.1", "10.0.0.100", 443, base + 10 * 60_000_000_000);
        assert!(result.unwrap().is_some());
    }
    
    #[test]
    fn test_irregular_traffic() {
        let mut detector = BeaconingDetector::new(1.0, 5);
        let base = 1_000_000_000_000u64;
        
        for i in 0..10 {
            let _ = detector.observe("10.0.0.1", "10.0.0.100", 443, base + i * 60_000_000_000 + (i * 1000 * 1_000_000) as u64);
        }
        
        let result = detector.observe("10.0.0.1", "10.0.0.100", 443, base + 10 * 60_000_000_000 + 10000 * 1_000_000);
        assert!(result.unwrap().is_none());
    }
}