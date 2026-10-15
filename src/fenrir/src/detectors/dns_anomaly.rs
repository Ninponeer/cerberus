//! DNS Anomaly Detection Module

use cerberus_core::inference::{DetectionDomain, InferenceOutput, Result, Tensor, TensorDtype};
use cerberus_core::{CerberusError, Result as CoreResult};
use std::collections::HashMap;

pub struct DnsAnomalyDetector {
    entropy_threshold: f32,
    nxdomain_burst_window_sec: u64,
    nxdomain_counts: HashMap<String, Vec<u64>>, // domain -> timestamps
}

impl DnsAnomalyDetector {
    pub fn new(entropy_threshold: f32, nxdomain_burst_window_sec: u64) -> Self {
        Self {
            entropy_threshold,
            nxdomain_burst_window_sec,
            nxdomain_counts: HashMap::new(),
        }
    }
    
    pub fn analyze(&mut self, query: &str, response: Option<&str>, rcode: i32, timestamp_ns: u64) -> Result<Option<InferenceOutput>> {
        // Calculate entropy of domain name
        let entropy = self.calculate_entropy(query);
        
        // Track NXDOMAIN bursts
        if rcode == 3 { // NXDOMAIN
            self.nxdomain_counts.entry(query.to_string())
                .or_default()
                .push(timestamp_ns);
            
            // Clean old entries
            let cutoff = timestamp_ns.saturating_sub(self.nxdomain_burst_window_sec * 1_000_000_000);
            if let Some(timestamps) = self.nxdomain_counts.get_mut(query) {
                timestamps.retain(|&ts| ts > cutoff);
            }
        }
        
        let mut confidence = 0.0f32;
        let mut is_anomaly = false;
        
        // High entropy = potential DGA
        if entropy > self.entropy_threshold {
            confidence += 0.4;
            is_anomaly = true;
        }
        
        // NXDOMAIN burst
        if let Some(timestamps) = self.nxdomain_counts.get(query) {
            if timestamps.len() > 10 {
                confidence += 0.4;
                is_anomaly = true;
            }
        }
        
        // Fast-flux indicators (many IPs for same domain)
        // Would need response parsing
        
        if is_anomaly {
            confidence = confidence.min(1.0);
            Ok(Some(InferenceOutput {
                domain: DetectionDomain::DnsAnomaly,
                output: Tensor {
                    data: vec![confidence, entropy],
                    shape: vec![1, 2],
                    dtype: TensorDtype::F32,
                },
                model: "dns_anomaly".to_string(),
                backend: cerberus_core::inference::BackendType::Onnx,
                latency_ms: 0.0,
            }))
        } else {
            Ok(None)
        }
    }
    
    fn calculate_entropy(&self, s: &str) -> f32 {
        let mut freq = HashMap::new();
        for c in s.chars() {
            *freq.entry(c).or_insert(0) += 1;
        }
        
        let len = s.len() as f32;
        let mut entropy = 0.0f32;
        for count in freq.values() {
            let p = *count as f32 / len;
            entropy -= p * p.log2();
        }
        entropy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_entropy() {
        let detector = DnsAnomalyDetector::new(3.5, 60);
        assert!(detector.calculate_entropy("aaaaaaaaaa") < 1.0);
        assert!(detector.calculate_entropy("x7k9m2p4q1") > 3.0);
    }
}