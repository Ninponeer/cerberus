//! Process Injection Detection Module

use cerberus_core::inference::{DetectionDomain, InferenceOutput, Result, Tensor, TensorDtype};
use cerberus_core::{CerberusError, Result as CoreResult};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub image_path: String,
    pub command_line: String,
    pub timestamp_ns: u64,
    pub operation: InjectionOperation,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InjectionOperation {
    CreateRemoteThread,
    WriteProcessMemory,
    VirtualAllocEx,
    QueueUserAPC,
    SetThreadContext,
    ProcessHollowing,
    DllInjection,
    ThreadHijacking,
    Other(String),
}

pub struct InjectionDetector {
    suspicious_apis: HashMap<String, f32>,
    process_tree: HashMap<u32, ProcessEvent>,
    high_risk_parents: Vec<String>,
}

impl InjectionDetector {
    pub fn new() -> Self {
        let mut suspicious_apis = HashMap::new();
        suspicious_apis.insert("CreateRemoteThread".to_string(), 0.9);
        suspicious_apis.insert("WriteProcessMemory".to_string(), 0.85);
        suspicious_apis.insert("VirtualAllocEx".to_string(), 0.8);
        suspicious_apis.insert("QueueUserAPC".to_string(), 0.75);
        suspicious_apis.insert("SetThreadContext".to_string(), 0.7);
        suspicious_apis.insert("NtCreateThreadEx".to_string(), 0.95);
        suspicious_apis.insert("RtlCreateUserThread".to_string(), 0.9);
        
        let high_risk_parents = vec![
            "powershell.exe".to_string(),
            "cmd.exe".to_string(),
            "wscript.exe".to_string(),
            "cscript.exe".to_string(),
            "mshta.exe".to_string(),
            "rundll32.exe".to_string(),
            "regsvr32.exe".to_string(),
        ];
        
        Self {
            suspicious_apis,
            process_tree: HashMap::new(),
            high_risk_parents,
        }
    }
    
    pub fn observe(&mut self, event: ProcessEvent) -> Result<Option<InferenceOutput>> {
        self.process_tree.insert(event.pid, event.clone());
        
        // Clean old entries (keep last 10 minutes)
        let cutoff = event.timestamp_ns.saturating_sub(600 * 1_000_000_000);
        self.process_tree.retain(|_, e| e.timestamp_ns > cutoff);
        
        let mut confidence = 0.0f32;
        let mut indicators = Vec::new();
        
        // Check for suspicious API
        if let Some(&score) = self.suspicious_apis.get(&event.operation.to_string()) {
            confidence += score * 0.5;
            indicators.push(format!("api:{}", event.operation));
        }
        
        // Check parent process
        if let Some(parent) = self.process_tree.get(&event.ppid) {
            let parent_name = std::path::Path::new(&parent.image_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            
            if self.high_risk_parents.iter().any(|p| p.eq_ignore_ascii_case(parent_name)) {
                confidence += 0.3;
                indicators.push(format!("parent:{}", parent_name));
            }
        }
        
        // Check for unsigned/unusual image
        if event.image_path.contains("Temp") || event.image_path.contains("AppData") {
            confidence += 0.2;
            indicators.push("path:temp".to_string());
        }
        
        // Check command line anomalies
        if event.command_line.len() > 500 || event.command_line.contains("Invoke-Expression") {
            confidence += 0.2;
            indicators.push("cmdline:anomaly".to_string());
        }
        
        confidence = confidence.min(1.0);
        
        if confidence > 0.5 {
            Ok(Some(InferenceOutput {
                domain: DetectionDomain::InjectionDetector,
                output: Tensor {
                    data: vec![confidence, indicators.len() as f32],
                    shape: vec![1, 2],
                    dtype: TensorDtype::F32,
                },
                model: "injection_detector".to_string(),
                backend: cerberus_core::inference::BackendType::Onnx,
                latency_ms: 0.0,
            }))
        } else {
            Ok(None)
        }
    }
}

impl Default for InjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for InjectionOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InjectionOperation::CreateRemoteThread => write!(f, "CreateRemoteThread"),
            InjectionOperation::WriteProcessMemory => write!(f, "WriteProcessMemory"),
            InjectionOperation::VirtualAllocEx => write!(f, "VirtualAllocEx"),
            InjectionOperation::QueueUserAPC => write!(f, "QueueUserAPC"),
            InjectionOperation::SetThreadContext => write!(f, "SetThreadContext"),
            InjectionOperation::ProcessHollowing => write!(f, "ProcessHollowing"),
            InjectionOperation::DllInjection => write!(f, "DllInjection"),
            InjectionOperation::ThreadHijacking => write!(f, "ThreadHijacking"),
            InjectionOperation::Other(s) => write!(f, "{}", s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_injection_detection() {
        let mut detector = InjectionDetector::new();
        let event = ProcessEvent {
            pid: 1234,
            ppid: 5678,
            image_path: "C:\\Temp\\malware.exe".to_string(),
            command_line: "Invoke-Expression 'bad stuff'".to_string(),
            timestamp_ns: 1_000_000_000_000,
            operation: InjectionOperation::CreateRemoteThread,
        };
        
        let result = detector.observe(event).unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().output.data[0] > 0.5);
    }
}