//! Lateral Movement Detection Module

use cerberus_core::inference::{DetectionDomain, InferenceOutput, Result, Tensor, TensorDtype};
use cerberus_core::{CerberusError, Result as CoreResult};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct NetworkConnection {
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub bytes: u64,
    pub timestamp_ns: u64,
    pub user: Option<String>,
    pub process: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HostProfile {
    pub ip: String,
    pub role: HostRole,
    pub typical_ports: Vec<u16>,
    pub typical_peers: Vec<String>,
    pub baseline_connections: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HostRole {
    Workstation,
    Server,
    DomainController,
    Database,
    WebServer,
    FileServer,
    PrintServer,
    IoT,
    Unknown,
}

pub struct LateralMovementDetector {
    connections: HashMap<String, Vec<NetworkConnection>>, // src_ip -> connections
    host_profiles: HashMap<String, HostProfile>,
    rare_edge_threshold: f32,
    admin_share_access: HashMap<String, u32>, // src_ip -> count
}

impl LateralMovementDetector {
    pub fn new(rare_edge_threshold: f32) -> Self {
        Self {
            connections: HashMap::new(),
            host_profiles: HashMap::new(),
            rare_edge_threshold,
            admin_share_access: HashMap::new(),
        }
    }
    
    pub fn register_host(&mut self, profile: HostProfile) {
        self.host_profiles.insert(profile.ip.clone(), profile);
    }
    
    pub fn observe(&mut self, conn: NetworkConnection) -> Result<Option<InferenceOutput>> {
        self.connections.entry(conn.src_ip.clone()).or_default().push(conn.clone());
        
        // Clean old (keep 1 hour)
        let cutoff = conn.timestamp_ns.saturating_sub(3600 * 1_000_000_000);
        if let Some(conns) = self.connections.get_mut(&conn.src_ip) {
            conns.retain(|c| c.timestamp_ns > cutoff);
        }
        
        let mut confidence = 0.0f32;
        let mut indicators = Vec::new();
        
        // Check for admin share access (C$, ADMIN$, IPC$)
        if conn.dst_port == 445 {
            // Would need SMB parsing for share name
            // For now, track SMB connections
            *self.admin_share_access.entry(conn.src_ip.clone()).or_insert(0) += 1;
            if self.admin_share_access[&conn.src_ip] > 5 {
                confidence += 0.4;
                indicators.push("smb:admin_shares".to_string());
            }
        }
        
        // Check for rare port/peer combinations
        if let Some(profile) = self.host_profiles.get(&conn.dst_ip) {
            if !profile.typical_ports.contains(&conn.dst_port) {
                confidence += 0.2;
                indicators.push(format!("port:rare_{}", conn.dst_port));
            }
            
            if !profile.typical_peers.contains(&conn.src_ip) {
                confidence += 0.3;
                indicators.push("peer:new".to_string());
            }
            
            // Workstation-to-workstation (unusual)
            if profile.role == HostRole::Workstation {
                if let Some(src_profile) = self.host_profiles.get(&conn.src_ip) {
                    if src_profile.role == HostRole::Workstation {
                        confidence += 0.4;
                        indicators.push("lateral:wkst_to_wkst".to_string());
                    }
                }
            }
            
            // DC access from non-admin
            if profile.role == HostRole::DomainController {
                if let Some(src_profile) = self.host_profiles.get(&conn.src_ip) {
                    if src_profile.role != HostRole::DomainController && src_profile.role != HostRole::Server {
                        confidence += 0.5;
                        indicators.push("lateral:dc_access".to_string());
                    }
                }
            }
        }
        
        // Check for pass-the-hash indicators (NTLM auth to multiple hosts)
        let unique_dsts = self.connections.get(&conn.src_ip)
            .map(|c| c.iter().filter(|x| x.dst_port == 445 || x.dst_port == 139).map(|x| x.dst_ip.clone()).collect::<std::collections::HashSet<_>>().len())
            .unwrap_or(0);
        if unique_dsts > 10 {
            confidence += 0.5;
            indicators.push(format!("pth:targets_{}", unique_dsts));
        }
        
        // Check for RDP/SSH brute then lateral
        if conn.dst_port == 3389 || conn.dst_port == 22 {
            let recent_auth = self.connections.get(&conn.src_ip)
                .map(|c| c.iter().filter(|x| x.timestamp_ns > cutoff && (x.dst_port == 3389 || x.dst_port == 22)).count())
                .unwrap_or(0);
            if recent_auth > 20 {
                confidence += 0.3;
                indicators.push("brute_then_lateral".to_string());
            }
        }
        
        // Check for WMI/RPC lateral movement ports
        if [135, 445, 139, 5985, 5986].contains(&conn.dst_port) {
            let lateral_count = self.connections.get(&conn.src_ip)
                .map(|c| c.iter().filter(|x| [135, 445, 139, 5985, 5986].contains(&x.dst_port)).count())
                .unwrap_or(0);
            if lateral_count > 5 {
                confidence += 0.3;
                indicators.push("lateral:wmi_rpc".to_string());
            }
        }
        
        confidence = confidence.min(1.0);
        
        if confidence > 0.4 {
            Ok(Some(InferenceOutput {
                domain: DetectionDomain::LateralMovement,
                output: Tensor {
                    data: vec![confidence, unique_dsts as f32],
                    shape: vec![1, 2],
                    dtype: TensorDtype::F32,
                },
                model: "lateral_movement".to_string(),
                backend: cerberus_core::inference::BackendType::Onnx,
                latency_ms: 0.0,
            }))
        } else {
            Ok(None)
        }
    }
}

impl Default for LateralMovementDetector {
    fn default() -> Self {
        Self::new(0.7)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_lateral_movement() {
        let mut detector = LateralMovementDetector::new(0.7);
        
        detector.register_host(HostProfile {
            ip: "10.0.0.10".to_string(),
            role: HostRole::Workstation,
            typical_ports: vec![80, 443, 53],
            typical_peers: vec!["10.0.0.1".to_string()],
            baseline_connections: 10,
        });
        
        detector.register_host(HostProfile {
            ip: "10.0.0.20".to_string(),
            role: HostRole::Workstation,
            typical_ports: vec![80, 443, 53],
            typical_peers: vec!["10.0.0.1".to_string()],
            baseline_connections: 10,
        });
        
        // Workstation to workstation on SMB
        for i in 0..10 {
            let conn = NetworkConnection {
                src_ip: "10.0.0.10".to_string(),
                dst_ip: "10.0.0.20".to_string(),
                dst_port: 445,
                protocol: "TCP".to_string(),
                bytes: 1024,
                timestamp_ns: 1_000_000_000_000 + i * 1_000_000_000,
                user: Some("user1".to_string()),
                process: Some("system".to_string()),
            };
            let _ = detector.observe(conn);
        }
        
        let result = detector.observe(NetworkConnection {
            src_ip: "10.0.0.10".to_string(),
            dst_ip: "10.0.0.20".to_string(),
            dst_port: 445,
            protocol: "TCP".to_string(),
            bytes: 1024,
            timestamp_ns: 1_000_000_000_000 + 10 * 1_000_000_000,
            user: Some("user1".to_string()),
            process: Some("system".to_string()),
        }).unwrap();
        
        assert!(result.is_some());
        assert!(result.unwrap().output.data[0] > 0.4);
    }
}