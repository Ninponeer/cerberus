//! Credential Abuse Detection Module

use cerberus_core::inference::{DetectionDomain, InferenceOutput, Result, Tensor, TensorDtype};
use cerberus_core::{CerberusError, Result as CoreResult};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct AuthEvent {
    pub user: String,
    pub source_ip: String,
    pub target_host: String,
    pub auth_type: AuthType,
    pub result: AuthResult,
    pub timestamp_ns: u64,
    pub logon_type: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthType {
    Kerberos,
    NTLM,
    LDAP,
    RDP,
    SSH,
    VPN,
    Web,
    Other(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthResult {
    Success,
    Failure(u32), // error code
    Lockout,
}

pub struct CredentialAbuseDetector {
    failed_attempts: HashMap<String, Vec<u64>>, // user@source -> timestamps
    successful_logons: HashMap<String, Vec<u64>>,
    lockout_threshold: usize,
    time_window_sec: u64,
    impossible_travel: HashMap<String, (String, u64)>, // user -> (location, timestamp)
}

impl CredentialAbuseDetector {
    pub fn new(lockout_threshold: usize, time_window_sec: u64) -> Self {
        Self {
            failed_attempts: HashMap::new(),
            successful_logons: HashMap::new(),
            lockout_threshold,
            time_window_sec,
            impossible_travel: HashMap::new(),
        }
    }
    
    pub fn observe(&mut self, event: AuthEvent) -> Result<Option<InferenceOutput>> {
        let key = format!("{}@{}", event.user, event.source_ip);
        let mut confidence = 0.0f32;
        let mut indicators = Vec::new();
        
        match event.result {
            AuthResult::Failure(code) => {
                self.failed_attempts.entry(key.clone()).or_default().push(event.timestamp_ns);
                Self::clean_old(self.time_window_sec, &mut self.failed_attempts, event.timestamp_ns);
                
                if let Some(attempts) = self.failed_attempts.get(&key) {
                    if attempts.len() >= self.lockout_threshold {
                        confidence += 0.6;
                        indicators.push(format!("bruteforce:{}", attempts.len()));
                    }
                }
                
                // Check for specific error codes
                match code {
                    0xC000006A => { indicators.push("error:bad_password".to_string()); } // STATUS_WRONG_PASSWORD
                    0xC000006D => { indicators.push("error:bad_username".to_string()); } // STATUS_LOGON_FAILURE
                    0xC000006E => { confidence += 0.2; indicators.push("error:account_restriction".to_string()); }
                    0xC000006F => { confidence += 0.3; indicators.push("error:time_restriction".to_string()); }
                    0xC0000070 => { confidence += 0.3; indicators.push("error:workstation_restriction".to_string()); }
                    0xC0000071 => { confidence += 0.2; indicators.push("error:password_expired".to_string()); }
                    0xC0000072 => { confidence += 0.4; indicators.push("error:account_disabled".to_string()); }
                    0xC0000193 => { confidence += 0.5; indicators.push("error:account_locked".to_string()); }
                    _ => {}
                }
            }
            AuthResult::Success => {
                self.successful_logons.entry(key.clone()).or_default().push(event.timestamp_ns);
                Self::clean_old(self.time_window_sec, &mut self.successful_logons, event.timestamp_ns);
                
                // Check for impossible travel
                if let Some((last_loc, last_time)) = self.impossible_travel.get(&event.user) {
                    let time_diff = event.timestamp_ns.saturating_sub(*last_time);
                    // If same user logs in from different location within 1 hour (impossible travel)
                    if time_diff < 3600 * 1_000_000_000 && last_loc != &event.source_ip {
                        confidence += 0.8;
                        indicators.push(format!("impossible_travel:{}->{}", last_loc, event.source_ip));
                    }
                }
                self.impossible_travel.insert(event.user.clone(), (event.source_ip.clone(), event.timestamp_ns));
            }
            AuthResult::Lockout => {
                confidence += 0.9;
                indicators.push("account_lockout".to_string());
            }
        }
        
        // Check for unusual logon type
        if let Some(lt) = event.logon_type {
            // 3 = Network, 9 = NewCredentials, 10 = RemoteInteractive
            if [9, 10].contains(&lt) && event.auth_type == AuthType::NTLM {
                confidence += 0.3;
                indicators.push(format!("logon_type:{}", lt));
            }
        }
        
        // Check for password spray (many users, one source, few attempts each)
        let source_failures = self.failed_attempts.iter()
            .filter(|(k, _)| k.ends_with(&format!("@{}", event.source_ip)))
            .count();
        if source_failures > 20 {
            confidence += 0.4;
            indicators.push("password_spray".to_string());
        }
        
        confidence = confidence.min(1.0);
        
        if confidence > 0.4 {
            Ok(Some(InferenceOutput {
                domain: DetectionDomain::CredentialAbuse,
                output: Tensor {
                    data: vec![confidence, indicators.len() as f32],
                    shape: vec![1, 2],
                    dtype: TensorDtype::F32,
                },
                model: "credential_abuse".to_string(),
                backend: cerberus_core::inference::BackendType::Onnx,
                latency_ms: 0.0,
            }))
        } else {
            Ok(None)
        }
    }
    
    fn clean_old(time_window_sec: u64, map: &mut HashMap<String, Vec<u64>>, now_ns: u64) {
        let cutoff = now_ns.saturating_sub(time_window_sec * 1_000_000_000);
        for timestamps in map.values_mut() {
            timestamps.retain(|&ts| ts > cutoff);
        }
        map.retain(|_, v| !v.is_empty());
    }
}

impl Default for CredentialAbuseDetector {
    fn default() -> Self {
        Self::new(5, 300) // 5 failures in 5 minutes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bruteforce_detection() {
        let mut detector = CredentialAbuseDetector::new(5, 300);
        let base = 1_000_000_000_000u64;
        
        for i in 0..6 {
            let event = AuthEvent {
                user: "admin".to_string(),
                source_ip: "10.0.0.100".to_string(),
                target_host: "dc01".to_string(),
                auth_type: AuthType::Kerberos,
                result: AuthResult::Failure(0xC000006A),
                timestamp_ns: base + i * 10_000_000_000,
                logon_type: Some(3),
            };
            let _ = detector.observe(event);
        }
        
        let result = detector.observe(AuthEvent {
            user: "admin".to_string(),
            source_ip: "10.0.0.100".to_string(),
            target_host: "dc01".to_string(),
            auth_type: AuthType::Kerberos,
            result: AuthResult::Failure(0xC000006A),
            timestamp_ns: base + 6 * 10_000_000_000,
            logon_type: Some(3),
        }).unwrap();
        
        assert!(result.is_some());
        assert!(result.unwrap().output.data[0] > 0.5);
    }
    
    #[test]
    fn test_impossible_travel() {
        let mut detector = CredentialAbuseDetector::new(5, 300);
        let base = 1_000_000_000_000u64;
        
        let event1 = AuthEvent {
            user: "alice".to_string(),
            source_ip: "10.0.0.50".to_string(),
            target_host: "app01".to_string(),
            auth_type: AuthType::Kerberos,
            result: AuthResult::Success,
            timestamp_ns: base,
            logon_type: Some(10),
        };
        detector.observe(event1).unwrap();
        
        // Impossible travel - same user, different IP, within 1 hour
        let event2 = AuthEvent {
            user: "alice".to_string(),
            source_ip: "10.0.1.100".to_string(),
            target_host: "app02".to_string(),
            auth_type: AuthType::Kerberos,
            result: AuthResult::Success,
            timestamp_ns: base + 30 * 60 * 1_000_000_000, // 30 minutes later
            logon_type: Some(10),
        };
        let result = detector.observe(event2).unwrap();
        
        assert!(result.is_some());
        assert!(result.unwrap().output.data[0] > 0.7);
    }
}