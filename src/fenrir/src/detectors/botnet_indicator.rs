//! Botnet Behavioral Indicators Module
//!
//! Detects behavioral indicators of botnet compromise in IoT devices
//! using network telemetry. Read-only observation only — no exploitation,
//! no state modification, no autonomous action on the device itself.
//!
//! Indicators include:
//! - Periodic beaconing to external C2 infrastructure
//! - DDoS traffic patterns (SYN floods, amplification)
//! - Unusual outbound port usage from IoT devices
//! - Scanning behavior originating from the device
//! - Communication with known-bad or geolocated-suspicious IPs

use cerberus_core::inference::{DetectionDomain, InferenceOutput, Result, Tensor, TensorDtype};
use cerberus_core::{Result as CoreResult};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// A single observed network flow from a device
#[derive(Debug, Clone)]
pub struct NetworkFlow {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: u8, // 6=TCP, 17=UDP, 1=ICMP
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub timestamp: Instant,
    pub duration_ms: u64,
}

/// Behavioral analysis window — flows within this window are analyzed together
#[derive(Debug, Clone)]
pub struct BotnetIndicatorConfig {
    pub beacon_interval_ms: u64,        // expected beacon period
    pub beacon_tolerance_ms: u64,       // +/- tolerance for beacon detection
    pub min_beacon_count: usize,        // minimum beacons to flag
    pub ddos_bytes_threshold: u64,      // bytes sent in window to flag as DDoS-like
    pub scan_dst_threshold: usize,      // unique dst IPs to flag as scanning
    pub suspicious_ports: HashSet<u16>, // ports IoT devices shouldn't contact
}

impl Default for BotnetIndicatorConfig {
    fn default() -> Self {
        let mut suspicious_ports = HashSet::new();
        // Ports IoT devices should rarely/never initiate outbound to
        suspicious_ports.insert(22);   // SSH outbound from IoT is unusual
        suspicious_ports.insert(23);   // Telnet outbound
        suspicious_ports.insert(445);  // SMB
        suspicious_ports.insert(3389); // RDP
        suspicious_ports.insert(5900); // VNC
        suspicious_ports.insert(135);  // MS-RPC
        suspicious_ports.insert(139);  // NetBIOS
        suspicious_ports.insert(6667); // IRC (classic C2)
        suspicious_ports.insert(6660); // IRC alt
        suspicious_ports.insert(6661); // IRC alt
        suspicious_ports.insert(6662); // IRC alt
        suspicious_ports.insert(6663); // IRC alt
        suspicious_ports.insert(6664); // IRC alt
        suspicious_ports.insert(6665); // IRC alt
        suspicious_ports.insert(6666); // IRC alt
        suspicious_ports.insert(6697); // IRC over TLS

        Self {
            beacon_interval_ms: 60_000,     // 1 minute expected beacon
            beacon_tolerance_ms: 10_000,    // +/- 10 seconds
            min_beacon_count: 3,            // 3+ periodic connections
            ddos_bytes_threshold: 1_000_000, // 1MB outbound in window
            scan_dst_threshold: 20,         // 20+ unique dst IPs in window
            suspicious_ports,
        }
    }
}

/// Result of botnet indicator analysis for a single device
#[derive(Debug, Clone)]
pub struct BotnetIndicatorResult {
    pub ip: IpAddr,
    pub is_suspicious: bool,
    pub suspicion_score: f32,              // 0.0 = clean, 1.0 = highly suspicious
    pub indicators: Vec<String>,
    pub beacon_detected: bool,
    pub beacon_count: usize,
    pub ddos_like: bool,
    pub scanning_like: bool,
    pub suspicious_port_contacts: Vec<u16>,
    pub flow_count: usize,
}

/// Analyzes network flows for botnet behavioral indicators.
pub struct BotnetIndicatorAnalyzer {
    config: BotnetIndicatorConfig,
    /// Per-device flow history (rolling window)
    flow_history: HashMap<IpAddr, VecDeque<NetworkFlow>>,
}

impl BotnetIndicatorAnalyzer {
    pub fn new(config: BotnetIndicatorConfig) -> Self {
        Self {
            config,
            flow_history: HashMap::new(),
        }
    }

    pub fn default() -> Self {
        Self::new(BotnetIndicatorConfig::default())
    }

    /// Add a flow to the analysis window. Returns updated indicator result
    /// for the source IP if enough data is available.
    pub fn observe_flow(&mut self, flow: NetworkFlow) -> BotnetIndicatorResult {
        self.flow_history
            .entry(flow.src_ip)
            .or_insert_with(VecDeque::new)
            .push_back(flow.clone());

        self.analyze_device(&flow.src_ip)
    }

    /// Analyze all observed flows for a device and return indicator result.
    pub fn analyze_device(&mut self, ip: &IpAddr) -> BotnetIndicatorResult {
        let flows = match self.flow_history.get(ip) {
            Some(f) => f,
            None => {
                return BotnetIndicatorResult {
                    ip: *ip,
                    is_suspicious: false,
                    suspicion_score: 0.0,
                    indicators: vec![],
                    beacon_detected: false,
                    beacon_count: 0,
                    ddos_like: false,
                    scanning_like: false,
                    suspicious_port_contacts: vec![],
                    flow_count: 0,
                };
            }
        };

        let flow_count = flows.len();
        let mut indicators: Vec<String> = Vec::new();
        let mut suspicion_score: f32 = 0.0;
        let mut is_suspicious = false;

        // --- Beacon detection ---
        let beacon_count = self.detect_beaconing(flows);
        if beacon_count >= self.config.min_beacon_count {
            indicators.push(format!("periodic_beaconing:count={}", beacon_count));
            suspicion_score += 0.35;
            is_suspicious = true;
        }

        // --- DDoS-like traffic ---
        let total_outbound: u64 = flows.iter().map(|f| f.bytes_sent).sum();
        if total_outbound > self.config.ddos_bytes_threshold {
            indicators.push(format!(
                "ddos_like_outbound:bytes={}",
                total_outbound
            ));
            suspicion_score += 0.25;
            is_suspicious = true;
        }

        // --- Scanning-like behavior ---
        let unique_dst: HashSet<IpAddr> = flows.iter().map(|f| f.dst_ip).collect();
        if unique_dst.len() >= self.config.scan_dst_threshold {
            indicators.push(format!(
                "scanning_like:unique_dst={}",
                unique_dst.len()
            ));
            suspicion_score += 0.25;
            is_suspicious = true;
        }

        // --- Suspicious port contacts ---
        let suspicious_ports: Vec<u16> = flows
            .iter()
            .filter(|f| self.config.suspicious_ports.contains(&f.dst_port))
            .map(|f| f.dst_port)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        if !suspicious_ports.is_empty() {
            let port_list: Vec<String> = suspicious_ports.iter().map(|p| p.to_string()).collect();
            indicators.push(format!("suspicious_port_contacts:{}", port_list.join(",")));
            suspicion_score += 0.15 * suspicious_ports.len() as f32;
            is_suspicious = true;
        }

        // Clamp score to [0, 1]
        suspicion_score = suspicion_score.min(1.0);

        BotnetIndicatorResult {
            ip: *ip,
            is_suspicious,
            suspicion_score,
            indicators,
            beacon_detected: beacon_count >= self.config.min_beacon_count,
            beacon_count,
            ddos_like: total_outbound > self.config.ddos_bytes_threshold,
            scanning_like: unique_dst.len() >= self.config.scan_dst_threshold,
            suspicious_port_contacts: suspicious_ports,
            flow_count,
        }
    }

    /// Detect periodic beaconing: flows to the same destination IP:port at
    /// regular intervals within tolerance.
    fn detect_beaconing(&self, flows: &VecDeque<NetworkFlow>) -> usize {
        // Group flows by destination
        let mut by_dst: HashMap<(IpAddr, u16), Vec<Instant>> = HashMap::new();
        for f in flows {
            by_dst
                .entry((f.dst_ip, f.dst_port))
                .or_insert_with(Vec::new)
                .push(f.timestamp);
        }

        let mut best_count = 0;
        for (_, mut timestamps) in by_dst {
            timestamps.sort();
            if timestamps.len() < self.config.min_beacon_count {
                continue;
            }

            // Check for regular intervals
            let mut intervals: Vec<u64> = Vec::new();
            for i in 1..timestamps.len() {
                intervals.push(
                    timestamps[i]
                        .duration_since(timestamps[i - 1])
                        .as_millis() as u64,
                );
            }

            // Count how many intervals fall within tolerance of the median
            let median_interval = intervals[intervals.len() / 2];
            let mut count = 0;
            for interval in &intervals {
                let diff = (*interval as i64 - median_interval as i64).abs() as u64;
                if diff <= self.config.beacon_tolerance_ms {
                    count += 1;
                }
            }

            if count > best_count {
                best_count = count;
            }
        }

        best_count
    }

    /// Convert a BotnetIndicatorResult into an InferenceOutput for Fenrir.
    pub fn to_inference_output(&self, result: &BotnetIndicatorResult) -> Result<InferenceOutput> {
        let data: Vec<f32> = vec![
            result.suspicion_score,
            if result.is_suspicious { 1.0 } else { 0.0 },
            if result.beacon_detected { 1.0 } else { 0.0 },
            if result.ddos_like { 1.0 } else { 0.0 },
            if result.scanning_like { 1.0 } else { 0.0 },
            result.suspicious_port_contacts.len() as f32,
            result.flow_count as f32,
        ];

        Ok(InferenceOutput {
            domain: DetectionDomain::IotDiscovery,
            output: Tensor {
                data,
                shape: vec![1, 7],
                dtype: TensorDtype::F32,
            },
            model: "botnet_indicator_analyzer".to_string(),
            backend: cerberus_core::inference::BackendType::Onnx,
            latency_ms: 0.0,
        })
    }

    /// Get flow count for a device (for testing / external inspection)
    pub fn flow_count_for(&self, ip: &IpAddr) -> usize {
        self.flow_history
            .get(ip)
            .map(|f| f.len())
            .unwrap_or(0)
    }
}

impl Default for BotnetIndicatorAnalyzer {
    fn default() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn make_flow(src: IpAddr, dst: IpAddr, dst_port: u16, bytes_sent: u64, millis_offset: u64) -> NetworkFlow {
        NetworkFlow {
            src_ip: src,
            src_port: 12345,
            dst_ip: dst,
            dst_port,
            protocol: 6,
            bytes_sent,
            bytes_received: 100,
            timestamp: Instant::now() + Duration::from_millis(millis_offset),
            duration_ms: 10,
        }
    }

    #[test]
    fn test_clean_device_no_indicators() {
        let mut analyzer = BotnetIndicatorAnalyzer::default();
        let ip: IpAddr = "192.168.12.117".parse().unwrap();

        // Single normal HTTP flow
        analyzer.observe_flow(make_flow(
            ip,
            "192.168.12.1".parse().unwrap(),
            80,
            500,
            0,
        ));

        let result = analyzer.analyze_device(&ip);
        assert!(!result.is_suspicious);
        assert_eq!(result.suspicion_score, 0.0);
    }

    #[test]
    fn test_beaconing_detection() {
        let mut analyzer = BotnetIndicatorAnalyzer::default();
        let ip: IpAddr = "192.168.12.117".parse().unwrap();
        let c2: IpAddr = "203.0.113.42".parse().unwrap();

        // 5 periodic beacons at ~60s intervals
        for i in 0..5 {
            analyzer.observe_flow(make_flow(ip, c2, 6667, 128, i * 60_000));
        }

        let result = analyzer.analyze_device(&ip);
        assert!(result.beacon_detected);
        assert!(result.is_suspicious);
        assert!(result.suspicion_score > 0.3);
        assert!(
            result
                .indicators
                .iter()
                .any(|i| i.contains("periodic_beaconing"))
        );
    }

    #[test]
    fn test_ddos_like_detection() {
        let mut analyzer = BotnetIndicatorAnalyzer::default();
        let ip: IpAddr = "192.168.12.117".parse().unwrap();
        let target: IpAddr = "198.51.100.7".parse().unwrap();

        // Large outbound to single target
        analyzer.observe_flow(make_flow(ip, target, 80, 2_000_000, 0));

        let result = analyzer.analyze_device(&ip);
        assert!(result.ddos_like);
        assert!(result.is_suspicious);
    }

    #[test]
    fn test_scanning_like_detection() {
        let mut analyzer = BotnetIndicatorAnalyzer::default();
        let ip: IpAddr = "192.168.12.117".parse().unwrap();

        // Contacts to 25 different destination IPs
        for i in 0..25 {
            let dst = format!("10.0.0.{}", i + 1).parse().unwrap();
            analyzer.observe_flow(make_flow(ip, dst, 80, 100, i as u64 * 100));
        }

        let result = analyzer.analyze_device(&ip);
        assert!(result.scanning_like);
        assert!(result.is_suspicious);
    }

    #[test]
    fn test_suspicious_port_contact() {
        let mut analyzer = BotnetIndicatorAnalyzer::default();
        let ip: IpAddr = "192.168.12.117".parse().unwrap();
        let dst: IpAddr = "203.0.113.99".parse().unwrap();

        // Contact on IRC C2 port
        analyzer.observe_flow(make_flow(ip, dst, 6667, 512, 0));

        let result = analyzer.analyze_device(&ip);
        assert!(
            result
                .suspicious_port_contacts
                .contains(&6667),
            "expected suspicious port 6667 in contacts"
        );
        assert!(result.is_suspicious);
    }

    #[test]
    fn test_default_config_suspicious_ports() {
        let config = BotnetIndicatorConfig::default();
        assert!(config.suspicious_ports.contains(&22));
        assert!(config.suspicious_ports.contains(&6667));
        assert!(config.suspicious_ports.contains(&6697));
        assert!(!config.suspicious_ports.contains(&80));
        assert!(!config.suspicious_ports.contains(&443));
    }

    #[test]
    fn test_ipv6_support() {
        let mut analyzer = BotnetIndicatorAnalyzer::default();
        let ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        let dst: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));

        // 4 periodic beacons at ~60s intervals (3 matching intervals)
        analyzer.observe_flow(make_flow(ip, dst, 6667, 128, 0));
        analyzer.observe_flow(make_flow(ip, dst, 6667, 128, 60_000));
        analyzer.observe_flow(make_flow(ip, dst, 6667, 128, 120_000));
        analyzer.observe_flow(make_flow(ip, dst, 6667, 128, 180_000));

        let result = analyzer.analyze_device(&ip);
        assert_eq!(result.flow_count, 4);
        assert!(result.beacon_detected);
    }
}
