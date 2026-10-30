//! Network Reconnaissance Detection Module
//!
//! Active host discovery, port scanning, and service banner grabbing
//! for the Fenrir Hunter component. Operates under explicit operator
//! authorization only - never self-propagates, never acts autonomously.

use cerberus_core::inference::{DetectionDomain, InferenceOutput, Result, Tensor, TensorDtype};
use cerberus_core::{CerberusError, Result as CoreResult};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Result of a single port probe
#[derive(Debug, Clone)]
pub struct PortProbe {
    pub port: u16,
    pub open: bool,
    pub response_time_ms: Option<f64>,
    pub banner: Option<String>,
}

/// Result of scanning a single host
#[derive(Debug, Clone)]
pub struct HostScanResult {
    pub ip: IpAddr,
    pub host_up: bool,
    pub open_ports: Vec<PortProbe>,
    pub scan_duration_ms: u64,
}

/// Configuration for the network recon detector
#[derive(Debug, Clone)]
pub struct NetworkReconConfig {
    pub connect_timeout_ms: u64,
    pub scan_timeout_ms: u64,
    pub max_concurrent_scans: usize,
    pub common_ports: Vec<u16>,
    pub banner_max_bytes: usize,
}

impl Default for NetworkReconConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 2000,
            scan_timeout_ms: 30000,
            max_concurrent_scans: 50,
            common_ports: vec![
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
                631, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6379,
                8080, 8443, 9000, 9100, 27017, 7000,
            ],
            banner_max_bytes: 1024,
        }
    }
}

/// Network reconnaissance detector - discovers hosts, open ports, and service banners
pub struct NetworkReconDetector {
    config: NetworkReconConfig,
    scan_history: HashMap<IpAddr, Vec<HostScanResult>>,
}

impl NetworkReconDetector {
    pub fn new(config: NetworkReconConfig) -> Self {
        Self {
            config,
            scan_history: HashMap::new(),
        }
    }

    /// Probe a single TCP port on a target host. Returns open/closed state,
    /// response time, and any banner data received.
    pub async fn probe_port(&self, ip: IpAddr, port: u16) -> CoreResult<PortProbe> {
        let addr = SocketAddr::new(ip, port);
        let start = Instant::now();

        match timeout(
            Duration::from_millis(self.config.connect_timeout_ms),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(stream)) => {
                let response_time_ms = start.elapsed().as_secs_f64() * 1000.0;
                let banner = self.grab_banner(stream, self.config.banner_max_bytes).await.ok().flatten();
                Ok(PortProbe {
                    port,
                    open: true,
                    response_time_ms: Some(response_time_ms),
                    banner,
                })
            }
            Ok(Err(e)) => Ok(PortProbe {
                port,
                open: false,
                response_time_ms: None,
                banner: None,
            }),
            Err(_) => Ok(PortProbe {
                port,
                open: false,
                response_time_ms: None,
                banner: None,
            }),
        }
    }

    /// Attempt to grab a service banner from an open TCP stream.
    async fn grab_banner(
        &self,
        mut stream: TcpStream,
        max_bytes: usize,
    ) -> CoreResult<Option<String>> {
        use tokio::io::AsyncReadExt;

        let mut buf = vec![0u8; max_bytes];
        match timeout(
            Duration::from_millis(self.config.connect_timeout_ms),
            stream.read(&mut buf),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => {
                let banner = String::from_utf8_lossy(&buf[..n])
                    .trim()
                    .replace("\r\n", " ")
                    .replace('\n', " ")
                    .replace('\r', " ")
                    .to_string();
                Ok(Some(banner))
            }
            _ => Ok(None),
        }
    }

    /// Scan a single host across the configured common ports.
    pub async fn scan_host(&mut self, ip: IpAddr) -> CoreResult<HostScanResult> {
        let start = Instant::now();

        // First, check if host is up by probing a few common ports
        let probe_ports: Vec<u16> = self.config.common_ports.clone();

        let mut futures = Vec::new();
        for port in &probe_ports {
            futures.push(self.probe_port(ip, *port));
        }

        let mut open_ports: Vec<PortProbe> = Vec::new();
        for fut in futures {
            match fut.await {
                Ok(probe) if probe.open => open_ports.push(probe),
                _ => {}
            }
        }

        let host_up = !open_ports.is_empty();
        let duration_ms = start.elapsed().as_millis() as u64;

        let scan_result = HostScanResult {
            ip,
            host_up,
            open_ports: open_ports.clone(),
            scan_duration_ms: duration_ms,
        };

        self.scan_history
            .entry(ip)
            .or_default()
            .push(scan_result.clone());

        Ok(scan_result)
    }

    /// Discover active hosts on a /24 subnet by scanning common ports.
    /// Limited to 256 addresses - use with explicit operator authorization.
    pub async fn discover_hosts(&mut self, subnet_prefix: &str) -> CoreResult<Vec<HostScanResult>> {
        let parts: Vec<&str> = subnet_prefix.split('.').collect();
        if parts.len() != 3 {
            return Err(CerberusError::Validation(
                "subnet_prefix must be in format a.b.c".to_string(),
            ));
        }

        let mut results: Vec<HostScanResult> = Vec::new();

        for i in 0..=255u8 {
            let ip_str = format!("{}.{}", subnet_prefix, i);
            let ip: IpAddr = ip_str.parse().map_err(|e| {
                CerberusError::Validation(format!("invalid IP {}: {}", ip_str, e))
            })?;
            if let Ok(sr) = self.scan_host(ip).await {
                if sr.host_up {
                    results.push(sr);
                }
            }
        }

        // Sort by IP for deterministic output
        results.sort_by_key(|sr: &HostScanResult| match sr.ip {
            IpAddr::V4(v4) => u128::from(u32::from(v4)),
            IpAddr::V6(_) => u128::MAX,
        });

        Ok(results)
    }

    /// Analyze scan results and produce an InferenceOutput if anomalies are detected.
    /// Anomalies include: unexpected open ports, unknown services, high port counts.
    pub fn analyze_scan(&self, scan: &HostScanResult) -> Result<Option<InferenceOutput>> {
        let mut confidence = 0.0f32;
        let mut indicators = Vec::new();

        // Any host up is notable in a controlled environment
        if scan.host_up {
            confidence += 0.1;
            indicators.push(format!("host_up:{}", scan.ip));
        }

        // Count open ports
        let open_count = scan.open_ports.len();
        if open_count > 0 {
            confidence += 0.2;
            indicators.push(format!("open_ports:{}", open_count));
        }

        // High port count = potentially exposed host
        if open_count > 10 {
            confidence += 0.3;
            indicators.push("high_port_count".to_string());
        }

        // Check for sensitive ports
        let sensitive_ports: Vec<u16> = vec![22, 23, 445, 3389, 5900, 6379, 27017];
        for probe in &scan.open_ports {
            if sensitive_ports.contains(&probe.port) {
                confidence += 0.2;
                indicators.push(format!("sensitive_port:{}", probe.port));
            }
            // Check for unknown/unexpected banners
            if let Some(banner) = &probe.banner {
                if banner.len() > 50 {
                    confidence += 0.1;
                    indicators.push(format!("verbose_banner:{}", probe.port));
                }
            }
        }

        confidence = confidence.min(1.0);

        if confidence > 0.3 {
            let mut data: Vec<f32> = vec![
                confidence,
                open_count as f32,
                if scan.host_up { 1.0 } else { 0.0 },
            ];
            // Add sensitive port count
            let sensitive_count = scan
                .open_ports
                .iter()
                .filter(|p| sensitive_ports.contains(&p.port))
                .count() as f32;
            data.push(sensitive_count);

            Ok(Some(InferenceOutput {
                domain: DetectionDomain::NetworkRecon,
                output: Tensor {
                    data,
                    shape: vec![1, 4],
                    dtype: TensorDtype::F32,
                },
                model: "network_recon".to_string(),
                backend: cerberus_core::inference::BackendType::Onnx,
                latency_ms: scan.scan_duration_ms as f32,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn scan_history(&self) -> &HashMap<IpAddr, Vec<HostScanResult>> {
        &self.scan_history
    }
}

impl Default for NetworkReconDetector {
    fn default() -> Self {
        Self::new(NetworkReconConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_config_defaults() {
        let config = NetworkReconConfig::default();
        assert_eq!(config.connect_timeout_ms, 2000);
        assert!(config.common_ports.contains(&7000)); // Ecobee port
        assert!(config.common_ports.contains(&22)); // SSH
        assert!(config.common_ports.contains(&443)); // HTTPS
    }

    #[test]
    fn test_analyze_scan_no_anomaly() {
        let detector = NetworkReconDetector::default();
        let scan = HostScanResult {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            host_up: false,
            open_ports: Vec::new(),
            scan_duration_ms: 100,
        };

        let result = detector.analyze_scan(&scan).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_analyze_scan_anomaly() {
        let detector = NetworkReconDetector::default();
        let scan = HostScanResult {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)),
            host_up: true,
            open_ports: vec![
                PortProbe {
                    port: 22,
                    open: true,
                    response_time_ms: Some(5.0),
                    banner: Some("SSH-2.0-OpenSSH_8.9".to_string()),
                },
                PortProbe {
                    port: 443,
                    open: true,
                    response_time_ms: Some(12.0),
                    banner: None,
                },
            ],
            scan_duration_ms: 500,
        };

        let result = detector.analyze_scan(&scan).unwrap();
        assert!(result.is_some());
        let output = result.unwrap();
        assert_eq!(output.domain, DetectionDomain::NetworkRecon);
        assert!(output.output.data[0] > 0.3);
    }

    #[test]
    fn test_parse_ip() {
        let ip: IpAddr = "192.168.12.117".parse().unwrap();
        match ip {
            IpAddr::V4(v4) => assert_eq!(v4, Ipv4Addr::new(192, 168, 12, 117)),
            IpAddr::V6(_) => panic!("expected IPv4"),
        }
    }
}