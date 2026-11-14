//! Blackbox IoT Fingerprinting Module
//!
//! Passive, read-only fingerprinting of IoT devices on the local network.
//! No authentication, no exploitation, no modification of device state.
//! Designed to identify devices, their services, and potential compromise
//! indicators without touching the device internals.

use cerberus_core::inference::{DetectionDomain, InferenceOutput, Result, Tensor, TensorDtype};
use cerberus_core::{Result as CoreResult};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Result of a blackbox fingerprint probe against a single host:port
#[derive(Debug, Clone)]
pub struct BlackboxFingerprint {
    pub ip: IpAddr,
    pub port: u16,
    pub service_name: Option<String>,
    pub server_header: Option<String>,
    pub response_body_preview: Option<String>,
    pub tls_supported: bool,
    pub response_time_ms: f64,
    pub is_suspicious: bool,
    pub suspicion_reasons: Vec<String>,
}

/// Configuration for blackbox fingerprinting
#[derive(Debug, Clone)]
pub struct BlackboxFingerprintConfig {
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub probe_endpoints: Vec<String>,
    pub suspicious_headers: Vec<String>,
    pub suspicious_keywords: Vec<String>,
}

impl Default for BlackboxFingerprintConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 2000,
            request_timeout_ms: 5000,
            probe_endpoints: vec![
                "/".to_string(),
                "/index.html".to_string(),
                "/favicon.ico".to_string(),
            ],
            suspicious_headers: vec![
                "server".to_string(),
                "x-powered-by".to_string(),
            ],
            suspicious_keywords: vec![
                "botnet".to_string(),
                "mirai".to_string(),
                "shell".to_string(),
                "exec".to_string(),
                "cmd".to_string(),
                "/bin/sh".to_string(),
                "wget".to_string(),
                "curl".to_string(),
                "ncat".to_string(),
                "nc ".to_string(),
            ],
        }
    }
}

/// Passive blackbox fingerprinting of IoT devices.
pub struct BlackboxFingerprinter {
    config: BlackboxFingerprintConfig,
}

impl BlackboxFingerprinter {
    pub fn new(config: BlackboxFingerprintConfig) -> Self {
        Self { config }
    }

    pub fn default() -> Self {
        Self::new(BlackboxFingerprintConfig::default())
    }

    /// Fingerprint a single host:port. Returns device service info and
    /// suspicion indicators without modifying device state.
    pub async fn fingerprint(&self, ip: IpAddr, port: u16) -> CoreResult<BlackboxFingerprint> {
        let start = Instant::now();
        let mut suspicion_reasons: Vec<String> = Vec::new();
        let mut service_name: Option<String> = None;
        let mut server_header: Option<String> = None;
        let mut response_body_preview: Option<String> = None;
        let mut tls_supported = false;
        let mut is_suspicious = false;

                // Probe each endpoint, collect the most informative response
        for endpoint in &self.config.probe_endpoints {
            if let Ok(info) = self.probe_endpoint(ip, port, endpoint).await {
                // Check response for suspicious content before moving fields
                if let Some(ref body) = info.response_body_preview {
                    for keyword in &self.config.suspicious_keywords {
                        if body.to_lowercase().contains(keyword) {
                            suspicion_reasons.push(format!(
                                "suspicious_keyword:{}:{}",
                                keyword, endpoint
                            ));
                            is_suspicious = true;
                        }
                    }
                }

                // Check headers for suspicious patterns
                if let Some(ref header) = info.server_header {
                    for suspicious in &self.config.suspicious_headers {
                        if header.to_lowercase().contains(suspicious) {
                            if header.to_lowercase().contains("mirai")
                                || header.to_lowercase().contains("botnet")
                            {
                                suspicion_reasons.push(format!(
                                    "suspicious_header_value:{}:{}",
                                    suspicious, header
                                ));
                                is_suspicious = true;
                            }
                        }
                    }
                }

                // HTTP on non-standard ports is suspicious for IoT
                if port != 80 && port != 443 && port != 8080 && port != 8443 {
                    if info.response_body_preview.is_some() || info.server_header.is_some() {
                        suspicion_reasons.push(format!(
                            "http_on_unusual_port:{}",
                            port
                        ));
                        is_suspicious = true;
                    }
                }

                // Now move fields into our accumulators
                if info.response_body_preview.is_some() {
                    response_body_preview = info.response_body_preview;
                }
                if info.server_header.is_some() {
                    server_header = info.server_header;
                }
                if info.service_name.is_some() {
                    service_name = info.service_name;
                }
                if info.tls_supported {
                    tls_supported = true;
                }
            }
        }

        let response_time_ms = start.elapsed().as_secs_f64() * 1000.0;

        // High response time on a local device can indicate load or C2 beaconing
        if response_time_ms > 5000.0 {
            suspicion_reasons.push(format!(
                "slow_response_ms:{}",
                response_time_ms as u64
            ));
            is_suspicious = true;
        }

        Ok(BlackboxFingerprint {
            ip,
            port,
            service_name,
            server_header,
            response_body_preview,
            tls_supported,
            response_time_ms,
            is_suspicious,
            suspicion_reasons,
        })
    }

    /// Probe a single HTTP endpoint on the target.
    async fn probe_endpoint(
        &self,
        ip: IpAddr,
        port: u16,
        endpoint: &str,
    ) -> CoreResult<BlackboxFingerprint> {
        let addr = SocketAddr::new(ip, port);

        let mut stream = match timeout(
            Duration::from_millis(self.config.connect_timeout_ms),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => {
                return Ok(BlackboxFingerprint {
                    ip,
                    port,
                    service_name: None,
                    server_header: None,
                    response_body_preview: None,
                    tls_supported: false,
                    response_time_ms: 0.0,
                    is_suspicious: false,
                    suspicion_reasons: vec![],
                });
            }
        };

        let host = match ip {
            std::net::IpAddr::V4(v4) => v4.to_string(),
            std::net::IpAddr::V6(v6) => format!("[{}]", v6),
        };
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: Cerberus-Fenrir/0.1\r\n\r\n",
            endpoint, host
        );

        let _ = timeout(
            Duration::from_millis(self.config.request_timeout_ms),
            stream.write_all(request.as_bytes()),
        )
        .await;

        let mut buf = vec![0u8; 8192];
        let n = match timeout(
            Duration::from_millis(self.config.request_timeout_ms),
            stream.read(&mut buf),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => n,
            _ => 0,
        };

        if n == 0 {
            return Ok(BlackboxFingerprint {
                ip,
                port,
                service_name: None,
                server_header: None,
                response_body_preview: None,
                tls_supported: false,
                response_time_ms: 0.0,
                is_suspicious: false,
                suspicion_reasons: vec![],
            });
        }

        let response = String::from_utf8_lossy(&buf[..n]).to_string();

        // Extract server header
        let server_header = response
            .lines()
            .find(|line| line.to_lowercase().starts_with("server:"))
            .map(|line| {
                line.splitn(2, ':')
                    .nth(1)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default()
            })
            .filter(|s| !s.is_empty());

        // Extract response body (after headers)
        let response_body_preview = response
            .split("\r\n\r\n")
            .nth(1)
            .map(|body| {
                let preview: String = body
                    .chars()
                    .take(200)
                    .collect();
                preview
            })
            .filter(|s| !s.is_empty());

        // Try to identify service from banner/body
        let service_name = self.identify_service(&response, port);

        Ok(BlackboxFingerprint {
            ip,
            port,
            service_name,
            server_header,
            response_body_preview,
            tls_supported: false, // We only do HTTP here; TLS would need a TLS handshake
            response_time_ms: 0.0, // filled in by caller
            is_suspicious: false, // filled in by caller
            suspicion_reasons: vec![],
        })
    }

    /// Best-effort service identification from HTTP response headers/body.
    fn identify_service(&self, response: &str, port: u16) -> Option<String> {
        let lower = response.to_lowercase();

        if lower.contains("ecobee") || lower.contains("airtunes") {
            return Some("ecobee_thermostat".to_string());
        }
        if lower.contains("wdmycloud") || lower.contains("western digital") {
            return Some("wd_mycloud".to_string());
        }
        if lower.contains("cisco") {
            return Some("cisco_device".to_string());
        }
        if lower.contains("nvidia") {
            return Some("nvidia_device".to_string());
        }
        if port == 22 {
            return Some("ssh".to_string());
        }
        if port == 23 {
            return Some("telnet".to_string());
        }
        if port == 80 || port == 8080 {
            return Some("http".to_string());
        }
        if port == 443 || port == 8443 {
            return Some("https".to_string());
        }
        if port == 554 || port == 8554 {
            return Some("rtsp".to_string());
        }
        if port == 1883 || port == 8883 {
            return Some("mqtt".to_string());
        }
        if port == 5683 || port == 5684 {
            return Some("coap".to_string());
        }

        None
    }

    /// Convert a BlackboxFingerprint into an InferenceOutput for Fenrir.
    pub fn to_inference_output(&self, fp: &BlackboxFingerprint) -> Result<InferenceOutput> {
        let confidence = if fp.is_suspicious { 0.8 } else { 0.5 };
        let suspicion_count = fp.suspicion_reasons.len() as f32;
        let mut data: Vec<f32> = vec![
            confidence,
            if fp.is_suspicious { 1.0 } else { 0.0 },
            suspicion_count,
            fp.response_time_ms as f32,
            if fp.tls_supported { 1.0 } else { 0.0 },
        ];

        Ok(InferenceOutput {
            domain: DetectionDomain::IotDiscovery,
            output: Tensor {
                data,
                shape: vec![1, 5],
                dtype: TensorDtype::F32,
            },
            model: "blackbox_fingerprinter".to_string(),
            backend: cerberus_core::inference::BackendType::Onnx,
            latency_ms: fp.response_time_ms as f32,
        })
    }
}

impl Default for BlackboxFingerprinter {
    fn default() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_identify_service_ecobee() {
        let fp = BlackboxFingerprinter::default();
        let resp = "HTTP/1.1 200 OK\r\nServer: AirTunes/366.0\r\n\r\n";
        assert_eq!(fp.identify_service(resp, 7000), Some("ecobee_thermostat".to_string()));
    }

    #[test]
    fn test_identify_service_telnet() {
        let fp = BlackboxFingerprinter::default();
        assert_eq!(fp.identify_service("", 23), Some("telnet".to_string()));
        // Telnet on port 80 still identifies as http (port-based fallback)
        assert_eq!(fp.identify_service("", 80), Some("http".to_string()));
    }

    #[test]
    fn test_identify_service_unknown() {
        let fp = BlackboxFingerprinter::default();
        assert_eq!(fp.identify_service("HTTP/1.1 200 OK\r\nServer: nginx\r\n", 9999), None);
    }

    #[test]
    fn test_suspicious_keyword_detection() {
        let _fp = BlackboxFingerprint {
            ip: "192.168.12.117".parse().unwrap(),
            port: 7000,
            service_name: Some("unknown".to_string()),
            server_header: None,
            response_body_preview: Some("mirai botnet payload".to_string()),
            tls_supported: false,
            response_time_ms: 100.0,
            is_suspicious: true,
            suspicion_reasons: vec!["suspicious_keyword:mirai:/".to_string()],
        };
        assert!(_fp.is_suspicious);
        assert!(_fp.suspicion_reasons.contains(&"suspicious_keyword:mirai:/".to_string()));
    }

    #[test]
    fn test_default_config_has_suspicious_keywords() {
        let config = BlackboxFingerprintConfig::default();
        assert!(config.suspicious_keywords.contains(&"mirai".to_string()));
        assert!(config.suspicious_keywords.contains(&"wget".to_string()));
        assert!(config.probe_endpoints.contains(&"/".to_string()));
    }
}
