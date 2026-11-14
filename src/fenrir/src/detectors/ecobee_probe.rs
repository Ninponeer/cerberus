//! Ecobee Thermostat Probe Module
//!
//! Passive discovery and telemetry gathering for Ecobee smart thermostats.
//! Operates under explicit operator authorization only - read-only HTTP GET
//! requests to the local thermostat API. Never exploits, never modifies device
//! state, never acts autonomously.

use cerberus_core::inference::{DetectionDomain, InferenceOutput, Result, Tensor, TensorDtype};
use cerberus_core::{Result as CoreResult};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Information gathered from an Ecobee probe
#[derive(Debug, Clone)]
pub struct EcobeeDeviceInfo {
    pub ip: IpAddr,
    pub port: u16,
    pub is_ecobee: bool,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
    pub device_id: Option<String>,
    pub temperature_f: Option<f32>,
    pub humidity_pct: Option<f32>,
    pub hvac_mode: Option<String>,
    pub raw_banner: Option<String>,
}

/// Configuration for Ecobee probing
#[derive(Debug, Clone)]
pub struct EcobeeProbeConfig {
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub probe_ports: Vec<u16>,
}

impl Default for EcobeeProbeConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 2000,
            request_timeout_ms: 5000,
            probe_ports: vec![80, 443, 7000],
        }
    }
}

/// Passive Ecobee thermostat probe. Attempts to identify Ecobee devices on the
/// local network and gather basic telemetry via read-only HTTP requests.
pub struct EcobeeProbe {
    config: EcobeeProbeConfig,
}

impl EcobeeProbe {
    pub fn new(config: EcobeeProbeConfig) -> Self {
        Self { config }
    }

    pub fn default() -> Self {
        Self::new(EcobeeProbeConfig::default())
    }

    /// Probe a single IP:port for an Ecobee thermostat. Returns device info
    /// if an Ecobee signature is detected, or a negative result if not.
    pub async fn probe(&self, ip: IpAddr, port: u16) -> CoreResult<EcobeeDeviceInfo> {
        let start = Instant::now();

        // Try HTTP GET on common Ecobee endpoints
        let endpoints = ["/", "/ecobee/api", "/api", "/thermostat"];
        let mut best_info = EcobeeDeviceInfo {
            ip,
            port,
            is_ecobee: false,
            model: None,
            firmware_version: None,
            device_id: None,
            temperature_f: None,
            humidity_pct: None,
            hvac_mode: None,
            raw_banner: None,
        };

        for endpoint in &endpoints {
            if let Ok(info) = self.probe_endpoint(ip, port, endpoint).await {
                if info.is_ecobee {
                    // Merge the best result (most complete)
                    best_info = self.merge_info(best_info, info);
                } else if best_info.raw_banner.is_none() {
                    best_info.raw_banner = info.raw_banner;
                }
            }
        }

        let _elapsed = start.elapsed();

        // Try to extract temperature/humidity from raw data if available
        if let Some(ref banner) = best_info.raw_banner {
            best_info.temperature_f = self.extract_temperature(banner);
            best_info.humidity_pct = self.extract_humidity(banner);
        }

        Ok(best_info)
    }

    /// Probe a single HTTP endpoint on the target.
    async fn probe_endpoint(
        &self,
        ip: IpAddr,
        port: u16,
        endpoint: &str,
    ) -> CoreResult<EcobeeDeviceInfo> {
        let addr = SocketAddr::new(ip, port);

        let mut stream = match timeout(
            Duration::from_millis(self.config.connect_timeout_ms),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => {
                return Ok(EcobeeDeviceInfo {
                    ip,
                    port,
                    is_ecobee: false,
                    model: None,
                    firmware_version: None,
                    device_id: None,
                    temperature_f: None,
                    humidity_pct: None,
                    hvac_mode: None,
                    raw_banner: None,
                });
            }
        };

        // Build a minimal HTTP GET request
        let host = match ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{}]", v6),
        };
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: Cerberus-Fenrir/0.1\r\n\r\n",
            endpoint, host
        );

        // Send request
        let _ = timeout(
            Duration::from_millis(self.config.request_timeout_ms),
            stream.write_all(request.as_bytes()),
        )
        .await;

        // Read response
        let mut buf = vec![0u8; 4096];
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
            return Ok(EcobeeDeviceInfo {
                ip,
                port,
                is_ecobee: false,
                model: None,
                firmware_version: None,
                device_id: None,
                temperature_f: None,
                humidity_pct: None,
                hvac_mode: None,
                raw_banner: None,
            });
        }

        let response = String::from_utf8_lossy(&buf[..n]).to_string();

        // Detect Ecobee signatures in headers or body
        let is_ecobee = self.is_ecobee_signature(&response);

        let mut info = EcobeeDeviceInfo {
            ip,
            port,
            is_ecobee,
            model: self.extract_model(&response),
            firmware_version: self.extract_firmware(&response),
            device_id: self.extract_device_id(&response),
            temperature_f: None,
            humidity_pct: None,
            hvac_mode: None,
            raw_banner: Some(response.lines().take(5).collect::<Vec<_>>().join(" | ")),
        };

        if is_ecobee {
            info.temperature_f = self.extract_temperature(&response);
            info.humidity_pct = self.extract_humidity(&response);
            info.hvac_mode = self.extract_hvac_mode(&response);
        }

        Ok(info)
    }

    /// Check if an HTTP response contains Ecobee signatures.
    fn is_ecobee_signature(&self, response: &str) -> bool {
        let lower = response.to_lowercase();
        lower.contains("ecobee")
            || lower.contains("ecobee thermostat")
            || lower.contains("x-ecobee")
            || lower.contains("ecobee-api")
    }

    /// Extract model name from response.
    fn extract_model(&self, _response: &str) -> Option<String> {
        // Ecobee doesn't always expose model in unauthenticated responses
        // This is a placeholder for future header/body parsing
        None
    }

    /// Extract firmware version from response.
    fn extract_firmware(&self, _response: &str) -> Option<String> {
        None
    }

    /// Extract device ID from response.
    fn extract_device_id(&self, _response: &str) -> Option<String> {
        None
    }

    /// Extract temperature in Fahrenheit from response body.
    fn extract_temperature(&self, _response: &str) -> Option<f32> {
        None
    }

    /// Extract humidity percentage from response body.
    fn extract_humidity(&self, _response: &str) -> Option<f32> {
        None
    }

    /// Extract HVAC mode from response.
    fn extract_hvac_mode(&self, _response: &str) -> Option<String> {
        None
    }

    /// Merge two EcobeeDeviceInfo results, preferring the more complete one.
    fn merge_info(&self, base: EcobeeDeviceInfo, overlay: EcobeeDeviceInfo) -> EcobeeDeviceInfo {
        EcobeeDeviceInfo {
            ip: base.ip,
            port: base.port,
            is_ecobee: base.is_ecobee || overlay.is_ecobee,
            model: overlay.model.or(base.model),
            firmware_version: overlay.firmware_version.or(base.firmware_version),
            device_id: overlay.device_id.or(base.device_id),
            temperature_f: overlay.temperature_f.or(base.temperature_f),
            humidity_pct: overlay.humidity_pct.or(base.humidity_pct),
            hvac_mode: overlay.hvac_mode.or(base.hvac_mode),
            raw_banner: overlay.raw_banner.or(base.raw_banner),
        }
    }

    /// Convert an EcobeeDeviceInfo into an InferenceOutput for the Fenrir
    /// inference pipeline.
    pub fn to_inference_output(&self, info: &EcobeeDeviceInfo) -> Result<InferenceOutput> {
        let confidence = if info.is_ecobee { 0.9 } else { 0.1 };
        let data: Vec<f32> = vec![
            confidence,
            if info.is_ecobee { 1.0 } else { 0.0 },
            info.temperature_f.unwrap_or(0.0),
            info.humidity_pct.unwrap_or(0.0),
        ];

        Ok(InferenceOutput {
            domain: DetectionDomain::IotDiscovery,
            output: Tensor {
                data,
                shape: vec![1, 4],
                dtype: TensorDtype::F32,
            },
            model: "ecobee_probe".to_string(),
            backend: cerberus_core::inference::BackendType::Onnx,
            latency_ms: 0.0,
        })
    }
}

impl Default for EcobeeProbe {
    fn default() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ecobee_signature_detection() {
        let probe = EcobeeProbe::default();

        assert!(probe.is_ecobee_signature("HTTP/1.1 200 OK\r\nX-Ecobee: thermostat\r\n"));
        assert!(probe.is_ecobee_signature(
            "HTTP/1.1 200 OK\r\nServer: ecobee-api/1.0\r\n"
        ));
        assert!(probe.is_ecobee_signature(
            "{\"name\":\"Ecobee SmartThermostat\",\"temperature\":72.0}"
        ));
        assert!(!probe.is_ecobee_signature("HTTP/1.1 200 OK\r\nServer: nginx\r\n"));
        assert!(!probe.is_ecobee_signature(""));
    }

    #[test]
    fn test_merge_info_prefers_overlay() {
        let probe = EcobeeProbe::default();
        let base = EcobeeDeviceInfo {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: 80,
            is_ecobee: true,
            model: Some("old".to_string()),
            firmware_version: None,
            device_id: None,
            temperature_f: None,
            humidity_pct: None,
            hvac_mode: None,
            raw_banner: Some("base".to_string()),
        };
        let overlay = EcobeeDeviceInfo {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: 80,
            is_ecobee: true,
            model: None,
            firmware_version: Some("4.5.0".to_string()),
            device_id: Some("ecobee-123".to_string()),
            temperature_f: Some(72.0),
            humidity_pct: Some(45.0),
            hvac_mode: Some("cool".to_string()),
            raw_banner: Some("overlay".to_string()),
        };

        let merged = probe.merge_info(base, overlay);
        assert_eq!(merged.model, Some("old".to_string())); // base wins for model
        assert_eq!(merged.firmware_version, Some("4.5.0".to_string())); // overlay wins
        assert_eq!(merged.device_id, Some("ecobee-123".to_string()));
        assert_eq!(merged.temperature_f, Some(72.0));
        assert_eq!(merged.humidity_pct, Some(45.0));
        assert_eq!(merged.hvac_mode, Some("cool".to_string()));
    }

    #[test]
    fn test_default_config_ports() {
        let config = EcobeeProbeConfig::default();
        assert!(config.probe_ports.contains(&80));
        assert!(config.probe_ports.contains(&443));
        assert!(config.probe_ports.contains(&7000)); // Ecobee local port
    }
}
