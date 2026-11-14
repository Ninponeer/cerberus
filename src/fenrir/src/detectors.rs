//! Detection Modules
//!
//! Individual detection modules for each threat domain

pub mod dns_anomaly;
pub mod binary_reputation;
pub mod beaconing_detector;
pub mod injection_detector;
pub mod credential_abuse;
pub mod lateral_movement;
pub mod network_recon;
pub mod ecobee_probe;
pub mod blackbox_fingerprint;
pub mod botnet_indicator;

pub use dns_anomaly::DnsAnomalyDetector;
pub use binary_reputation::BinaryReputationDetector;
pub use beaconing_detector::BeaconingDetector;
pub use injection_detector::InjectionDetector;
pub use credential_abuse::CredentialAbuseDetector;
pub use lateral_movement::LateralMovementDetector;
pub use network_recon::{HostScanResult, NetworkReconConfig, NetworkReconDetector, PortProbe};
pub use ecobee_probe::{EcobeeDeviceInfo, EcobeeProbe};
pub use blackbox_fingerprint::{BlackboxFingerprint, BlackboxFingerprinter};
pub use botnet_indicator::{BotnetIndicatorAnalyzer, BotnetIndicatorResult};