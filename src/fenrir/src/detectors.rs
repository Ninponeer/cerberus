//! Detection Modules
//!
//! Individual detection modules for each threat domain

pub mod dns_anomaly;
pub mod binary_reputation;
pub mod beaconing_detector;
pub mod injection_detector;
pub mod credential_abuse;
pub mod lateral_movement;

pub use dns_anomaly::DnsAnomalyDetector;
pub use binary_reputation::BinaryReputationDetector;
pub use beaconing_detector::BeaconingDetector;
pub use injection_detector::InjectionDetector;
pub use credential_abuse::CredentialAbuseDetector;
pub use lateral_movement::LateralMovementDetector;