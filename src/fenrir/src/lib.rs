//! Fenrir - The Hunter
//!
//! Threat discovery, behavioral analysis, anomaly detection.

pub mod config;
pub mod detectors;
pub mod inference;

pub use config::*;
pub use detectors::*;
pub use inference::*;
