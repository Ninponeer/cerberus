//! Fenrir - The Hunter
//!
//! Threat discovery, behavioral analysis, anomaly detection.

pub mod config;
pub mod detectors;

#[cfg(feature = "inference")]
pub mod inference;

pub use config::*;
pub use detectors::*;

#[cfg(feature = "inference")]
pub use inference::*;
