//! Cerberus Core - Shared types, error handling, and utilities
//!
//! This crate provides the foundational types and utilities used across
//! all Cerberus components (Fenrir, Garmr, Orthrus, Pack, Yggdrasil).

pub mod error;
pub mod identity;
pub mod telemetry;
pub mod observation;
pub mod verdict;
pub mod action;
pub mod config;
pub mod crypto;
pub mod util;
pub mod inference;

pub use error::{CerberusError, Result};
pub use identity::{SpiffeId, TrustDomain, AgentIdentity};
pub use telemetry::{TelemetryEvent, EventType, Platform};
pub use observation::{Observation, ObservationType, Evidence};
pub use verdict::{Verdict, Classification, RecommendedAction, ActionType};
pub use action::{ActionDirective, ActionResult, ActionStatus, TargetSelector};
pub use config::{GlobalConfig, ComponentConfig};
pub use crypto::{SigningKeyWrapper, VerifyingKeyWrapper, SignatureWrapper};
pub use inference::{
    ComputeTier, EndpointCapabilities, GpuInfo, BackendType, DetectionDomain,
    ModelSpec, ModelHandle, Tensor, TensorDtype, InferenceOutput, ActiveModel,
    ModelSelectionEntry, InferenceBackend, ModelSelectionPolicy,
};

/// Cerberus protocol version
pub const PROTOCOL_VERSION: &str = "0.1.0";

/// Project name constant
pub const PROJECT_NAME: &str = "cerberus";

/// Default gRPC port base
pub const GRPC_PORT_BASE: u16 = 50050;