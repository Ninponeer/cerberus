// Fenrir inference module
// Requires the "inference" feature (pulls in ML backends with C toolchain deps)

#[cfg(feature = "inference")]
pub mod backends;

#[cfg(feature = "inference")]
pub mod router;

#[cfg(feature = "inference")]
use cerberus_core::inference::{
    BackendType, ComputeTier, DetectionDomain, InferenceBackend, InferenceOutput,
    ModelHandle, ModelSelectionPolicy, ModelSpec, Result, Tensor,
};

#[cfg(feature = "inference")]
pub use backends::*;

#[cfg(feature = "inference")]
pub use router::ModelRouter;
