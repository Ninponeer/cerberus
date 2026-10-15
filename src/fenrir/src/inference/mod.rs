// Fenrir inference module
pub mod backends;
pub mod router;

use cerberus_core::inference::{
    BackendType, ComputeTier, DetectionDomain, InferenceBackend, InferenceOutput,
    ModelHandle, ModelSelectionPolicy, ModelSpec, Result, Tensor,
};

pub use backends::*;
pub use router::ModelRouter;