//! Error types for the Shepherd operator crate.

use thiserror::Error;

/// Shepherd-specific errors covering operator key management,
/// Yggdrasil queries, Garmr/Orthrus integration, and CLI operations.
#[derive(Error, Debug)]
pub enum ShepherdError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Operator key error: {0}")]
    OperatorKey(String),

    #[error("Yggdrasil query error: {0}")]
    Yggdrasil(String),

    #[error("Garmr integration error: {0}")]
    Garmr(String),

    #[error("Orthrus integration error: {0}")]
    Orthrus(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),
}

pub type Result<T> = std::result::Result<T, ShepherdError>;
