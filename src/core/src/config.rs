//! Configuration types

use serde::{Deserialize, Serialize};

/// Global Cerberus configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    pub project_name: String,
    pub environment: Environment,
    pub spiffe_trust_domain: String,
    pub log_level: LogLevel,
    pub metrics_enabled: bool,
    pub tracing_enabled: bool,
}

/// Deployment environment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Environment {
    Development,
    Staging,
    Production,
    AirGapped,
}

/// Log levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Component-specific configuration trait
pub trait ComponentConfig: Sized {
    fn load() -> crate::Result<Self>;
    fn validate(&self) -> crate::Result<()>;
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            project_name: "cerberus".to_string(),
            environment: Environment::Development,
            spiffe_trust_domain: "cerberus.local".to_string(),
            log_level: LogLevel::Info,
            metrics_enabled: true,
            tracing_enabled: true,
        }
    }
}