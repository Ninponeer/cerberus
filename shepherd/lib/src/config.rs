//! Shepherd operator configuration.
//!
//! Loads operator keys, Yggdrasil store path, and component endpoints
//! from environment, config file, and defaults.

use crate::error::{Result, ShepherdError};
use cerberus_core::identity::{SpiffeId, TrustDomain};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Shepherd configuration for the operator CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShepherdConfig {
    /// SPIFFE trust domain
    pub trust_domain: TrustDomain,
    /// Shepherd SPIFFE ID path (e.g. "shepherd/cli/operator-01")
    pub spiffe_path: String,
    /// Path to operator signing key file (PEM or raw bytes)
    pub operator_key_path: PathBuf,
    /// Path to Yggdrasil RocksDB store directory
    pub yggdrasil_store_path: PathBuf,
    /// Operator display name
    pub operator_name: String,
    /// Auto-approve confidence threshold (0.0-1.0). Verdicts above this
    /// threshold can be auto-confirmed without operator intervention.
    pub auto_approve_threshold: f32,
    /// Whether operator confirmation is required for all containments
    pub force_human_approval: bool,
    /// Approval token TTL in seconds
    pub approval_ttl_sec: i64,
    /// Known Garmr endpoints for direct queries
    pub garmr_endpoints: Vec<String>,
    /// Known Orthrus endpoints for direct queries
    pub orthrus_endpoints: Vec<String>,
    /// Custom parameters map for extensibility
    pub extra: HashMap<String, String>,
}

impl Default for ShepherdConfig {
    fn default() -> Self {
        Self {
            trust_domain: TrustDomain::cerberus_local(),
            spiffe_path: "shepherd/cli/operator".to_string(),
            operator_key_path: dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".cerberus/shepherd/operator_key"),
            yggdrasil_store_path: PathBuf::from("/opt/bitbucket/cerberus/data/yggdrasil"),
            operator_name: "operator".to_string(),
            auto_approve_threshold: 0.85,
            force_human_approval: false,
            approval_ttl_sec: 3600,
            garmr_endpoints: Vec::new(),
            orthrus_endpoints: Vec::new(),
            extra: HashMap::new(),
        }
    }
}

impl ShepherdConfig {
    /// Load configuration from a TOML file, falling back to defaults.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        if !path.as_ref().exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ShepherdError::Config(format!("Failed to read config: {e}")))?;
        toml::from_str(&contents).map_err(|e| ShepherdError::Config(format!("Failed to parse config: {e}")))
    }

    /// Save configuration to a TOML file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ShepherdError::Config(format!("Failed to create config dir: {e}")))?;
        }
        let contents = toml::to_string_pretty(self)
            .map_err(|e| ShepherdError::Config(format!("Failed to serialize config: {e}")))?;
        std::fs::write(path.as_ref(), contents)
            .map_err(|e| ShepherdError::Config(format!("Failed to write config: {e}")))?;
        Ok(())
    }

    /// Returns the full SPIFFE ID for this operator.
    pub fn spiffe_id(&self) -> SpiffeId {
        SpiffeId::new(&self.trust_domain, &self.spiffe_path)
    }

    /// Returns the config file path used by default.
    pub fn default_config_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".cerberus/shepherd/config.toml")
    }
}

impl std::fmt::Display for ShepherdConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Shepherd Configuration")?;
        writeln!(f, "  Trust domain: {}", self.trust_domain)?;
        writeln!(f, "  SPIFFE ID: {}", self.spiffe_id())?;
        writeln!(f, "  Operator: {}", self.operator_name)?;
        writeln!(
            f,
            "  Auto-approve threshold: {:.2}",
            self.auto_approve_threshold
        )?;
        writeln!(
            f,
            "  Force human approval: {}",
            self.force_human_approval
        )?;
        writeln!(f, "  Yggdrasil store: {}", self.yggdrasil_store_path.display())?;
        writeln!(f, "  Operator key: {}", self.operator_key_path.display())?;
        Ok(())
    }
}
