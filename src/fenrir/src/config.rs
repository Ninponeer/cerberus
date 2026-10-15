//! Fenrir Configuration

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FenrirConfig {
    #[serde(default = "default_tier")]
    pub endpoint_tier: String,
}

fn default_tier() -> String {
    "auto".to_string()
}

impl Default for FenrirConfig {
    fn default() -> Self {
        Self {
            endpoint_tier: "auto".to_string(),
        }
    }
}
