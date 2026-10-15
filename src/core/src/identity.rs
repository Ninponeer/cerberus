//! Identity types for Cerberus (SPIFFE-based)

use serde::{Deserialize, Serialize};
use std::fmt;

/// SPIFFE Trust Domain
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TrustDomain(pub String);

impl fmt::Display for TrustDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TrustDomain {
    pub fn new(domain: impl Into<String>) -> Self {
        Self(domain.into())
    }

    pub fn cerberus_local() -> Self {
        Self("cerberus.local".to_string())
    }
}

/// SPIFFE ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpiffeId(pub String);

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl SpiffeId {
    pub fn new(trust_domain: &TrustDomain, path: &str) -> Self {
        Self(format!("spiffe://{}/{}", trust_domain.0, path.trim_start_matches('/')))
    }

    pub fn trust_domain(&self) -> Option<TrustDomain> {
        self.0.strip_prefix("spiffe://")?
            .split('/')
            .next()
            .map(|s| TrustDomain(s.to_string()))
    }

    pub fn path(&self) -> Option<&str> {
        self.0.strip_prefix("spiffe://")?.split('/').nth(1)
    }

    pub fn is_valid(&self) -> bool {
        self.0.starts_with("spiffe://") && self.path().is_some()
    }
}

/// Agent identity with SPIFFE ID and derived signing key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub spiffe_id: SpiffeId,
    pub cert_fingerprint: String,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl AgentIdentity {
    pub fn is_valid(&self) -> bool {
        self.spiffe_id.is_valid() && chrono::Utc::now() < self.expires_at
    }

    pub fn time_until_expiry(&self) -> chrono::Duration {
        self.expires_at - chrono::Utc::now()
    }
}