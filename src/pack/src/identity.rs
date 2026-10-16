//! Sovereign node identity and mTLS credentials for Cerberus Pack nodes.

use cerberus_core::crypto::{SigningKeyWrapper, VerifyingKeyWrapper};
use cerberus_core::error::{CerberusError, Result};
use cerberus_core::identity::{AgentIdentity, SpiffeId, TrustDomain};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::Signature;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, SanType};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Sovereign identity of a local Pack node.
#[derive(Debug, Clone)]
pub struct PackNodeIdentity {
    pub node_id: Uuid,
    pub name: String,
    pub spiffe_id: SpiffeId,
    pub signing_key: SigningKeyWrapper,
    pub created_at: DateTime<Utc>,
}

impl PackNodeIdentity {
    /// Generates a new sovereign node identity with an Ed25519 keypair and SPIFFE ID.
    pub fn generate(node_name: impl Into<String>) -> Result<Self> {
        let node_id = Uuid::new_v4();
        let name = node_name.into();
        let trust_domain = TrustDomain::cerberus_local();
        let spiffe_id = SpiffeId::new(&trust_domain, &format!("pack/node/{}", node_id));
        let signing_key = SigningKeyWrapper::generate();

        Ok(Self {
            node_id,
            name,
            spiffe_id,
            signing_key,
            created_at: Utc::now(),
        })
    }

    /// Returns the public verifying key of the node.
    pub fn verifying_key(&self) -> VerifyingKeyWrapper {
        VerifyingKeyWrapper(self.signing_key.verifying_key())
    }

    /// Signs an arbitrary data buffer using the local Ed25519 private key.
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.signing_key.sign(data)
    }

    /// Converts this node identity into a standard Cerberus core AgentIdentity.
    pub fn to_agent_identity(&self, fingerprint: String, ttl: Duration) -> AgentIdentity {
        AgentIdentity {
            spiffe_id: self.spiffe_id.clone(),
            cert_fingerprint: fingerprint,
            issued_at: self.created_at,
            expires_at: self.created_at + ttl,
        }
    }

    /// Generates self-signed X.509 certificate and private key in PEM format for mutual TLS.
    /// Embeds the node's SPIFFE ID URI as a Subject Alternative Name (SAN).
    pub fn generate_mtls_cert(&self, ttl_days: u32) -> Result<(String, String)> {
        let mut params = CertificateParams::default();

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("cerberus-pack-{}", self.node_id));
        dn.push(DnType::OrganizationName, "Project Cerberus");
        dn.push(DnType::OrganizationalUnitName, "Pack Swarm Node");
        params.distinguished_name = dn;

        // Subject Alternative Names: SPIFFE URI and local DNS name
        let spiffe_uri = self.spiffe_id.to_string();
        params.subject_alt_names = vec![
            SanType::URI(spiffe_uri),
            SanType::DnsName(self.name.clone()),
            SanType::DnsName("localhost".to_string()),
        ];

        // Validity period
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::days(ttl_days as i64);

        let cert = Certificate::from_params(params)
            .map_err(|e| CerberusError::Crypto(format!("Failed to generate X.509 certificate: {}", e)))?;

        let cert_pem = cert.serialize_pem()
            .map_err(|e| CerberusError::Crypto(format!("Failed to serialize certificate PEM: {}", e)))?;
        let key_pem = cert.serialize_private_key_pem();

        Ok((cert_pem, key_pem))
    }

    /// Computes the SHA-256 fingerprint of a PEM certificate string.
    pub fn compute_cert_fingerprint(cert_pem: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(cert_pem.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }
}
