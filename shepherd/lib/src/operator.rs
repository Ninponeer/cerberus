//! Operator identity and cryptographic key management.
//!
//! Shepherd operators sign ApprovalTokens with an Ed25519 key.
//! Keys are persisted to disk and loaded on startup.

use crate::error::{Result, ShepherdError};
use cerberus_core::crypto::{SigningKeyWrapper, VerifyingKeyWrapper};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Operator identity: SPIFFE ID plus signing/verifying key pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorIdentity {
    pub spiffe_id: String,
    pub cert_fingerprint: String,
    pub operator_name: String,
    #[serde(skip)]
    pub signing_key: Option<SigningKeyWrapper>,
    #[serde(skip)]
    pub verifying_key: Option<VerifyingKeyWrapper>,
}

impl OperatorIdentity {
    /// Create a new operator identity with a fresh Ed25519 key pair.
    pub fn generate(operator_name: String, spiffe_id: String) -> Self {
        let signing_key = SigningKeyWrapper::generate();
        let verifying_key = VerifyingKeyWrapper(signing_key.verifying_key());
        let cert_fingerprint = signing_key.to_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>();

        Self {
            spiffe_id,
            cert_fingerprint,
            operator_name,
            signing_key: Some(signing_key),
            verifying_key: Some(verifying_key),
        }
    }

    /// Load operator identity from disk. The signing key is read from
    /// `key_path`; the verifying key is derived from it.
    pub fn load_from_file(key_path: &Path, spiffe_id: String, operator_name: String) -> Result<Self> {
        let bytes = fs::read(key_path)
            .map_err(|e| ShepherdError::OperatorKey(format!("Failed to read key file: {e}")))?;

        if bytes.len() != 32 {
            return Err(ShepherdError::OperatorKey(format!(
                "Expected 32-byte raw Ed25519 seed, got {} bytes",
                bytes.len()
            )));
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        let signing_key = SigningKeyWrapper::from_bytes(&seed)
            .map_err(|e| ShepherdError::OperatorKey(format!("Invalid key: {e}")))?;

        let verifying_key = VerifyingKeyWrapper(signing_key.verifying_key());
        let cert_fingerprint = seed.iter().map(|b| format!("{:02x}", b)).collect::<String>();

        Ok(Self {
            spiffe_id,
            cert_fingerprint,
            operator_name,
            signing_key: Some(signing_key),
            verifying_key: Some(verifying_key),
        })
    }

    /// Persist the signing key seed to disk (32 raw bytes, mode 0600).
    pub fn save_key_to_file(&self, key_path: &Path) -> Result<()> {
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or_else(|| ShepherdError::OperatorKey("No signing key loaded".to_string()))?;

        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| ShepherdError::OperatorKey(format!("Failed to create key dir: {e}")))?;
        }

        let seed_bytes = signing_key.to_bytes();
        let mut secret = SecretBox::new(Box::new(seed_bytes.to_vec()));

        // Write raw 32-byte seed with restrictive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::write(key_path, secret.expose_secret())
                .map_err(|e| ShepherdError::OperatorKey(format!("Failed to write key: {e}")))?;
            fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| ShepherdError::OperatorKey(format!("Failed to set key permissions: {e}")))?;
        }
        #[cfg(not(unix))]
        {
            fs::write(key_path, secret.expose_secret())
                .map_err(|e| ShepherdError::OperatorKey(format!("Failed to write key: {e}")))?;
        }

        secret.zeroize();
        Ok(())
    }

    /// Returns the verifying key (public key) for signature verification.
    pub fn verifying_key(&self) -> Option<&VerifyingKeyWrapper> {
        self.verifying_key.as_ref()
    }

    /// Returns the signing key for creating approval tokens.
    pub fn signing_key(&self) -> Option<&SigningKeyWrapper> {
        self.signing_key.as_ref()
    }
}

impl Drop for OperatorIdentity {
    fn drop(&mut self) {
        if let Some(ref mut key) = self.signing_key {
            // SigningKeyWrapper derives ZeroizeOnDrop via cerberus-core
            let _ = key;
        }
    }
}

/// Key store: manages operator key persistence and rotation.
#[derive(Debug)]
pub struct KeyStore {
    key_dir: PathBuf,
}

impl KeyStore {
    /// Create a new KeyStore pointing at the given directory.
    pub fn new<P: AsRef<Path>>(dir: P) -> Self {
        Self {
            key_dir: dir.as_ref().to_path_buf(),
        }
    }

    /// Ensure the key directory exists.
    pub fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.key_dir)
            .map_err(|e| ShepherdError::OperatorKey(format!("Failed to create key dir: {e}")))?;
        Ok(())
    }

    /// Path to the active operator key file.
    pub fn active_key_path(&self) -> PathBuf {
        self.key_dir.join("operator_key")
    }

    /// Path to the operator identity metadata file.
    pub fn identity_path(&self) -> PathBuf {
        self.key_dir.join("operator_identity.json")
    }

    /// List all key files in the store.
    pub fn list_keys(&self) -> Result<Vec<PathBuf>> {
        let mut keys = Vec::new();
        if self.key_dir.exists() {
            for entry in fs::read_dir(&self.key_dir)
                .map_err(|e| ShepherdError::OperatorKey(format!("Failed to read key dir: {e}")))?
            {
                let entry = entry.map_err(|e| ShepherdError::OperatorKey(format!("Failed to read dir entry: {e}")))?;
                let path = entry.path();
                if path.is_file() && path.extension().map_or(false, |e| e == "key") {
                    keys.push(path);
                }
            }
        }
        keys.sort();
        Ok(keys)
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new(
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".cerberus/shepherd/keys"),
        )
    }
}
