//! Cryptographic utilities

use crate::error::{CerberusError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// Ed25519 signing key wrapper with secure memory handling
#[derive(Clone, ZeroizeOnDrop)]
pub struct SigningKeyWrapper(pub SigningKey);

impl SigningKeyWrapper {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self(signing_key)
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(bytes);
        Ok(Self(signing_key))
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.0.sign(msg)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl std::fmt::Debug for SigningKeyWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKeyWrapper").finish_non_exhaustive()
    }
}

/// Ed25519 verifying key wrapper
#[derive(Debug, Clone)]
pub struct VerifyingKeyWrapper(pub VerifyingKey);

impl VerifyingKeyWrapper {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let vk = VerifyingKey::from_bytes(bytes)
            .map_err(|e| CerberusError::Crypto(format!("Invalid verifying key: {}", e)))?;
        Ok(Self(vk))
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        self.0.verify(msg, sig)
            .map_err(|e| CerberusError::Crypto(format!("Signature verification failed: {}", e)))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Signature wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureWrapper(#[serde(with = "signature_serde")] pub Signature);

mod signature_serde {
    use ed25519_dalek::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(sig: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(sig.to_bytes().as_ref())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("Invalid signature length"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Signature::from_bytes(&arr))
    }
}

impl SignatureWrapper {
    pub fn new(sig: Signature) -> Self {
        Self(sig)
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }
}