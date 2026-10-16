//! Serialization helper for fixed-size 64-byte Ed25519 signatures.

pub mod sig_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(
                "Invalid signature length: expected 64 bytes",
            ));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}
