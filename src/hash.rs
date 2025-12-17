use sha2::{Digest, Sha256};

/// Domain-separated SHA-256 hash function.
/// H(tag, bytes) = SHA256(tag || 0x00 || bytes) as hex lowercase with "sha256:" prefix
pub fn h_sha256(tag: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tag.as_bytes());
    hasher.update([0u8]); // 0x00 separator
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Format hash bytes as "sha256:<hex>" string
pub fn prefixed_hex_sha256(hash_bytes: [u8; 32]) -> String {
    format!("sha256:{}", hex::encode(hash_bytes))
}

/// Hash a JSON value with a domain tag, returning "sha256:<hex>"
pub fn hash_json(tag: &str, value: &serde_json::Value) -> String {
    use crate::canon::canonical_string;
    let canon_bytes = canonical_string(value).into_bytes();
    let hash_bytes = h_sha256(tag, &canon_bytes);
    prefixed_hex_sha256(hash_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_hash_json() {
        let obj = json!({"test": "value"});
        let hash = hash_json("pactum:test:0", &obj);
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 71); // "sha256:" + 64 hex chars
    }
}
