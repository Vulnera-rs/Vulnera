//! API key generator service

use hex;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::domain::auth::value_objects::ApiKeyHash;

/// API key generator service
#[derive(Clone)]
pub struct ApiKeyGenerator {
    /// Length of the API key (excluding prefix)
    key_length: usize,
    /// Prefix for API keys (e.g., "vuln_")
    prefix: String,
}

impl ApiKeyGenerator {
    /// Create a new API key generator with default settings
    pub fn new() -> Self {
        Self {
            key_length: 32,
            prefix: "vuln_".to_string(),
        }
    }

    /// Create a new API key generator with custom length
    pub fn with_length(key_length: usize) -> Self {
        Self {
            key_length,
            prefix: "vuln_".to_string(),
        }
    }

    /// Create a new API key generator with custom prefix and length
    pub fn with_prefix_and_length(prefix: String, key_length: usize) -> Self {
        Self { prefix, key_length }
    }

    /// Generate a new API key and its hash
    /// Returns (plaintext_key, key_hash)
    pub fn generate(&self) -> (String, ApiKeyHash) {
        // Generate random bytes
        let mut random_bytes = vec![0u8; self.key_length];
        rand::rng().fill_bytes(&mut random_bytes);

        // Hex encode the random bytes
        let hex_encoded = hex::encode(random_bytes);

        // Create the full API key with prefix
        let plaintext_key = format!("{}{}", self.prefix, hex_encoded);

        // Hash the full key (including prefix) using SHA256
        let mut hasher = Sha256::new();
        hasher.update(plaintext_key.as_bytes());
        let hash_bytes = hasher.finalize();
        let key_hash = hex::encode(hash_bytes);

        (plaintext_key, ApiKeyHash::from(key_hash))
    }

    /// Hash an existing API key (for validation)
    pub fn hash_key(&self, key: &str) -> ApiKeyHash {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let hash_bytes = hasher.finalize();
        let key_hash = hex::encode(hash_bytes);
        ApiKeyHash::from(key_hash)
    }

    /// Compare two API key hashes in constant time to prevent timing attacks
    ///
    /// This method should be used when comparing a user-provided API key hash
    /// against a stored hash to prevent timing-based side-channel attacks.
    ///
    /// # Arguments
    /// * `provided_hash` - The hash of the user-provided API key
    /// * `stored_hash` - The hash stored in the database
    ///
    /// # Returns
    /// `true` if the hashes match, `false` otherwise
    pub fn constant_time_compare(provided_hash: &ApiKeyHash, stored_hash: &ApiKeyHash) -> bool {
        let provided_bytes = provided_hash.as_str().as_bytes();
        let stored_bytes = stored_hash.as_str().as_bytes();

        // If lengths differ, we still want to do a constant-time comparison
        // to avoid leaking information about hash length
        if provided_bytes.len() != stored_bytes.len() {
            return false;
        }

        provided_bytes.ct_eq(stored_bytes).into()
    }

    /// Mask an API key for display (shows first 8 chars and last 4 chars)
    pub fn mask_key(&self, key: &str) -> String {
        if key.len() <= 12 {
            return "*".repeat(key.len());
        }

        let prefix_len = self.prefix.len();
        if key.starts_with(&self.prefix) {
            // Show prefix + first 4 chars + mask + last 4 chars
            let rest = &key[prefix_len..];
            if rest.len() <= 8 {
                format!("{}{}", self.prefix, "*".repeat(rest.len()))
            } else {
                format!(
                    "{}{}...{}",
                    self.prefix,
                    &rest[..4],
                    &rest[rest.len() - 4..]
                )
            }
        } else {
            // Fallback for keys without prefix
            format!("{}...{}", &key[..4], &key[key.len() - 4..])
        }
    }
}

impl Default for ApiKeyGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_generation() {
        let generator = ApiKeyGenerator::new();
        let (key1, hash1) = generator.generate();
        let (key2, hash2) = generator.generate();

        // Keys should be different
        assert_ne!(key1, key2);
        assert_ne!(hash1.as_str(), hash2.as_str());

        // Keys should have the prefix
        assert!(key1.starts_with("vuln_"));
        assert!(key2.starts_with("vuln_"));
    }

    #[test]
    fn test_api_key_hashing() {
        let generator = ApiKeyGenerator::new();
        let (key, hash) = generator.generate();

        // Hash the same key should produce the same hash
        let computed_hash = generator.hash_key(&key);
        assert_eq!(hash.as_str(), computed_hash.as_str());
    }

    #[test]
    fn test_api_key_masking() {
        let generator = ApiKeyGenerator::new();
        let (key, _) = generator.generate();

        let masked = generator.mask_key(&key);
        assert!(masked.contains("..."));
        assert!(masked.starts_with("vuln_"));
        assert!(masked.len() < key.len());
    }

    #[test]
    fn test_custom_length() {
        let generator = ApiKeyGenerator::with_length(16);
        let (key, _) = generator.generate();

        // Should be prefix + 16 bytes * 2 (hex) = prefix + 32 chars
        assert_eq!(key.len(), "vuln_".len() + 32);
    }

    #[test]
    fn test_constant_time_compare() {
        let generator = ApiKeyGenerator::new();
        let (key1, hash1) = generator.generate();
        let (key2, hash2) = generator.generate();

        // Same hashes should match
        let hash1_copy = generator.hash_key(&key1);
        assert!(ApiKeyGenerator::constant_time_compare(&hash1, &hash1_copy));

        // Different hashes should not match
        assert!(!ApiKeyGenerator::constant_time_compare(&hash1, &hash2));
    }

    #[test]
    fn test_constant_time_compare_different_lengths() {
        // Create hashes of different lengths manually
        let short_hash = ApiKeyHash::from("abc123".to_string());
        let long_hash = ApiKeyHash::from("abc123def456".to_string());

        // Different length hashes should not match
        assert!(!ApiKeyGenerator::constant_time_compare(
            &short_hash,
            &long_hash
        ));
    }
}
