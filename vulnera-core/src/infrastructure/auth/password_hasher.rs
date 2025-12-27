//! Password hashing service using Argon2id (OWASP-recommended)

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{
        PasswordHash as Argon2Hash, PasswordHasher as Argon2Hasher, PasswordVerifier, SaltString,
        rand_core::OsRng,
    },
};

use crate::domain::auth::{errors::AuthError, value_objects::PasswordHash};

/// Password hashing service using Argon2id (OWASP-recommended)
///
/// Argon2id is the OWASP-recommended password hashing algorithm, providing
/// resistance to both side-channel and GPU-based attacks.
#[derive(Clone)]
pub struct PasswordHasher {
    /// Argon2 parameters (memory cost, time cost, parallelism)
    params: Params,
}

impl PasswordHasher {
    /// OWASP minimum recommended memory cost: 19 MiB (19,456 KiB)
    const MEMORY_COST: u32 = 19_456;
    /// OWASP recommended iterations (time cost)
    const TIME_COST: u32 = 2;
    /// OWASP recommended parallelism
    const PARALLELISM: u32 = 1;
    /// Output hash length in bytes
    const OUTPUT_LEN: usize = 32;

    /// Create a new password hasher with OWASP-recommended parameters
    pub fn new() -> Self {
        let params = Params::new(
            Self::MEMORY_COST,
            Self::TIME_COST,
            Self::PARALLELISM,
            Some(Self::OUTPUT_LEN),
        )
        .expect("Invalid Argon2 parameters");

        Self { params }
    }

    /// Create a new password hasher with custom parameters
    ///
    /// Use this for testing or when specific resource constraints apply.
    pub fn with_params(memory_cost: u32, time_cost: u32, parallelism: u32) -> Self {
        let params = Params::new(memory_cost, time_cost, parallelism, Some(Self::OUTPUT_LEN))
            .expect("Invalid Argon2 parameters");

        Self { params }
    }

    /// Hash a password asynchronously (non-blocking)
    ///
    /// Uses `spawn_blocking` to offload CPU-intensive Argon2 hashing to the blocking thread pool,
    /// preventing tokio runtime starvation under concurrent load.
    pub async fn hash(&self, password: String) -> Result<PasswordHash, AuthError> {
        let params = self.params.clone();
        tokio::task::spawn_blocking(move || {
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            argon2
                .hash_password(password.as_bytes(), &salt)
                .map(|h| h.to_string())
        })
        .await
        .map_err(|e| {
            tracing::error!("Password hash task panicked: {}", e);
            AuthError::InvalidPassword {
                reason: "Password hashing failed".to_string(),
            }
        })?
        .map(PasswordHash::from)
        .map_err(|e| {
            tracing::error!("Failed to hash password: {}", e);
            AuthError::InvalidPassword {
                reason: "Password hashing failed".to_string(),
            }
        })
    }

    /// Verify a password asynchronously (non-blocking)
    ///
    /// Uses `spawn_blocking` to offload CPU-intensive Argon2 verification to the blocking thread pool,
    /// preventing tokio runtime starvation under concurrent load.
    pub async fn verify(&self, password: String, hash: PasswordHash) -> Result<bool, AuthError> {
        tokio::task::spawn_blocking(move || {
            let hash_str = hash.as_str();

            // Parse the PHC-format hash
            let parsed_hash = Argon2Hash::new(hash_str).map_err(|e| {
                tracing::error!("Failed to parse password hash: {}", e);
                AuthError::InvalidPassword {
                    reason: "Password verification failed".to_string(),
                }
            })?;

            // Verify using Argon2id (default configuration handles parameter extraction from hash)
            let argon2 = Argon2::default();
            Ok(argon2
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok())
        })
        .await
        .map_err(|e| {
            tracing::error!("Password verify task panicked: {}", e);
            AuthError::InvalidPassword {
                reason: "Password verification failed".to_string(),
            }
        })?
    }
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_password_hashing_and_verification() {
        let hasher = PasswordHasher::new();
        let password = "test_password_123";

        let hash = hasher.hash(password.to_string()).await.unwrap();
        assert!(
            hasher
                .verify(password.to_string(), hash.clone())
                .await
                .unwrap()
        );
        assert!(
            !hasher
                .verify("wrong_password".to_string(), hash)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_password_hash_uniqueness() {
        let hasher = PasswordHasher::new();
        let password = "same_password";

        let hash1 = hasher.hash(password.to_string()).await.unwrap();
        let hash2 = hasher.hash(password.to_string()).await.unwrap();

        // Hashes should be different (Argon2 uses salt)
        assert_ne!(hash1.as_str(), hash2.as_str());

        // But both should verify correctly
        assert!(hasher.verify(password.to_string(), hash1).await.unwrap());
        assert!(hasher.verify(password.to_string(), hash2).await.unwrap());
    }

    #[tokio::test]
    async fn test_argon2id_hash_format() {
        let hasher = PasswordHasher::new();
        let password = "secure_password_123!";

        let hash = hasher.hash(password.to_string()).await.unwrap();

        // Verify it's an Argon2id hash (PHC format starts with $argon2id$)
        assert!(hash.as_str().starts_with("$argon2id$"));
    }

    #[tokio::test]
    async fn test_custom_params() {
        // Use lower memory for faster testing
        let hasher = PasswordHasher::with_params(4096, 1, 1);
        let password = "test_password";

        let hash = hasher.hash(password.to_string()).await.unwrap();
        assert!(hasher.verify(password.to_string(), hash).await.unwrap());
    }
}
