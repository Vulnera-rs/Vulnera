//! Password hashing service using bcrypt

use bcrypt::{DEFAULT_COST, hash, verify};

use crate::domain::auth::{errors::AuthError, value_objects::PasswordHash};

/// Password hashing service using bcrypt
#[derive(Clone)]
pub struct PasswordHasher {
    /// Bcrypt cost factor (default: 12)
    cost: u32,
}

impl PasswordHasher {
    /// Create a new password hasher with default cost
    pub fn new() -> Self {
        Self { cost: DEFAULT_COST }
    }

    /// Create a new password hasher with custom cost
    pub fn with_cost(cost: u32) -> Self {
        Self { cost }
    }

    /// Hash a password asynchronously (non-blocking)
    ///
    /// Uses `spawn_blocking` to offload CPU-intensive bcrypt hashing to the blocking thread pool,
    /// preventing tokio runtime starvation under concurrent load.
    pub async fn hash(&self, password: String) -> Result<PasswordHash, AuthError> {
        let cost = self.cost;
        tokio::task::spawn_blocking(move || hash(password, cost))
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
    /// Uses `spawn_blocking` to offload CPU-intensive bcrypt verification to the blocking thread pool,
    /// preventing tokio runtime starvation under concurrent load.
    pub async fn verify(&self, password: String, hash: PasswordHash) -> Result<bool, AuthError> {
        tokio::task::spawn_blocking(move || verify(&password, hash.as_str()))
            .await
            .map_err(|e| {
                tracing::error!("Password verify task panicked: {}", e);
                AuthError::InvalidPassword {
                    reason: "Password verification failed".to_string(),
                }
            })?
            .map_err(|e| {
                tracing::error!("Failed to verify password: {}", e);
                AuthError::InvalidPassword {
                    reason: "Password verification failed".to_string(),
                }
            })
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

        // Hashes should be different (bcrypt uses salt)
        assert_ne!(hash1.as_str(), hash2.as_str());

        // But both should verify correctly
        assert!(hasher.verify(password.to_string(), hash1).await.unwrap());
        assert!(hasher.verify(password.to_string(), hash2).await.unwrap());
    }
}
