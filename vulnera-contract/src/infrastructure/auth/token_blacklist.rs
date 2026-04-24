//! Token blacklist service for refresh token revocation
//!
//! This module provides a cache-backed token blacklist that allows revoking
//! refresh tokens before their natural expiration. Blacklisted tokens are
//! stored in Dragonfly/Redis with TTL matching the token's remaining lifetime.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

use crate::application::errors::ApplicationError;
use crate::application::vulnerability::services::CacheService;
use crate::domain::auth::value_objects::UserId;

/// Token blacklist service trait
#[async_trait]
pub trait TokenBlacklistService: Send + Sync {
    /// Add a token to the blacklist
    ///
    /// # Arguments
    /// * `token_jti` - The JWT ID (jti) or token hash to blacklist
    /// * `ttl` - How long to keep the token in the blacklist (should match remaining token lifetime)
    async fn blacklist_token(&self, token_jti: &str, ttl: Duration)
    -> Result<(), ApplicationError>;

    /// Check if a token is blacklisted
    ///
    /// # Arguments
    /// * `token_jti` - The JWT ID (jti) or token hash to check
    ///
    /// # Returns
    /// `true` if the token is blacklisted, `false` otherwise
    async fn is_blacklisted(&self, token_jti: &str) -> Result<bool, ApplicationError>;

    /// Revoke all tokens for a user (logout from all devices)
    ///
    /// # Arguments
    /// * `user_id` - The user whose tokens should be revoked
    /// * `ttl` - How long to maintain the user revocation entry
    async fn revoke_all_user_tokens(
        &self,
        user_id: &UserId,
        ttl: Duration,
    ) -> Result<(), ApplicationError>;

    /// Check if all tokens for a user have been revoked
    ///
    /// # Arguments
    /// * `user_id` - The user to check
    /// * `token_iat` - The token's issued-at timestamp (tokens issued before revocation are invalid)
    ///
    /// # Returns
    /// `true` if the user's tokens have been revoked after `token_iat`, `false` otherwise
    async fn are_user_tokens_revoked(
        &self,
        user_id: &UserId,
        token_iat: i64,
    ) -> Result<bool, ApplicationError>;
}

/// Cache-backed implementation of token blacklist
pub struct CacheTokenBlacklistService<C: CacheService> {
    cache: Arc<C>,
}

impl<C: CacheService> CacheTokenBlacklistService<C> {
    /// Create a new cache-backed token blacklist service
    pub fn new(cache: Arc<C>) -> Self {
        Self { cache }
    }

    /// Generate the cache key for a blacklisted token
    fn token_key(token_jti: &str) -> String {
        format!("auth:blacklist:token:{}", token_jti)
    }

    /// Generate the cache key for user-wide token revocation
    fn user_revocation_key(user_id: &UserId) -> String {
        format!("auth:blacklist:user:{}", user_id.as_str())
    }

    /// Generate a token identifier from the token string
    /// Uses SHA-256 hash of the token to create a consistent identifier
    pub fn hash_token(token: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[async_trait]
impl<C: CacheService + Send + Sync> TokenBlacklistService for CacheTokenBlacklistService<C> {
    async fn blacklist_token(
        &self,
        token_jti: &str,
        ttl: Duration,
    ) -> Result<(), ApplicationError> {
        let key = Self::token_key(token_jti);
        let timestamp = chrono::Utc::now().timestamp();

        self.cache.set(&key, &timestamp, ttl).await?;

        tracing::debug!(token_jti = %token_jti, "Token added to blacklist");
        Ok(())
    }

    async fn is_blacklisted(&self, token_jti: &str) -> Result<bool, ApplicationError> {
        let key = Self::token_key(token_jti);
        let result: Option<i64> = self.cache.get(&key).await?;
        Ok(result.is_some())
    }

    async fn revoke_all_user_tokens(
        &self,
        user_id: &UserId,
        ttl: Duration,
    ) -> Result<(), ApplicationError> {
        let key = Self::user_revocation_key(user_id);
        let timestamp = chrono::Utc::now().timestamp();

        self.cache.set(&key, &timestamp, ttl).await?;

        tracing::info!(user_id = %user_id, "All user tokens revoked");
        Ok(())
    }

    async fn are_user_tokens_revoked(
        &self,
        user_id: &UserId,
        token_iat: i64,
    ) -> Result<bool, ApplicationError> {
        let key = Self::user_revocation_key(user_id);
        let revocation_time: Option<i64> = self.cache.get(&key).await?;

        match revocation_time {
            Some(revoked_at) => {
                // Token is invalid if it was issued before the revocation time
                Ok(token_iat < revoked_at)
            }
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_token() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test";
        let hash =
            CacheTokenBlacklistService::<crate::infrastructure::cache::DragonflyCache>::hash_token(
                token,
            );

        // Hash should be consistent
        let hash2 =
            CacheTokenBlacklistService::<crate::infrastructure::cache::DragonflyCache>::hash_token(
                token,
            );
        assert_eq!(hash, hash2);

        // Hash should be 64 characters (256 bits in hex)
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_token_key_generation() {
        let jti = "abc123";
        let key =
            CacheTokenBlacklistService::<crate::infrastructure::cache::DragonflyCache>::token_key(
                jti,
            );
        assert_eq!(key, "auth:blacklist:token:abc123");
    }

    #[test]
    fn test_user_revocation_key_generation() {
        let user_id = UserId::generate();
        let key = CacheTokenBlacklistService::<crate::infrastructure::cache::DragonflyCache>::user_revocation_key(&user_id);
        assert!(key.starts_with("auth:blacklist:user:"));
    }
}
