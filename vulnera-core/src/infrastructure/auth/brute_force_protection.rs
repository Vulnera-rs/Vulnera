//! Brute force protection service
//!
//! This module implements protection against brute force attacks on authentication
//! endpoints by tracking failed login attempts and implementing exponential backoff
//! with temporary account lockout.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

use crate::application::errors::ApplicationError;
use crate::application::vulnerability::services::CacheService;
use crate::domain::auth::errors::AuthError;

/// Configuration for brute force protection
#[derive(Debug, Clone)]
pub struct BruteForceConfig {
    /// Maximum failed attempts before lockout
    pub max_attempts: u32,
    /// Base lockout duration (exponentially increased with each lockout)
    pub base_lockout_duration: Duration,
    /// Maximum lockout duration cap
    pub max_lockout_duration: Duration,
    /// Window for counting failed attempts
    pub attempt_window: Duration,
    /// Multiplier for exponential backoff
    pub backoff_multiplier: f64,
}

impl Default for BruteForceConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base_lockout_duration: Duration::from_secs(60), // 1 minute base
            max_lockout_duration: Duration::from_secs(3600), // 1 hour max
            attempt_window: Duration::from_secs(900),       // 15 minute window
            backoff_multiplier: 2.0,
        }
    }
}

/// Login attempt tracking data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoginAttemptData {
    /// Number of failed attempts in the current window
    pub failed_attempts: u32,
    /// Number of times the account has been locked out
    pub lockout_count: u32,
    /// Timestamp when the current lockout expires (if locked)
    pub locked_until: Option<i64>,
    /// Timestamp of the first failed attempt in the current window
    pub window_start: i64,
}

impl Default for LoginAttemptData {
    fn default() -> Self {
        Self {
            failed_attempts: 0,
            lockout_count: 0,
            locked_until: None,
            window_start: chrono::Utc::now().timestamp(),
        }
    }
}

/// Result of checking login permission
#[derive(Debug, Clone)]
pub enum LoginPermission {
    /// Login is allowed
    Allowed,
    /// Account is temporarily locked
    Locked {
        /// Seconds until the lockout expires
        retry_after_seconds: u64,
        /// Human-readable message
        message: String,
    },
}

/// Brute force protection service trait
#[async_trait]
pub trait BruteForceProtection: Send + Sync {
    /// Check if a login attempt is allowed for the given identifier (email or IP)
    async fn check_login_allowed(
        &self,
        identifier: &str,
    ) -> Result<LoginPermission, ApplicationError>;

    /// Record a failed login attempt
    async fn record_failed_attempt(&self, identifier: &str) -> Result<(), ApplicationError>;

    /// Record a successful login (resets the attempt counter)
    async fn record_successful_login(&self, identifier: &str) -> Result<(), ApplicationError>;

    /// Get the current attempt data for an identifier
    async fn get_attempt_data(
        &self,
        identifier: &str,
    ) -> Result<Option<LoginAttemptData>, ApplicationError>;
}

/// Cache-backed implementation of brute force protection
pub struct CacheBruteForceProtection<C: CacheService> {
    cache: Arc<C>,
    config: BruteForceConfig,
}

impl<C: CacheService> CacheBruteForceProtection<C> {
    /// Create a new cache-backed brute force protection service
    pub fn new(cache: Arc<C>, config: BruteForceConfig) -> Self {
        Self { cache, config }
    }

    /// Create with default configuration
    pub fn with_defaults(cache: Arc<C>) -> Self {
        Self::new(cache, BruteForceConfig::default())
    }

    /// Generate cache key for login attempts
    fn attempt_key(identifier: &str) -> String {
        // Use SHA-256 hash of identifier to prevent key injection and normalize length
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(identifier.as_bytes());
        let hash = hex::encode(hasher.finalize());
        format!("auth:brute_force:{}", hash)
    }

    /// Calculate lockout duration based on lockout count
    fn calculate_lockout_duration(&self, lockout_count: u32) -> Duration {
        let multiplier = self.config.backoff_multiplier.powi(lockout_count as i32);
        let duration_secs = self.config.base_lockout_duration.as_secs_f64() * multiplier;
        let capped_secs = duration_secs.min(self.config.max_lockout_duration.as_secs_f64());
        Duration::from_secs_f64(capped_secs)
    }
}

#[async_trait]
impl<C: CacheService + Send + Sync> BruteForceProtection for CacheBruteForceProtection<C> {
    async fn check_login_allowed(
        &self,
        identifier: &str,
    ) -> Result<LoginPermission, ApplicationError> {
        let key = Self::attempt_key(identifier);
        let data: Option<LoginAttemptData> = self.cache.get(&key).await?;

        let now = chrono::Utc::now().timestamp();

        match data {
            Some(attempt_data) => {
                // Check if currently locked out
                if let Some(locked_until) = attempt_data.locked_until {
                    if now < locked_until {
                        let retry_after = (locked_until - now) as u64;
                        return Ok(LoginPermission::Locked {
                            retry_after_seconds: retry_after,
                            message: format!(
                                "Account temporarily locked due to too many failed login attempts. Try again in {} seconds.",
                                retry_after
                            ),
                        });
                    }
                }

                Ok(LoginPermission::Allowed)
            }
            None => Ok(LoginPermission::Allowed),
        }
    }

    async fn record_failed_attempt(&self, identifier: &str) -> Result<(), ApplicationError> {
        let key = Self::attempt_key(identifier);
        let now = chrono::Utc::now().timestamp();

        let mut data: LoginAttemptData = self.cache.get(&key).await?.unwrap_or_default();

        // Check if we're in a new window
        let window_expired =
            (now - data.window_start) > self.config.attempt_window.as_secs() as i64;
        if window_expired {
            // Reset window but keep lockout count for progressive backoff
            data.failed_attempts = 0;
            data.window_start = now;
            data.locked_until = None;
        }

        // Increment failed attempts
        data.failed_attempts += 1;

        tracing::debug!(
            identifier_hash = %Self::attempt_key(identifier),
            failed_attempts = data.failed_attempts,
            max_attempts = self.config.max_attempts,
            "Recording failed login attempt"
        );

        // Check if we need to lock the account
        if data.failed_attempts >= self.config.max_attempts {
            data.lockout_count += 1;
            let lockout_duration = self.calculate_lockout_duration(data.lockout_count);
            data.locked_until = Some(now + lockout_duration.as_secs() as i64);

            tracing::warn!(
                identifier_hash = %Self::attempt_key(identifier),
                lockout_count = data.lockout_count,
                lockout_duration_secs = lockout_duration.as_secs(),
                "Account locked due to too many failed attempts"
            );
        }

        // Store with TTL longer than max lockout duration to track lockout count
        let ttl = self.config.max_lockout_duration + self.config.attempt_window;
        self.cache.set(&key, &data, ttl).await?;

        Ok(())
    }

    async fn record_successful_login(&self, identifier: &str) -> Result<(), ApplicationError> {
        let key = Self::attempt_key(identifier);

        // On successful login, we can either:
        // 1. Delete the entry completely (fresh start)
        // 2. Keep lockout_count but reset attempts (progressive trust)
        // We'll use option 1 for simplicity - successful login resets everything
        self.cache.invalidate(&key).await?;

        tracing::debug!(
            identifier_hash = %Self::attempt_key(identifier),
            "Login attempt data cleared after successful login"
        );

        Ok(())
    }

    async fn get_attempt_data(
        &self,
        identifier: &str,
    ) -> Result<Option<LoginAttemptData>, ApplicationError> {
        let key = Self::attempt_key(identifier);
        self.cache.get(&key).await
    }
}

/// Extension trait for converting brute force errors to auth errors
pub trait BruteForceAuthError {
    /// Convert a locked permission to an auth error
    fn to_auth_error(self) -> Result<(), AuthError>;
}

impl BruteForceAuthError for LoginPermission {
    fn to_auth_error(self) -> Result<(), AuthError> {
        match self {
            LoginPermission::Allowed => Ok(()),
            LoginPermission::Locked {
                retry_after_seconds,
                message,
            } => Err(AuthError::InvalidPassword {
                reason: format!("{} (retry after {} seconds)", message, retry_after_seconds),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BruteForceConfig::default();
        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.base_lockout_duration, Duration::from_secs(60));
        assert_eq!(config.max_lockout_duration, Duration::from_secs(3600));
    }

    #[test]
    fn test_lockout_duration_calculation() {
        // Create a mock service to test duration calculation
        struct MockCache;

        #[async_trait]
        impl CacheService for MockCache {
            async fn get<T>(&self, _key: &str) -> Result<Option<T>, ApplicationError>
            where
                T: serde::de::DeserializeOwned + Send,
            {
                Ok(None)
            }
            async fn set<T>(
                &self,
                _key: &str,
                _value: &T,
                _ttl: Duration,
            ) -> Result<(), ApplicationError>
            where
                T: serde::Serialize + Send + Sync,
            {
                Ok(())
            }
            async fn invalidate(&self, _key: &str) -> Result<(), ApplicationError> {
                Ok(())
            }
        }

        let service = CacheBruteForceProtection::with_defaults(Arc::new(MockCache));

        // First lockout: 60 seconds
        assert_eq!(
            service.calculate_lockout_duration(1),
            Duration::from_secs(120)
        ); // 60 * 2^1

        // Second lockout: 240 seconds
        assert_eq!(
            service.calculate_lockout_duration(2),
            Duration::from_secs(240)
        ); // 60 * 2^2

        // Should be capped at max
        let max_lockout = service.calculate_lockout_duration(10);
        assert!(max_lockout <= service.config.max_lockout_duration);
    }

    #[test]
    fn test_attempt_key_generation() {
        let key1 =
            CacheBruteForceProtection::<crate::infrastructure::cache::DragonflyCache>::attempt_key(
                "user@example.com",
            );
        let key2 =
            CacheBruteForceProtection::<crate::infrastructure::cache::DragonflyCache>::attempt_key(
                "user@example.com",
            );
        let key3 =
            CacheBruteForceProtection::<crate::infrastructure::cache::DragonflyCache>::attempt_key(
                "other@example.com",
            );

        // Same input should produce same key
        assert_eq!(key1, key2);

        // Different input should produce different key
        assert_ne!(key1, key3);

        // Keys should start with the prefix
        assert!(key1.starts_with("auth:brute_force:"));
    }
}
