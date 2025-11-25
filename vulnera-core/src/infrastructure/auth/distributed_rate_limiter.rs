//! Distributed rate limiter using cache backend
//!
//! This module provides a Redis/Dragonfly-backed rate limiter for use in
//! multi-instance deployments where rate limits need to be shared across servers.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

use crate::application::errors::ApplicationError;
use crate::application::vulnerability::services::CacheService;

/// Rate limit result
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    /// Request is allowed
    Allowed {
        /// Number of remaining requests
        remaining: u32,
        /// Time until limit resets (in seconds)
        reset_after: u64,
    },
    /// Request is rate limited
    Limited {
        /// Seconds to wait before retrying
        retry_after: u64,
        /// Maximum requests allowed
        limit: u32,
    },
}

/// Configuration for distributed rate limiting
#[derive(Debug, Clone)]
pub struct DistributedRateLimitConfig {
    /// Maximum requests for authenticated users per window
    pub authenticated_limit: u32,
    /// Window duration for authenticated users
    pub authenticated_window: Duration,
    /// Maximum requests for unauthenticated users per window
    pub unauthenticated_limit: u32,
    /// Window duration for unauthenticated users
    pub unauthenticated_window: Duration,
    /// Key prefix for rate limit entries
    pub key_prefix: String,
}

impl Default for DistributedRateLimitConfig {
    fn default() -> Self {
        Self {
            authenticated_limit: 60,                            // 60 requests
            authenticated_window: Duration::from_secs(60),      // per minute
            unauthenticated_limit: 10,                          // 10 requests
            unauthenticated_window: Duration::from_secs(86400), // per day
            key_prefix: "rate_limit".to_string(),
        }
    }
}

/// Rate limit entry stored in cache
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RateLimitEntry {
    /// Number of requests made in the current window
    count: u32,
    /// Window start timestamp (Unix seconds)
    window_start: i64,
}

/// Trait for distributed rate limiting
#[async_trait]
pub trait DistributedRateLimiter: Send + Sync {
    /// Check rate limit for a key
    ///
    /// # Arguments
    /// * `key` - The rate limit key (e.g., IP address, API key hash)
    /// * `is_authenticated` - Whether the request is authenticated
    ///
    /// # Returns
    /// `RateLimitResult` indicating whether the request is allowed
    async fn check(
        &self,
        key: &str,
        is_authenticated: bool,
    ) -> Result<RateLimitResult, ApplicationError>;

    /// Get current rate limit status for a key
    async fn get_status(
        &self,
        key: &str,
        is_authenticated: bool,
    ) -> Result<Option<(u32, u32)>, ApplicationError>;
}

/// Cache-backed distributed rate limiter
pub struct CacheDistributedRateLimiter<C: CacheService> {
    cache: Arc<C>,
    config: DistributedRateLimitConfig,
}

impl<C: CacheService> CacheDistributedRateLimiter<C> {
    /// Create a new cache-backed rate limiter
    pub fn new(cache: Arc<C>, config: DistributedRateLimitConfig) -> Self {
        Self { cache, config }
    }

    /// Create with default configuration
    pub fn with_defaults(cache: Arc<C>) -> Self {
        Self::new(cache, DistributedRateLimitConfig::default())
    }

    /// Generate cache key for rate limit entry
    fn cache_key(&self, key: &str, is_authenticated: bool) -> String {
        let auth_prefix = if is_authenticated { "auth" } else { "unauth" };
        format!("{}:{}:{}", self.config.key_prefix, auth_prefix, key)
    }

    /// Get limit and window based on authentication status
    fn get_limits(&self, is_authenticated: bool) -> (u32, Duration) {
        if is_authenticated {
            (
                self.config.authenticated_limit,
                self.config.authenticated_window,
            )
        } else {
            (
                self.config.unauthenticated_limit,
                self.config.unauthenticated_window,
            )
        }
    }
}

#[async_trait]
impl<C: CacheService + Send + Sync> DistributedRateLimiter for CacheDistributedRateLimiter<C> {
    async fn check(
        &self,
        key: &str,
        is_authenticated: bool,
    ) -> Result<RateLimitResult, ApplicationError> {
        let cache_key = self.cache_key(key, is_authenticated);
        let (limit, window) = self.get_limits(is_authenticated);
        let now = chrono::Utc::now().timestamp();
        let window_secs = window.as_secs() as i64;

        // Get current entry from cache
        let entry: Option<RateLimitEntry> = self.cache.get(&cache_key).await?;

        let (new_entry, result) = match entry {
            Some(mut existing) => {
                // Check if we're still in the same window
                if now - existing.window_start < window_secs {
                    // Same window - check limit
                    if existing.count >= limit {
                        // Rate limited
                        let reset_after = (existing.window_start + window_secs - now) as u64;
                        return Ok(RateLimitResult::Limited {
                            retry_after: reset_after,
                            limit,
                        });
                    }

                    // Increment count
                    existing.count += 1;
                    let remaining = limit.saturating_sub(existing.count);
                    let reset_after = (existing.window_start + window_secs - now) as u64;

                    (
                        existing,
                        RateLimitResult::Allowed {
                            remaining,
                            reset_after,
                        },
                    )
                } else {
                    // New window - reset counter
                    let new = RateLimitEntry {
                        count: 1,
                        window_start: now,
                    };
                    let remaining = limit - 1;
                    let reset_after = window_secs as u64;

                    (
                        new,
                        RateLimitResult::Allowed {
                            remaining,
                            reset_after,
                        },
                    )
                }
            }
            None => {
                // First request - create new entry
                let new = RateLimitEntry {
                    count: 1,
                    window_start: now,
                };
                let remaining = limit - 1;
                let reset_after = window_secs as u64;

                (
                    new,
                    RateLimitResult::Allowed {
                        remaining,
                        reset_after,
                    },
                )
            }
        };

        // Store updated entry with TTL slightly longer than window
        let ttl = window + Duration::from_secs(60); // Add 1 minute buffer
        self.cache.set(&cache_key, &new_entry, ttl).await?;

        Ok(result)
    }

    async fn get_status(
        &self,
        key: &str,
        is_authenticated: bool,
    ) -> Result<Option<(u32, u32)>, ApplicationError> {
        let cache_key = self.cache_key(key, is_authenticated);
        let (limit, window) = self.get_limits(is_authenticated);
        let now = chrono::Utc::now().timestamp();
        let window_secs = window.as_secs() as i64;

        let entry: Option<RateLimitEntry> = self.cache.get(&cache_key).await?;

        match entry {
            Some(existing) => {
                // Check if still in window
                if now - existing.window_start < window_secs {
                    let remaining = limit.saturating_sub(existing.count);
                    Ok(Some((remaining, limit)))
                } else {
                    // Window expired - full limit available
                    Ok(Some((limit, limit)))
                }
            }
            None => {
                // No entry - full limit available
                Ok(Some((limit, limit)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DistributedRateLimitConfig::default();
        assert_eq!(config.authenticated_limit, 60);
        assert_eq!(config.unauthenticated_limit, 10);
    }

    #[test]
    fn test_cache_key_generation() {
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

        let limiter = CacheDistributedRateLimiter::with_defaults(Arc::new(MockCache));

        let auth_key = limiter.cache_key("192.168.1.1", true);
        assert_eq!(auth_key, "rate_limit:auth:192.168.1.1");

        let unauth_key = limiter.cache_key("192.168.1.1", false);
        assert_eq!(unauth_key, "rate_limit:unauth:192.168.1.1");
    }
}
