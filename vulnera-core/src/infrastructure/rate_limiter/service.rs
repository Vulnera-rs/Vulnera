//! Rate Limiter Service
//!
//! The main service that coordinates rate limiting across the application.
//! Provides a unified interface for:
//! - Token bucket rate limiting for API requests
//! - Sliding window rate limiting for auth endpoints
//! - Tier-based limits with organization bonuses

use super::sliding_window::{AuthRateLimitResult, SlidingWindowLimiter};
use super::storage::{DragonflyRateLimitStorage, InMemoryRateLimitStorage, RateLimitStorage};
use super::token_bucket::TokenBucket;
use super::types::{AuthEndpoint, AuthTier, RateLimitKey, RateLimitResult, RequestCost};
use crate::config::{RateLimitStorageBackend, TieredRateLimitConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Main rate limiter service
pub struct RateLimiterService {
    /// Token bucket for general API rate limiting
    token_bucket: TokenBucket,
    /// Sliding window for auth endpoint protection
    auth_limiter: SlidingWindowLimiter,
    /// Storage backend
    storage: Arc<dyn RateLimitStorage>,
    /// Configuration
    config: TieredRateLimitConfig,
}

impl RateLimiterService {
    /// Create a new rate limiter service with explicit Dragonfly URL
    pub async fn new_with_url(
        config: TieredRateLimitConfig,
        dragonfly_url: &str,
    ) -> Result<Self, String> {
        let storage: Arc<dyn RateLimitStorage> = match config.storage_backend {
            RateLimitStorageBackend::Dragonfly => {
                match DragonflyRateLimitStorage::new(dragonfly_url).await {
                    Ok(storage) => {
                        info!(
                            "Rate limiter using Dragonfly storage backend at {}",
                            dragonfly_url
                        );
                        Arc::new(storage)
                    }
                    Err(e) => {
                        warn!(
                            "Failed to connect to Dragonfly for rate limiting, falling back to in-memory: {}",
                            e
                        );
                        Arc::new(InMemoryRateLimitStorage::new())
                    }
                }
            }
            RateLimitStorageBackend::Memory => {
                info!("Rate limiter using in-memory storage backend");
                Arc::new(InMemoryRateLimitStorage::new())
            }
        };

        let token_bucket = TokenBucket::new(Arc::clone(&storage), "ratelimit:api");
        let auth_limiter = SlidingWindowLimiter::new(Arc::clone(&storage), "ratelimit:auth");

        Ok(Self {
            token_bucket,
            auth_limiter,
            storage,
            config,
        })
    }

    /// Create with a custom storage backend (for testing)
    pub fn with_storage(storage: Arc<dyn RateLimitStorage>, config: TieredRateLimitConfig) -> Self {
        let token_bucket = TokenBucket::new(Arc::clone(&storage), "ratelimit:api");
        let auth_limiter = SlidingWindowLimiter::new(Arc::clone(&storage), "ratelimit:auth");

        Self {
            token_bucket,
            auth_limiter,
            storage,
            config,
        }
    }

    /// Check if rate limiting is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check rate limit for an API request
    ///
    /// # Arguments
    /// * `ip` - Client IP address
    /// * `user_id` - Optional user ID (for cookie auth)
    /// * `api_key_id` - Optional API key ID
    /// * `is_org_member` - Whether the user is an organization member
    /// * `cost` - The request cost type
    ///
    /// # Returns
    /// A `RateLimitResult` indicating if the request is allowed
    pub async fn check_api_limit(
        &self,
        ip: &str,
        user_id: Option<Uuid>,
        api_key_id: Option<Uuid>,
        is_org_member: bool,
        cost: RequestCost,
    ) -> RateLimitResult {
        if !self.config.enabled {
            return RateLimitResult::allowed(u32::MAX, u32::MAX, 0, AuthTier::Anonymous);
        }

        // Determine tier and key
        let (tier, key, tier_config) = if let Some(api_key) = api_key_id {
            (
                AuthTier::ApiKey,
                RateLimitKey::ApiKeyId(api_key),
                &self.config.tiers.api_key,
            )
        } else if let Some(user) = user_id {
            (
                AuthTier::Authenticated,
                RateLimitKey::UserId(user),
                &self.config.tiers.authenticated,
            )
        } else {
            (
                AuthTier::Anonymous,
                RateLimitKey::Ip(ip.to_string()),
                &self.config.tiers.anonymous,
            )
        };

        // Calculate request cost
        let cost_value = cost.value(&self.config.costs);

        // Apply org bonus if applicable
        let org_bonus = if is_org_member {
            self.config.tiers.org_bonus_percent
        } else {
            0
        };

        self.token_bucket
            .check(&key, tier, tier_config, cost_value, org_bonus)
            .await
    }

    /// Check rate limit for an auth endpoint (login/register)
    ///
    /// # Arguments
    /// * `ip` - Client IP address
    /// * `endpoint` - The auth endpoint type
    ///
    /// # Returns
    /// An `AuthRateLimitResult` indicating if the request is allowed
    pub async fn check_auth_limit(&self, ip: &str, endpoint: AuthEndpoint) -> AuthRateLimitResult {
        if !self.config.enabled || !self.config.auth_protection.enabled {
            return AuthRateLimitResult::allowed(u32::MAX, endpoint);
        }

        self.auth_limiter
            .check(ip, endpoint, &self.config.auth_protection)
            .await
    }

    /// Clear auth rate limit state after successful login
    pub async fn clear_auth_limit(&self, ip: &str, endpoint: AuthEndpoint) {
        self.auth_limiter.clear(ip, endpoint).await;
    }

    /// Get current rate limit status without consuming tokens
    pub async fn peek_api_limit(
        &self,
        ip: &str,
        user_id: Option<Uuid>,
        api_key_id: Option<Uuid>,
        is_org_member: bool,
    ) -> RateLimitResult {
        if !self.config.enabled {
            return RateLimitResult::allowed(u32::MAX, u32::MAX, 0, AuthTier::Anonymous);
        }

        let (tier, key, tier_config) = if let Some(api_key) = api_key_id {
            (
                AuthTier::ApiKey,
                RateLimitKey::ApiKeyId(api_key),
                &self.config.tiers.api_key,
            )
        } else if let Some(user) = user_id {
            (
                AuthTier::Authenticated,
                RateLimitKey::UserId(user),
                &self.config.tiers.authenticated,
            )
        } else {
            (
                AuthTier::Anonymous,
                RateLimitKey::Ip(ip.to_string()),
                &self.config.tiers.anonymous,
            )
        };

        let org_bonus = if is_org_member {
            self.config.tiers.org_bonus_percent
        } else {
            0
        };

        self.token_bucket
            .peek(&key, tier, tier_config, org_bonus)
            .await
    }

    /// Start the cleanup task for in-memory storage
    pub fn start_cleanup_task(self: Arc<Self>) {
        let cleanup_interval = Duration::from_secs(self.config.cleanup_interval_seconds);

        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);

            loop {
                interval.tick().await;
                self.storage.cleanup().await;
                debug!("Rate limiter cleanup completed");
            }
        });
    }

    /// Get the configuration
    pub fn config(&self) -> &TieredRateLimitConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuthProtectionConfig, RequestCostsConfig, TierLimitConfig, TierLimitsConfig,
    };

    fn test_config() -> TieredRateLimitConfig {
        TieredRateLimitConfig {
            enabled: true,
            storage_backend: RateLimitStorageBackend::Memory,
            cleanup_interval_seconds: 300,
            tiers: TierLimitsConfig {
                api_key: TierLimitConfig {
                    requests_per_minute: 100,
                    requests_per_hour: 2000,
                    burst_size: 20,
                },
                authenticated: TierLimitConfig {
                    requests_per_minute: 60,
                    requests_per_hour: 1000,
                    burst_size: 10,
                },
                anonymous: TierLimitConfig {
                    requests_per_minute: 20,
                    requests_per_hour: 100,
                    burst_size: 5,
                },
                org_bonus_percent: 20,
            },
            costs: RequestCostsConfig {
                get: 1,
                post: 2,
                analysis: 5,
                llm: 10,
            },
            auth_protection: AuthProtectionConfig {
                enabled: true,
                login_attempts_per_minute: 5,
                login_attempts_per_hour: 20,
                register_attempts_per_minute: 3,
                register_attempts_per_hour: 10,
                lockout_duration_minutes: 15,
            },
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_disabled() {
        let mut config = test_config();
        config.enabled = false;

        let storage = Arc::new(InMemoryRateLimitStorage::new());
        let service = RateLimiterService::with_storage(storage, config);

        let result = service
            .check_api_limit("192.168.1.1", None, None, false, RequestCost::Get)
            .await;

        assert!(result.allowed);
        assert_eq!(result.limit, u32::MAX);
    }

    #[tokio::test]
    async fn test_anonymous_rate_limit() {
        let config = test_config();
        let storage = Arc::new(InMemoryRateLimitStorage::new());
        let service = RateLimiterService::with_storage(storage, config);

        // First request should be allowed
        let result = service
            .check_api_limit("192.168.1.1", None, None, false, RequestCost::Get)
            .await;

        assert!(result.allowed);
        assert_eq!(result.tier, AuthTier::Anonymous);
        assert!(result.remaining > 0);
    }

    #[tokio::test]
    async fn test_authenticated_rate_limit() {
        let config = test_config();
        let storage = Arc::new(InMemoryRateLimitStorage::new());
        let service = RateLimiterService::with_storage(storage, config);

        let user_id = Uuid::new_v4();
        let result = service
            .check_api_limit("192.168.1.1", Some(user_id), None, false, RequestCost::Get)
            .await;

        assert!(result.allowed);
        assert_eq!(result.tier, AuthTier::Authenticated);
    }

    #[tokio::test]
    async fn test_api_key_rate_limit() {
        let config = test_config();
        let storage = Arc::new(InMemoryRateLimitStorage::new());
        let service = RateLimiterService::with_storage(storage, config);

        let api_key_id = Uuid::new_v4();
        let result = service
            .check_api_limit(
                "192.168.1.1",
                None,
                Some(api_key_id),
                false,
                RequestCost::Get,
            )
            .await;

        assert!(result.allowed);
        assert_eq!(result.tier, AuthTier::ApiKey);
    }

    #[tokio::test]
    async fn test_org_bonus_applied() {
        let config = test_config();
        let storage = Arc::new(InMemoryRateLimitStorage::new());
        let service = RateLimiterService::with_storage(storage, config);

        let user_id = Uuid::new_v4();

        // Without org bonus
        let result_no_bonus = service
            .peek_api_limit("192.168.1.1", Some(user_id), None, false)
            .await;

        // With org bonus (should have 20% more)
        let user_id2 = Uuid::new_v4();
        let result_with_bonus = service
            .peek_api_limit("192.168.1.1", Some(user_id2), None, true)
            .await;

        // Org member should have higher limit
        assert!(result_with_bonus.limit > result_no_bonus.limit);
    }

    #[tokio::test]
    async fn test_auth_rate_limit() {
        let config = test_config();
        let storage = Arc::new(InMemoryRateLimitStorage::new());
        let service = RateLimiterService::with_storage(storage, config);

        let result = service
            .check_auth_limit("192.168.1.1", AuthEndpoint::Login)
            .await;

        assert!(result.allowed);
        assert!(result.remaining > 0);
    }

    #[tokio::test]
    async fn test_request_cost() {
        let config = test_config();
        let storage = Arc::new(InMemoryRateLimitStorage::new());
        let service = RateLimiterService::with_storage(storage, config);

        let user_id = Uuid::new_v4();

        // GET costs 1
        let result1 = service
            .check_api_limit("192.168.1.1", Some(user_id), None, false, RequestCost::Get)
            .await;
        let remaining_after_get = result1.remaining;

        // LLM costs 10
        let result2 = service
            .check_api_limit("192.168.1.1", Some(user_id), None, false, RequestCost::Llm)
            .await;
        let remaining_after_llm = result2.remaining;

        // LLM should consume more tokens
        assert!(remaining_after_get > remaining_after_llm + 5);
    }
}
