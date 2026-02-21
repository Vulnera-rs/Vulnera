//! Comprehensive test suite for the rate limiting system
//!
//! Tests cover:
//! - Token bucket algorithm
//! - Sliding window algorithm
//! - Tier-based rate limiting
//! - Organization bonus
//! - Auth endpoint protection
//! - In-memory storage
//! - Integration with Dragonfly/Redis

use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use vulnera_core::config::{
    AuthProtectionConfig, RateLimitStorageBackend, RequestCostsConfig, TierLimitConfig,
    TierLimitsConfig, TieredRateLimitConfig,
};
use vulnera_core::infrastructure::rate_limiter::{
    service::RateLimiterService,
    sliding_window::SlidingWindowLimiter,
    storage::{InMemoryRateLimitStorage, RateLimitStorage},
    token_bucket::TokenBucket,
    types::{AuthEndpoint, AuthTier, RateLimitKey, RateLimitResult, RequestCost},
};

// ============================================================================
// Test Fixtures
// ============================================================================

fn default_test_config() -> TieredRateLimitConfig {
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
            free: 0,
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

fn strict_test_config() -> TieredRateLimitConfig {
    TieredRateLimitConfig {
        enabled: true,
        storage_backend: RateLimitStorageBackend::Memory,
        cleanup_interval_seconds: 60,
        tiers: TierLimitsConfig {
            api_key: TierLimitConfig {
                requests_per_minute: 10,
                requests_per_hour: 50,
                burst_size: 5,
            },
            authenticated: TierLimitConfig {
                requests_per_minute: 5,
                requests_per_hour: 25,
                burst_size: 2,
            },
            anonymous: TierLimitConfig {
                requests_per_minute: 3,
                requests_per_hour: 10,
                burst_size: 1,
            },
            org_bonus_percent: 20,
        },
        costs: RequestCostsConfig {
            get: 1,
            post: 2,
            analysis: 5,
            llm: 10,
            free: 0,
        },
        auth_protection: AuthProtectionConfig {
            enabled: true,
            login_attempts_per_minute: 3,
            login_attempts_per_hour: 10,
            register_attempts_per_minute: 2,
            register_attempts_per_hour: 5,
            lockout_duration_minutes: 1,
        },
    }
}

fn create_test_storage() -> Arc<dyn RateLimitStorage> {
    Arc::new(InMemoryRateLimitStorage::new())
}

// ============================================================================
// Token Bucket Algorithm Tests
// ============================================================================

mod token_bucket_tests {
    use super::*;

    #[tokio::test]
    async fn test_initial_request_allowed() {
        let storage = create_test_storage();
        let bucket = TokenBucket::new(storage, "test");
        let config = default_test_config();

        let key = RateLimitKey::Ip("192.168.1.1".to_string());
        let result = bucket
            .check(&key, AuthTier::Anonymous, &config.tiers.anonymous, 1, 0)
            .await;

        assert!(result.allowed);
        assert!(result.remaining > 0);
        assert!(result.retry_after.is_none());
    }

    #[tokio::test]
    async fn test_burst_allowed() {
        let storage = create_test_storage();
        let bucket = TokenBucket::new(storage, "test");
        let config = strict_test_config();

        let key = RateLimitKey::Ip("192.168.1.1".to_string());

        // Anonymous has burst_size=1, requests_per_minute=3, so max_tokens=4
        // Make 4 requests in quick succession (burst)
        for i in 0..4 {
            let result = bucket
                .check(&key, AuthTier::Anonymous, &config.tiers.anonymous, 1, 0)
                .await;
            assert!(
                result.allowed,
                "Request {} should be allowed in burst",
                i + 1
            );
        }
    }

    #[tokio::test]
    async fn test_exceeding_limit_blocked() {
        let storage = create_test_storage();
        let bucket = TokenBucket::new(storage, "test");
        let config = strict_test_config();

        let key = RateLimitKey::Ip("192.168.1.1".to_string());

        // Anonymous: requests_per_minute=3, burst_size=1 -> max_tokens=4
        // Exhaust all tokens
        for _ in 0..4 {
            let _ = bucket
                .check(&key, AuthTier::Anonymous, &config.tiers.anonymous, 1, 0)
                .await;
        }

        // Next request should be blocked
        let result = bucket
            .check(&key, AuthTier::Anonymous, &config.tiers.anonymous, 1, 0)
            .await;

        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
        assert!(result.retry_after.is_some());
    }

    #[tokio::test]
    async fn test_different_keys_independent() {
        let storage = create_test_storage();
        let bucket = TokenBucket::new(storage, "test");
        let config = strict_test_config();

        let key1 = RateLimitKey::Ip("192.168.1.1".to_string());
        let key2 = RateLimitKey::Ip("192.168.1.2".to_string());

        // Exhaust tokens for key1
        for _ in 0..10 {
            let _ = bucket
                .check(&key1, AuthTier::Anonymous, &config.tiers.anonymous, 1, 0)
                .await;
        }

        // key2 should still be allowed
        let result = bucket
            .check(&key2, AuthTier::Anonymous, &config.tiers.anonymous, 1, 0)
            .await;
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_peek_does_not_consume_tokens() {
        let storage = create_test_storage();
        let bucket = TokenBucket::new(storage, "test");
        let config = default_test_config();

        let key = RateLimitKey::Ip("192.168.1.1".to_string());

        // Peek
        let peek_result = bucket
            .peek(&key, AuthTier::Anonymous, &config.tiers.anonymous, 0)
            .await;

        // Check (should have same remaining)
        let check_result = bucket
            .check(&key, AuthTier::Anonymous, &config.tiers.anonymous, 1, 0)
            .await;

        // After peek and 1 check, remaining should be initial - 1
        // (peek doesn't consume, check consumes 1)
        assert!(check_result.remaining < peek_result.remaining);
    }

    #[tokio::test]
    async fn test_org_bonus_increases_limit() {
        let storage = create_test_storage();
        let bucket = TokenBucket::new(storage, "test");
        let config = default_test_config();

        let key_no_bonus = RateLimitKey::UserId(Uuid::new_v4());
        let key_with_bonus = RateLimitKey::UserId(Uuid::new_v4());

        // Without bonus (0%)
        let result_no_bonus = bucket
            .peek(
                &key_no_bonus,
                AuthTier::Authenticated,
                &config.tiers.authenticated,
                0,
            )
            .await;

        // With 20% bonus
        let result_with_bonus = bucket
            .peek(
                &key_with_bonus,
                AuthTier::Authenticated,
                &config.tiers.authenticated,
                20,
            )
            .await;

        // 60 req/min + 20% = 72 req/min
        assert_eq!(result_no_bonus.limit, 60);
        assert_eq!(result_with_bonus.limit, 72);
    }

    #[tokio::test]
    async fn test_cost_weighting() {
        let storage = create_test_storage();
        let bucket = TokenBucket::new(storage, "test");
        let config = default_test_config();

        let key = RateLimitKey::UserId(Uuid::new_v4());

        // Initial state
        let initial = bucket
            .peek(
                &key,
                AuthTier::Authenticated,
                &config.tiers.authenticated,
                0,
            )
            .await;

        // Consume with GET cost (1)
        let _ = bucket
            .check(
                &key,
                AuthTier::Authenticated,
                &config.tiers.authenticated,
                1,
                0,
            )
            .await;

        let after_get = bucket
            .peek(
                &key,
                AuthTier::Authenticated,
                &config.tiers.authenticated,
                0,
            )
            .await;

        // Consume with LLM cost (10)
        let _ = bucket
            .check(
                &key,
                AuthTier::Authenticated,
                &config.tiers.authenticated,
                10,
                0,
            )
            .await;

        let after_llm = bucket
            .peek(
                &key,
                AuthTier::Authenticated,
                &config.tiers.authenticated,
                0,
            )
            .await;

        // GET consumed 1 token, LLM consumed 10 tokens
        assert_eq!(initial.remaining - after_get.remaining, 1);
        assert_eq!(after_get.remaining - after_llm.remaining, 10);
    }
}

// ============================================================================
// Sliding Window Algorithm Tests (Auth Protection)
// ============================================================================

mod sliding_window_tests {
    use super::*;

    #[tokio::test]
    async fn test_auth_initial_request_allowed() {
        let storage = create_test_storage();
        let limiter = SlidingWindowLimiter::new(storage, "test");
        let config = default_test_config();

        let result = limiter
            .check("192.168.1.1", AuthEndpoint::Login, &config.auth_protection)
            .await;

        assert!(result.allowed);
        assert!(result.remaining > 0);
        assert!(result.lockout_until.is_none());
    }

    #[tokio::test]
    async fn test_auth_disabled_always_allows() {
        let storage = create_test_storage();
        let limiter = SlidingWindowLimiter::new(storage, "test");
        let mut config = default_test_config();
        config.auth_protection.enabled = false;

        // Make many requests - all should be allowed
        for _ in 0..100 {
            let result = limiter
                .check("192.168.1.1", AuthEndpoint::Login, &config.auth_protection)
                .await;
            assert!(result.allowed);
        }
    }

    #[tokio::test]
    async fn test_auth_lockout_on_exceed() {
        let storage = create_test_storage();
        let limiter = SlidingWindowLimiter::new(storage, "test");
        let config = strict_test_config();

        // Make requests up to limit (3 per minute for login)
        for _ in 0..3 {
            let _ = limiter
                .check("192.168.1.1", AuthEndpoint::Login, &config.auth_protection)
                .await;
        }

        // Next request should be blocked with lockout
        let result = limiter
            .check("192.168.1.1", AuthEndpoint::Login, &config.auth_protection)
            .await;

        assert!(!result.allowed);
        assert!(result.lockout_until.is_some());
    }

    #[tokio::test]
    async fn test_auth_different_endpoints_independent() {
        let storage = create_test_storage();
        let limiter = SlidingWindowLimiter::new(storage, "test");
        let config = strict_test_config();

        // Exceed login limit
        for _ in 0..10 {
            let _ = limiter
                .check("192.168.1.1", AuthEndpoint::Login, &config.auth_protection)
                .await;
        }

        // Register should still be allowed (different endpoint)
        let result = limiter
            .check(
                "192.168.1.1",
                AuthEndpoint::Register,
                &config.auth_protection,
            )
            .await;

        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_auth_different_ips_independent() {
        let storage = create_test_storage();
        let limiter = SlidingWindowLimiter::new(storage, "test");
        let config = strict_test_config();

        // Exceed limit for IP1
        for _ in 0..10 {
            let _ = limiter
                .check("192.168.1.1", AuthEndpoint::Login, &config.auth_protection)
                .await;
        }

        // IP2 should still be allowed
        let result = limiter
            .check("192.168.1.2", AuthEndpoint::Login, &config.auth_protection)
            .await;

        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_auth_clear_removes_state() {
        let storage = create_test_storage();
        let limiter = SlidingWindowLimiter::new(storage, "test");
        let config = strict_test_config();

        // Make some requests
        for _ in 0..2 {
            let _ = limiter
                .check("192.168.1.1", AuthEndpoint::Login, &config.auth_protection)
                .await;
        }

        // Clear the state
        limiter.clear("192.168.1.1", AuthEndpoint::Login).await;

        // Should have full remaining again
        let result = limiter
            .check("192.168.1.1", AuthEndpoint::Login, &config.auth_protection)
            .await;

        assert!(result.allowed);
        assert!(result.remaining > 0);
    }
}

// ============================================================================
// Rate Limiter Service Tests
// ============================================================================

mod service_tests {
    use super::*;

    #[tokio::test]
    async fn test_service_disabled() {
        let mut config = default_test_config();
        config.enabled = false;

        let storage = create_test_storage();
        let service = RateLimiterService::with_storage(storage, config);

        assert!(!service.is_enabled());

        let result = service
            .check_api_limit("192.168.1.1", None, None, false, RequestCost::Get)
            .await;

        assert!(result.allowed);
        assert_eq!(result.limit, u32::MAX);
    }

    #[tokio::test]
    async fn test_service_tier_detection_anonymous() {
        let config = default_test_config();
        let storage = create_test_storage();
        let service = RateLimiterService::with_storage(storage, config);

        let result = service
            .check_api_limit("192.168.1.1", None, None, false, RequestCost::Get)
            .await;

        assert_eq!(result.tier, AuthTier::Anonymous);
    }

    #[tokio::test]
    async fn test_service_tier_detection_authenticated() {
        let config = default_test_config();
        let storage = create_test_storage();
        let service = RateLimiterService::with_storage(storage, config);

        let user_id = Uuid::new_v4();
        let result = service
            .check_api_limit("192.168.1.1", Some(user_id), None, false, RequestCost::Get)
            .await;

        assert_eq!(result.tier, AuthTier::Authenticated);
    }

    #[tokio::test]
    async fn test_service_tier_detection_api_key() {
        let config = default_test_config();
        let storage = create_test_storage();
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

        assert_eq!(result.tier, AuthTier::ApiKey);
    }

    #[tokio::test]
    async fn test_service_api_key_priority_over_user() {
        let config = default_test_config();
        let storage = create_test_storage();
        let service = RateLimiterService::with_storage(storage, config);

        let user_id = Uuid::new_v4();
        let api_key_id = Uuid::new_v4();

        // When both are present, API key takes priority
        let result = service
            .check_api_limit(
                "192.168.1.1",
                Some(user_id),
                Some(api_key_id),
                false,
                RequestCost::Get,
            )
            .await;

        assert_eq!(result.tier, AuthTier::ApiKey);
    }

    #[tokio::test]
    async fn test_service_org_bonus() {
        let config = default_test_config();
        let storage = create_test_storage();
        let service = RateLimiterService::with_storage(storage, config);

        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();

        // User without org membership
        let result_no_org = service
            .peek_api_limit("192.168.1.1", Some(user1), None, false)
            .await;

        // User with org membership
        let result_with_org = service
            .peek_api_limit("192.168.1.1", Some(user2), None, true)
            .await;

        // Org member should have 20% higher limit
        assert!(result_with_org.limit > result_no_org.limit);
        assert_eq!(result_with_org.limit, result_no_org.limit * 120 / 100);
    }

    #[tokio::test]
    async fn test_service_request_costs() {
        let config = default_test_config();
        let storage = create_test_storage();
        let service = RateLimiterService::with_storage(storage, config);

        let user_id = Uuid::new_v4();

        // GET (cost 1)
        let _ = service
            .check_api_limit("192.168.1.1", Some(user_id), None, false, RequestCost::Get)
            .await;
        let after_get = service
            .peek_api_limit("192.168.1.1", Some(user_id), None, false)
            .await;

        // POST (cost 2)
        let _ = service
            .check_api_limit("192.168.1.1", Some(user_id), None, false, RequestCost::Post)
            .await;
        let after_post = service
            .peek_api_limit("192.168.1.1", Some(user_id), None, false)
            .await;

        // Analysis (cost 5)
        let _ = service
            .check_api_limit(
                "192.168.1.1",
                Some(user_id),
                None,
                false,
                RequestCost::Analysis,
            )
            .await;
        let after_analysis = service
            .peek_api_limit("192.168.1.1", Some(user_id), None, false)
            .await;

        // LLM (cost 10)
        let _ = service
            .check_api_limit("192.168.1.1", Some(user_id), None, false, RequestCost::Llm)
            .await;
        let after_llm = service
            .peek_api_limit("192.168.1.1", Some(user_id), None, false)
            .await;

        // Verify costs
        assert_eq!(after_get.remaining - after_post.remaining, 2);
        assert_eq!(after_post.remaining - after_analysis.remaining, 5);
        assert_eq!(after_analysis.remaining - after_llm.remaining, 10);
    }

    #[tokio::test]
    async fn test_service_auth_limit() {
        let config = default_test_config();
        let storage = create_test_storage();
        let service = RateLimiterService::with_storage(storage, config);

        let result = service
            .check_auth_limit("192.168.1.1", AuthEndpoint::Login)
            .await;

        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_service_auth_limit_disabled() {
        let mut config = default_test_config();
        config.auth_protection.enabled = false;

        let storage = create_test_storage();
        let service = RateLimiterService::with_storage(storage, config);

        // Make many requests - all should be allowed
        for _ in 0..100 {
            let result = service
                .check_auth_limit("192.168.1.1", AuthEndpoint::Login)
                .await;
            assert!(result.allowed);
        }
    }

    #[tokio::test]
    async fn test_service_clear_auth_limit() {
        let config = strict_test_config();
        let storage = create_test_storage();
        let service = RateLimiterService::with_storage(storage, config);

        // Make some login attempts
        for _ in 0..2 {
            let _ = service
                .check_auth_limit("192.168.1.1", AuthEndpoint::Login)
                .await;
        }

        // Clear (simulating successful login)
        service
            .clear_auth_limit("192.168.1.1", AuthEndpoint::Login)
            .await;

        // Should have fresh state
        let result = service
            .check_auth_limit("192.168.1.1", AuthEndpoint::Login)
            .await;
        assert!(result.allowed);
    }
}

// ============================================================================
// Storage Backend Tests
// ============================================================================

mod storage_tests {
    use super::*;
    use vulnera_core::infrastructure::rate_limiter::types::{SlidingWindowState, TokenBucketState};

    #[tokio::test]
    async fn test_memory_storage_token_bucket_lifecycle() {
        let storage = InMemoryRateLimitStorage::new();

        let key = "test:bucket";
        let state = TokenBucketState {
            tokens: 50.0,
            last_refill: 1234567890,
        };

        // Set
        storage.set_token_bucket(key, &state, 60).await.unwrap();

        // Get
        let retrieved = storage.get_token_bucket(key).await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.tokens, 50.0);
        assert_eq!(retrieved.last_refill, 1234567890);

        // Delete
        storage.delete(key).await.unwrap();

        // Verify deleted
        let retrieved = storage.get_token_bucket(key).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_memory_storage_sliding_window_lifecycle() {
        let storage = InMemoryRateLimitStorage::new();

        let key = "test:window";
        let state = SlidingWindowState {
            current_count: 5,
            previous_count: 10,
            window_start: 1234567890,
        };

        // Set
        storage.set_sliding_window(key, &state, 60).await.unwrap();

        // Get
        let retrieved = storage.get_sliding_window(key).await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.current_count, 5);
        assert_eq!(retrieved.previous_count, 10);
    }

    #[tokio::test]
    async fn test_memory_storage_lockout_lifecycle() {
        let storage = InMemoryRateLimitStorage::new();

        let key = "test:auth";

        // Set lockout
        storage.set_lockout(key, 1234567890, 60).await.unwrap();

        // Get lockout
        let retrieved = storage.get_lockout(key).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), 1234567890);
    }

    #[tokio::test]
    async fn test_memory_storage_cleanup() {
        let storage = InMemoryRateLimitStorage::new();

        // Set some values
        let state = TokenBucketState {
            tokens: 50.0,
            last_refill: 1234567890,
        };
        storage
            .set_token_bucket("test:bucket1", &state, 60)
            .await
            .unwrap();
        storage
            .set_token_bucket("test:bucket2", &state, 1) // 1 second TTL
            .await
            .unwrap();

        // Wait for short TTL to expire
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Cleanup
        storage.cleanup().await;

        // bucket1 should still exist (60s TTL)
        let b1 = storage.get_token_bucket("test:bucket1").await.unwrap();
        assert!(b1.is_some());

        // bucket2 should be gone (1s TTL expired)
        let b2 = storage.get_token_bucket("test:bucket2").await.unwrap();
        assert!(b2.is_none());
    }
}

// ============================================================================
// Type Tests
// ============================================================================

mod type_tests {
    use super::*;

    #[test]
    fn test_auth_tier_as_str() {
        assert_eq!(AuthTier::ApiKey.as_str(), "api_key");
        assert_eq!(AuthTier::Authenticated.as_str(), "authenticated");
        assert_eq!(AuthTier::Anonymous.as_str(), "anonymous");
    }

    #[test]
    fn test_auth_tier_display() {
        assert_eq!(format!("{}", AuthTier::ApiKey), "api_key");
        assert_eq!(format!("{}", AuthTier::Authenticated), "authenticated");
        assert_eq!(format!("{}", AuthTier::Anonymous), "anonymous");
    }

    #[test]
    fn test_rate_limit_key_to_redis() {
        let ip_key = RateLimitKey::Ip("192.168.1.1".to_string());
        assert_eq!(ip_key.to_redis_key("prefix"), "prefix:ip:192.168.1.1");

        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let user_key = RateLimitKey::UserId(user_id);
        assert_eq!(
            user_key.to_redis_key("prefix"),
            "prefix:user:550e8400-e29b-41d4-a716-446655440000"
        );

        let api_key_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap();
        let api_key = RateLimitKey::ApiKeyId(api_key_id);
        assert_eq!(
            api_key.to_redis_key("prefix"),
            "prefix:apikey:550e8400-e29b-41d4-a716-446655440001"
        );

        let auth_ip = RateLimitKey::AuthIp("10.0.0.1".to_string());
        assert_eq!(auth_ip.to_redis_key("prefix"), "prefix:auth:10.0.0.1");
    }

    #[test]
    fn test_rate_limit_result_allowed() {
        let result = RateLimitResult::allowed(100, 50, 1234567890, AuthTier::ApiKey);
        assert!(result.allowed);
        assert_eq!(result.limit, 100);
        assert_eq!(result.remaining, 50);
        assert_eq!(result.reset_at, 1234567890);
        assert!(result.retry_after.is_none());
        assert_eq!(result.tier, AuthTier::ApiKey);
    }

    #[test]
    fn test_rate_limit_result_blocked() {
        let result = RateLimitResult::blocked(100, 1234567890, 30, AuthTier::Anonymous);
        assert!(!result.allowed);
        assert_eq!(result.limit, 100);
        assert_eq!(result.remaining, 0);
        assert_eq!(result.reset_at, 1234567890);
        assert_eq!(result.retry_after, Some(30));
        assert_eq!(result.tier, AuthTier::Anonymous);
    }

    #[test]
    fn test_auth_endpoint_as_str() {
        assert_eq!(AuthEndpoint::Login.as_str(), "login");
        assert_eq!(AuthEndpoint::Register.as_str(), "register");
    }

    #[test]
    fn test_request_cost_value() {
        let config = RequestCostsConfig {
            get: 1,
            post: 2,
            analysis: 5,
            llm: 10,
            free: 0,
        };

        assert_eq!(RequestCost::Get.value(&config), 1);
        assert_eq!(RequestCost::Post.value(&config), 2);
        assert_eq!(RequestCost::Analysis.value(&config), 5);
        assert_eq!(RequestCost::Llm.value(&config), 10);
        assert_eq!(RequestCost::Custom(42).value(&config), 42);
    }
}

// ============================================================================
// Integration Tests (with test containers)
// Requires Redis/Dragonfly to be running - run with --ignored flag
// ============================================================================

#[cfg(test)]
mod integration_tests {
    use super::*;
    use testcontainers::{GenericImage, core::WaitFor, runners::AsyncRunner};
    use vulnera_core::infrastructure::rate_limiter::types::TokenBucketState;

    async fn start_redis() -> (testcontainers::ContainerAsync<GenericImage>, String) {
        let container = GenericImage::new("redis", "7-alpine")
            .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
            .start()
            .await
            .expect("Failed to start Redis container");

        let port = container
            .get_host_port_ipv4(6379)
            .await
            .expect("Failed to get port");
        let url = format!("redis://127.0.0.1:{}", port);

        (container, url)
    }

    #[tokio::test]
    #[ignore = "requires Docker for Redis container"]
    async fn test_dragonfly_storage_integration() {
        use vulnera_core::infrastructure::rate_limiter::storage::DragonflyRateLimitStorage;

        let (_container, url) = start_redis().await;

        let storage = DragonflyRateLimitStorage::new(&url)
            .await
            .expect("Failed to create storage");

        let state = TokenBucketState {
            tokens: 50.0,
            last_refill: 1234567890,
        };

        // Set
        storage
            .set_token_bucket("test:integration", &state, 60)
            .await
            .unwrap();

        // Get
        let retrieved = storage.get_token_bucket("test:integration").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().tokens, 50.0);
    }

    #[tokio::test]
    #[ignore = "requires Docker for Redis container"]
    async fn test_service_with_dragonfly() {
        use vulnera_core::infrastructure::rate_limiter::storage::DragonflyRateLimitStorage;

        let (_container, url) = start_redis().await;

        // Create storage directly instead of using env var
        let storage = Arc::new(
            DragonflyRateLimitStorage::new(&url)
                .await
                .expect("Failed to create storage"),
        );

        let config = default_test_config();
        let service = RateLimiterService::with_storage(storage, config);

        let result = service
            .check_api_limit("192.168.1.1", None, None, false, RequestCost::Get)
            .await;

        assert!(result.allowed);
    }
}
