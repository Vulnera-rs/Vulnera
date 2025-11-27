//! Token Bucket Rate Limiter
//!
//! Implements the token bucket algorithm for rate limiting.
//! Tokens are added to the bucket at a constant rate, and each request
//! consumes tokens. If the bucket is empty, the request is rejected.
//!
//! This allows for bursty traffic while maintaining an average rate limit.

use super::storage::RateLimitStorage;
use super::types::{current_time_millis, AuthTier, RateLimitKey, RateLimitResult, TokenBucketState};
use crate::config::TierLimitConfig;
use std::sync::Arc;
use tracing::{debug, warn};

/// Token bucket rate limiter
pub struct TokenBucket {
    storage: Arc<dyn RateLimitStorage>,
    key_prefix: String,
}

impl TokenBucket {
    /// Create a new token bucket rate limiter
    pub fn new(storage: Arc<dyn RateLimitStorage>, key_prefix: &str) -> Self {
        Self {
            storage,
            key_prefix: key_prefix.to_string(),
        }
    }

    /// Check if a request is allowed and consume tokens
    ///
    /// # Arguments
    /// * `key` - The rate limit key (IP, user ID, or API key ID)
    /// * `tier` - The authentication tier
    /// * `config` - The tier limit configuration
    /// * `cost` - The number of tokens to consume
    /// * `org_bonus_percent` - Bonus percentage for organization members (0-100)
    ///
    /// # Returns
    /// A `RateLimitResult` indicating if the request is allowed
    pub async fn check(
        &self,
        key: &RateLimitKey,
        tier: AuthTier,
        config: &TierLimitConfig,
        cost: u32,
        org_bonus_percent: u8,
    ) -> RateLimitResult {
        let redis_key = key.to_redis_key(&self.key_prefix);

        // Apply organization bonus
        let effective_limit = apply_org_bonus(config.requests_per_minute, org_bonus_percent);
        let effective_burst = apply_org_bonus(config.burst_size, org_bonus_percent);
        let max_tokens = effective_limit + effective_burst;

        // Refill rate: tokens per millisecond
        let refill_rate = effective_limit as f64 / 60_000.0; // per minute -> per millisecond

        // Get current state or create new
        let mut state = match self.storage.get_token_bucket(&redis_key).await {
            Ok(Some(state)) => state,
            Ok(None) => TokenBucketState::new(max_tokens),
            Err(e) => {
                warn!("Failed to get token bucket state, allowing request: {}", e);
                return RateLimitResult::allowed(
                    effective_limit,
                    effective_limit,
                    calculate_reset_time(),
                    tier,
                );
            }
        };

        let now = current_time_millis();

        // Refill tokens based on time elapsed
        let elapsed_ms = now.saturating_sub(state.last_refill);
        let tokens_to_add = elapsed_ms as f64 * refill_rate;
        state.tokens = (state.tokens + tokens_to_add).min(max_tokens as f64);
        state.last_refill = now;

        // Check if we have enough tokens
        let cost_f64 = cost as f64;
        if state.tokens >= cost_f64 {
            // Consume tokens
            state.tokens -= cost_f64;

            // Save state with TTL (2 minutes to ensure cleanup)
            if let Err(e) = self.storage.set_token_bucket(&redis_key, &state, 120).await {
                warn!("Failed to save token bucket state: {}", e);
            }

            let remaining = state.tokens.floor() as u32;
            debug!(
                key = %redis_key,
                tier = %tier,
                remaining = remaining,
                limit = effective_limit,
                "Rate limit check passed"
            );

            RateLimitResult::allowed(effective_limit, remaining, calculate_reset_time(), tier)
        } else {
            // Not enough tokens, calculate retry-after
            let tokens_needed = cost_f64 - state.tokens;
            let wait_ms = (tokens_needed / refill_rate).ceil() as u64;
            let retry_after_secs = (wait_ms / 1000).max(1);

            // Save state anyway (to preserve refill calculation)
            if let Err(e) = self.storage.set_token_bucket(&redis_key, &state, 120).await {
                warn!("Failed to save token bucket state: {}", e);
            }

            debug!(
                key = %redis_key,
                tier = %tier,
                retry_after = retry_after_secs,
                "Rate limit exceeded"
            );

            RateLimitResult::blocked(
                effective_limit,
                calculate_reset_time(),
                retry_after_secs,
                tier,
            )
        }
    }

    /// Get the current state without consuming tokens (for headers)
    pub async fn peek(
        &self,
        key: &RateLimitKey,
        tier: AuthTier,
        config: &TierLimitConfig,
        org_bonus_percent: u8,
    ) -> RateLimitResult {
        let redis_key = key.to_redis_key(&self.key_prefix);

        let effective_limit = apply_org_bonus(config.requests_per_minute, org_bonus_percent);
        let effective_burst = apply_org_bonus(config.burst_size, org_bonus_percent);
        let max_tokens = effective_limit + effective_burst;
        let refill_rate = effective_limit as f64 / 60_000.0;

        let state = match self.storage.get_token_bucket(&redis_key).await {
            Ok(Some(mut state)) => {
                // Calculate current tokens with refill
                let now = current_time_millis();
                let elapsed_ms = now.saturating_sub(state.last_refill);
                let tokens_to_add = elapsed_ms as f64 * refill_rate;
                state.tokens = (state.tokens + tokens_to_add).min(max_tokens as f64);
                state
            }
            Ok(None) => TokenBucketState::new(max_tokens),
            Err(_) => TokenBucketState::new(max_tokens),
        };

        let remaining = state.tokens.floor() as u32;
        RateLimitResult::allowed(effective_limit, remaining, calculate_reset_time(), tier)
    }
}

/// Apply organization bonus to a limit value
fn apply_org_bonus(base: u32, bonus_percent: u8) -> u32 {
    if bonus_percent == 0 {
        return base;
    }
    let bonus = (base as u64 * bonus_percent as u64) / 100;
    (base as u64 + bonus).min(u32::MAX as u64) as u32
}

/// Calculate the reset time (end of current minute)
fn calculate_reset_time() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Reset at the end of the current minute
    (now / 60 + 1) * 60
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_org_bonus() {
        assert_eq!(apply_org_bonus(100, 0), 100);
        assert_eq!(apply_org_bonus(100, 20), 120);
        assert_eq!(apply_org_bonus(100, 50), 150);
        assert_eq!(apply_org_bonus(100, 100), 200);
    }

    #[test]
    fn test_calculate_reset_time() {
        let reset = calculate_reset_time();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Reset should be within the next minute
        assert!(reset > now);
        assert!(reset <= now + 60);
        // Reset should be on a minute boundary
        assert_eq!(reset % 60, 0);
    }
}
