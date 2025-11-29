//! Sliding Window Rate Limiter
//!
//! Implements the sliding window counter algorithm for rate limiting.
//! This is stricter than token bucket and doesn't allow bursts,
//! making it ideal for auth endpoint protection.
//!
//! The algorithm uses two windows (current and previous) and calculates
//! a weighted count based on how far we are into the current window.

use super::storage::RateLimitStorage;
use super::types::{AuthEndpoint, RateLimitKey, SlidingWindowState, current_time_secs};
use crate::config::AuthProtectionConfig;
use std::sync::Arc;
use tracing::{debug, warn};

/// Result of an auth rate limit check
#[derive(Debug, Clone)]
pub struct AuthRateLimitResult {
    /// Whether the request is allowed
    pub allowed: bool,
    /// Remaining attempts in the current window
    pub remaining: u32,
    /// Unix timestamp when the lockout expires (if blocked)
    pub lockout_until: Option<u64>,
    /// The endpoint type
    pub endpoint: AuthEndpoint,
}

impl AuthRateLimitResult {
    /// Create an allowed result
    pub fn allowed(remaining: u32, endpoint: AuthEndpoint) -> Self {
        Self {
            allowed: true,
            remaining,
            lockout_until: None,
            endpoint,
        }
    }

    /// Create a blocked result
    pub fn blocked(lockout_until: u64, endpoint: AuthEndpoint) -> Self {
        Self {
            allowed: false,
            remaining: 0,
            lockout_until: Some(lockout_until),
            endpoint,
        }
    }
}

/// Sliding window rate limiter for auth endpoint protection
pub struct SlidingWindowLimiter {
    storage: Arc<dyn RateLimitStorage>,
    key_prefix: String,
    /// Window size in seconds (60 for per-minute limits)
    window_size: u64,
}

impl SlidingWindowLimiter {
    /// Create a new sliding window limiter
    pub fn new(storage: Arc<dyn RateLimitStorage>, key_prefix: &str) -> Self {
        Self {
            storage,
            key_prefix: key_prefix.to_string(),
            window_size: 60, // 1 minute windows
        }
    }

    /// Check if an auth request is allowed
    ///
    /// # Arguments
    /// * `ip` - The client IP address
    /// * `endpoint` - The auth endpoint type (login/register)
    /// * `config` - Auth protection configuration
    ///
    /// # Returns
    /// An `AuthRateLimitResult` indicating if the request is allowed
    pub async fn check(
        &self,
        ip: &str,
        endpoint: AuthEndpoint,
        config: &AuthProtectionConfig,
    ) -> AuthRateLimitResult {
        if !config.enabled {
            return AuthRateLimitResult::allowed(u32::MAX, endpoint);
        }

        // Build a consistent key using RateLimitKey for the base, then add endpoint
        let key = RateLimitKey::AuthIp(ip.to_string());
        let base_key = key.to_redis_key(&self.key_prefix);
        let redis_key = format!("{}:{}", base_key, endpoint.as_str());

        // Check for existing lockout
        if let Ok(Some(lockout_until)) = self.storage.get_lockout(&redis_key).await {
            let now = current_time_secs();
            if now < lockout_until {
                debug!(
                    ip = %ip,
                    endpoint = %endpoint.as_str(),
                    lockout_until = lockout_until,
                    "Auth request blocked by lockout"
                );
                return AuthRateLimitResult::blocked(lockout_until, endpoint);
            }
        }

        // Get limits based on endpoint type
        let (limit_per_minute, limit_per_hour) = match endpoint {
            AuthEndpoint::Login => (
                config.login_attempts_per_minute,
                config.login_attempts_per_hour,
            ),
            AuthEndpoint::Register => (
                config.register_attempts_per_minute,
                config.register_attempts_per_hour,
            ),
        };

        // Check per-minute limit
        let minute_key = format!("{}:min", redis_key);
        let minute_result = self
            .check_window(&minute_key, limit_per_minute, self.window_size)
            .await;

        if !minute_result.0 {
            // Exceeded per-minute limit, apply lockout
            let lockout_until = current_time_secs() + (config.lockout_duration_minutes as u64 * 60);
            if let Err(e) = self
                .storage
                .set_lockout(
                    &redis_key,
                    lockout_until,
                    config.lockout_duration_minutes as u64 * 60,
                )
                .await
            {
                warn!("Failed to set lockout: {}", e);
            }

            debug!(
                ip = %ip,
                endpoint = %endpoint.as_str(),
                lockout_until = lockout_until,
                "Auth per-minute limit exceeded, applying lockout"
            );

            return AuthRateLimitResult::blocked(lockout_until, endpoint);
        }

        // Check per-hour limit
        let hour_key = format!("{}:hr", redis_key);
        let hour_result = self.check_window(&hour_key, limit_per_hour, 3600).await;

        if !hour_result.0 {
            // Exceeded per-hour limit, apply lockout
            let lockout_until = current_time_secs() + (config.lockout_duration_minutes as u64 * 60);
            if let Err(e) = self
                .storage
                .set_lockout(
                    &redis_key,
                    lockout_until,
                    config.lockout_duration_minutes as u64 * 60,
                )
                .await
            {
                warn!("Failed to set lockout: {}", e);
            }

            debug!(
                ip = %ip,
                endpoint = %endpoint.as_str(),
                lockout_until = lockout_until,
                "Auth per-hour limit exceeded, applying lockout"
            );

            return AuthRateLimitResult::blocked(lockout_until, endpoint);
        }

        // Increment counters
        if let Err(e) = self
            .increment_window(&minute_key, self.window_size * 2)
            .await
        {
            warn!("Failed to increment minute counter: {}", e);
        }
        if let Err(e) = self.increment_window(&hour_key, 7200).await {
            warn!("Failed to increment hour counter: {}", e);
        }

        let remaining = minute_result.1.min(hour_result.1);
        debug!(
            ip = %ip,
            endpoint = %endpoint.as_str(),
            remaining = remaining,
            "Auth rate limit check passed"
        );

        AuthRateLimitResult::allowed(remaining, endpoint)
    }

    /// Check a sliding window without incrementing
    /// Returns (allowed, remaining)
    async fn check_window(&self, key: &str, limit: u32, window_size: u64) -> (bool, u32) {
        let state = match self.storage.get_sliding_window(key).await {
            Ok(Some(state)) => state,
            Ok(None) => return (true, limit),
            Err(e) => {
                warn!("Failed to get sliding window state: {}", e);
                return (true, limit);
            }
        };

        let now = current_time_secs();
        let window_start = now - (now % window_size);

        // Calculate weighted count using sliding window
        let count = if state.window_start == window_start {
            // We're in the same window
            let elapsed_ratio = (now % window_size) as f64 / window_size as f64;
            let weighted_prev = state.previous_count as f64 * (1.0 - elapsed_ratio);
            state.current_count as f64 + weighted_prev
        } else if state.window_start + window_size == window_start {
            // Previous window became current window
            let elapsed_ratio = (now % window_size) as f64 / window_size as f64;
            
            state.current_count as f64 * (1.0 - elapsed_ratio)
        } else {
            // Windows are too old, start fresh
            0.0
        };

        let count_rounded = count.ceil() as u32;
        let remaining = limit.saturating_sub(count_rounded);
        let allowed = count_rounded < limit;

        (allowed, remaining)
    }

    /// Increment the sliding window counter
    async fn increment_window(&self, key: &str, ttl_secs: u64) -> Result<(), String> {
        let now = current_time_secs();
        let window_start = now - (now % self.window_size);

        let mut state = match self.storage.get_sliding_window(key).await {
            Ok(Some(state)) => state,
            Ok(None) => SlidingWindowState::new(),
            Err(e) => return Err(e),
        };

        if state.window_start == window_start {
            // Same window, just increment
            state.current_count += 1;
        } else if state.window_start + self.window_size == window_start {
            // Rolled over to new window
            state.previous_count = state.current_count;
            state.current_count = 1;
            state.window_start = window_start;
        } else {
            // Windows are too old, start fresh
            state = SlidingWindowState {
                current_count: 1,
                previous_count: 0,
                window_start,
            };
        }

        self.storage.set_sliding_window(key, &state, ttl_secs).await
    }

    /// Clear the rate limit state for an IP (e.g., after successful login)
    pub async fn clear(&self, ip: &str, endpoint: AuthEndpoint) {
        let key = RateLimitKey::AuthIp(ip.to_string());
        let base_key = key.to_redis_key(&self.key_prefix);
        let redis_key = format!("{}:{}", base_key, endpoint.as_str());
        let minute_key = format!("{}:min", redis_key);
        let hour_key = format!("{}:hr", redis_key);

        // Delete all related keys
        let _ = self.storage.delete(&redis_key).await;
        let _ = self.storage.delete(&minute_key).await;
        let _ = self.storage.delete(&hour_key).await;

        debug!(ip = %ip, endpoint = %endpoint.as_str(), "Cleared auth rate limit state");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_rate_limit_result_allowed() {
        let result = AuthRateLimitResult::allowed(5, AuthEndpoint::Login);
        assert!(result.allowed);
        assert_eq!(result.remaining, 5);
        assert!(result.lockout_until.is_none());
    }

    #[test]
    fn test_auth_rate_limit_result_blocked() {
        let result = AuthRateLimitResult::blocked(1234567890, AuthEndpoint::Register);
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
        assert_eq!(result.lockout_until, Some(1234567890));
    }

    #[test]
    fn test_auth_endpoint_as_str() {
        assert_eq!(AuthEndpoint::Login.as_str(), "login");
        assert_eq!(AuthEndpoint::Register.as_str(), "register");
    }
}
