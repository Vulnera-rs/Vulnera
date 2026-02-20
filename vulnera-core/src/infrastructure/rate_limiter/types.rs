//! Rate limiter types and core data structures

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Authentication tier for rate limiting
/// Determines which rate limit bucket applies to a request
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthTier {
    /// API key authentication (CLI/Extensions) - highest limits
    ApiKey,
    /// Cookie-based authentication (web users) - medium limits
    Authenticated,
    /// Unauthenticated users - lowest limits
    Anonymous,
}

impl AuthTier {
    /// Get the tier name for logging and metrics
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthTier::ApiKey => "api_key",
            AuthTier::Authenticated => "authenticated",
            AuthTier::Anonymous => "anonymous",
        }
    }
}

impl std::fmt::Display for AuthTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Key used to identify rate limit buckets
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RateLimitKey {
    /// Rate limit by IP address
    Ip(String),
    /// Rate limit by user ID
    UserId(Uuid),
    /// Rate limit by API key ID
    ApiKeyId(Uuid),
    /// Rate limit by IP for auth endpoints (login/register)
    AuthIp(String),
}

impl RateLimitKey {
    /// Convert to a Redis-compatible key string
    pub fn to_redis_key(&self, prefix: &str) -> String {
        match self {
            RateLimitKey::Ip(ip) => format!("{}:ip:{}", prefix, ip),
            RateLimitKey::UserId(id) => format!("{}:user:{}", prefix, id),
            RateLimitKey::ApiKeyId(id) => format!("{}:apikey:{}", prefix, id),
            RateLimitKey::AuthIp(ip) => format!("{}:auth:{}", prefix, ip),
        }
    }
}

/// Result of a rate limit check
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    /// Whether the request is allowed
    pub allowed: bool,
    /// Maximum requests allowed in the current window
    pub limit: u32,
    /// Remaining requests in the current window
    pub remaining: u32,
    /// Unix timestamp when the rate limit resets
    pub reset_at: u64,
    /// Retry-After duration in seconds (only set when blocked)
    pub retry_after: Option<u64>,
    /// The tier that was applied
    pub tier: AuthTier,
}

impl RateLimitResult {
    /// Create a new allowed result
    pub fn allowed(limit: u32, remaining: u32, reset_at: u64, tier: AuthTier) -> Self {
        Self {
            allowed: true,
            limit,
            remaining,
            reset_at,
            retry_after: None,
            tier,
        }
    }

    /// Create a new blocked result
    pub fn blocked(limit: u32, reset_at: u64, retry_after: u64, tier: AuthTier) -> Self {
        Self {
            allowed: false,
            limit,
            remaining: 0,
            reset_at,
            retry_after: Some(retry_after),
            tier,
        }
    }
}

/// Token bucket state for a single key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBucketState {
    /// Current number of tokens in the bucket
    pub tokens: f64,
    /// Last time the bucket was refilled (Unix timestamp in milliseconds)
    pub last_refill: u64,
}

impl TokenBucketState {
    /// Create a new token bucket with full tokens
    pub fn new(max_tokens: u32) -> Self {
        Self {
            tokens: max_tokens as f64,
            last_refill: current_time_millis(),
        }
    }
}

/// Sliding window counter state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlidingWindowState {
    /// Count in the current window
    pub current_count: u32,
    /// Count in the previous window
    pub previous_count: u32,
    /// Start time of the current window (Unix timestamp in seconds)
    pub window_start: u64,
}

impl SlidingWindowState {
    /// Create a new sliding window state
    pub fn new() -> Self {
        Self {
            current_count: 0,
            previous_count: 0,
            window_start: current_time_secs(),
        }
    }
}

impl Default for SlidingWindowState {
    fn default() -> Self {
        Self::new()
    }
}

/// Request cost weights for different operation types
#[derive(Debug, Clone, Copy)]
pub enum RequestCost {
    /// Standard GET request
    Get,
    /// POST/PUT/DELETE request
    Post,
    /// Analysis operation (dependency scan, SAST, etc.)
    Analysis,
    /// LLM operation (explanations, code fixes)
    Llm,
    /// Zero cost operation (SAST, Secrets, API security)
    Free,
    /// Custom cost
    Custom(u32),
}

impl RequestCost {
    /// Get the cost value based on config
    pub fn value(&self, config: &crate::config::RequestCostsConfig) -> u32 {
        match self {
            RequestCost::Get => config.get,
            RequestCost::Post => config.post,
            RequestCost::Analysis => config.analysis,
            RequestCost::Llm => config.llm,
            RequestCost::Free => config.free,
            RequestCost::Custom(cost) => *cost,
        }
    }
}

/// Auth endpoint type for brute-force protection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthEndpoint {
    Login,
    Register,
}

impl AuthEndpoint {
    /// Get the endpoint name for logging
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthEndpoint::Login => "login",
            AuthEndpoint::Register => "register",
        }
    }
}

/// Get current time in milliseconds since Unix epoch
pub fn current_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

/// Get current time in seconds since Unix epoch
pub fn current_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_tier_display() {
        assert_eq!(AuthTier::ApiKey.as_str(), "api_key");
        assert_eq!(AuthTier::Authenticated.as_str(), "authenticated");
        assert_eq!(AuthTier::Anonymous.as_str(), "anonymous");
    }

    #[test]
    fn test_rate_limit_key_to_redis() {
        let ip_key = RateLimitKey::Ip("192.168.1.1".to_string());
        assert_eq!(ip_key.to_redis_key("ratelimit"), "ratelimit:ip:192.168.1.1");

        let user_id = Uuid::new_v4();
        let user_key = RateLimitKey::UserId(user_id);
        assert_eq!(
            user_key.to_redis_key("ratelimit"),
            format!("ratelimit:user:{}", user_id)
        );
    }

    #[test]
    fn test_rate_limit_result_allowed() {
        let result = RateLimitResult::allowed(100, 50, 1234567890, AuthTier::ApiKey);
        assert!(result.allowed);
        assert_eq!(result.limit, 100);
        assert_eq!(result.remaining, 50);
        assert!(result.retry_after.is_none());
    }

    #[test]
    fn test_rate_limit_result_blocked() {
        let result = RateLimitResult::blocked(100, 1234567890, 60, AuthTier::Anonymous);
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
        assert_eq!(result.retry_after, Some(60));
    }
}
