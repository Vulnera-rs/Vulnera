use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use uuid::Uuid;

use vulnera_core::config::LlmRateLimitConfig;

use crate::presentation::models::ErrorResponse;

/// Token bucket state for LLM rate limiting
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Number of tokens available
    tokens: u32,
    /// Maximum capacity of the bucket
    capacity: u32,
    /// Last refill timestamp (Unix timestamp in seconds)
    last_refill: u64,
    /// Refill rate per second (tokens per second)
    refill_rate: f64,
}

impl TokenBucket {
    fn new(capacity: u32, refill_rate: f64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            tokens: capacity,
            capacity,
            last_refill: now,
            refill_rate,
        }
    }

    /// Check if a token can be consumed, and consume it if available
    fn try_consume(&mut self) -> bool {
        self.refill();

        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    /// Get the number of tokens remaining
    fn remaining(&self) -> u32 {
        self.tokens
    }

    /// Get the time until the next token is available (in seconds)
    fn retry_after(&self) -> u64 {
        if self.tokens > 0 {
            0
        } else {
            // Calculate time until next token based on refill rate
            (1.0 / self.refill_rate).ceil() as u64
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let elapsed = now.saturating_sub(self.last_refill);
        if elapsed == 0 {
            return;
        }

        // Calculate tokens to add based on elapsed time
        let tokens_to_add = (elapsed as f64 * self.refill_rate) as u32;
        if tokens_to_add > 0 {
            self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
            self.last_refill = now;
        }
    }
}

/// LLM Rate limiter state (shared across requests)
#[derive(Debug, Clone)]
pub struct LlmRateLimiterState {
    /// Per-key token buckets
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    /// Rate limit configuration
    config: LlmRateLimitConfig,
    /// Cleanup task handle (for periodic cleanup)
    _cleanup_handle: Arc<tokio::task::JoinHandle<()>>,
}

impl LlmRateLimiterState {
    /// Create a new LLM rate limiter state
    pub fn new(config: LlmRateLimitConfig) -> Self {
        let buckets = Arc::new(RwLock::new(HashMap::<String, TokenBucket>::new()));
        let buckets_clone = buckets.clone();

        // Start cleanup task to remove expired entries
        let cleanup_interval = Duration::from_secs(3600); // Cleanup every hour
        let cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                let mut buckets = buckets_clone.write().await;

                // Remove buckets that haven't been accessed recently (older than 24 hours)
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let expire_time = 86400; // 24 hours

                buckets.retain(|_, bucket| {
                    let elapsed = now.saturating_sub(bucket.last_refill);
                    elapsed < expire_time
                });
            }
        });

        Self {
            buckets,
            config,
            _cleanup_handle: Arc::new(cleanup_handle),
        }
    }

    /// Check if a request should be rate limited
    async fn check_rate_limit(&self, key: &str) -> Result<(), (u64, u32, u32)> {
        // Determine capacity and refill rate
        // For now, we use the same limit for all users, but this could be tiered
        let capacity = self.config.requests_per_minute;
        let refill_rate = self.config.requests_per_minute as f64 / 60.0;

        let mut buckets = self.buckets.write().await;

        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(capacity, refill_rate));

        if bucket.try_consume() {
            Ok(())
        } else {
            let retry_after = bucket.retry_after();
            let limit = capacity;
            let remaining = bucket.remaining();
            Err((retry_after, limit, remaining))
        }
    }

    /// Get the rate limit key
    fn get_key(&self, request: &Request) -> String {
        // Use API key if available, otherwise IP
        request
            .headers()
            .get("x-api-key")
            .and_then(|h| h.to_str().ok())
            .map(|s| format!("apikey:{}", s))
            .or_else(|| {
                request
                    .headers()
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| {
                        s.strip_prefix("Bearer ")
                            .or_else(|| s.strip_prefix("token "))
                            .map(|s| format!("apikey:{}", s))
                    })
            })
            .unwrap_or_else(|| {
                // Fallback to IP
                let ip = request
                    .headers()
                    .get("x-forwarded-for")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.split(',').next())
                    .map(|s| s.trim().to_string())
                    .or_else(|| {
                        request
                            .headers()
                            .get("x-real-ip")
                            .and_then(|h| h.to_str().ok())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| "unknown-ip".to_string());
                format!("ip:{}", ip)
            })
    }
}

/// LLM Rate limiting middleware
pub async fn llm_rate_limit_middleware(
    State(state): State<Arc<LlmRateLimiterState>>,
    request: Request,
    next: Next,
) -> Response {
    // Check rate limit
    let key = state.get_key(&request);
    match state.check_rate_limit(&key).await {
        Ok(()) => {
            // Rate limit passed, continue with request
            let mut response = next.run(request).await;

            // Add rate limit headers to successful responses
            let limit = state.config.requests_per_minute;

            let headers = response.headers_mut();
            headers.insert("x-llm-ratelimit-limit", HeaderValue::from(limit));

            // Get current remaining tokens (approximate)
            let buckets = state.buckets.read().await;
            let remaining = buckets.get(&key).map(|b| b.remaining()).unwrap_or(limit);

            headers.insert("x-llm-ratelimit-remaining", HeaderValue::from(remaining));

            response
        }
        Err((retry_after, limit, remaining)) => {
            // Rate limit exceeded
            tracing::warn!(
                key = %key,
                retry_after = retry_after,
                "LLM Rate limit exceeded"
            );

            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(ErrorResponse {
                    code: "LLM_RATE_LIMIT_EXCEEDED".to_string(),
                    message: format!(
                        "LLM Rate limit exceeded. Please retry after {} seconds.",
                        retry_after
                    ),
                    details: Some(serde_json::json!({
                        "retry_after": retry_after,
                        "limit": limit,
                        "remaining": remaining,
                    })),
                    request_id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                }),
            )
                .into_response();

            // Add rate limit headers to error response
            let headers = response.headers_mut();
            headers.insert("x-llm-ratelimit-limit", HeaderValue::from(limit));
            headers.insert("x-llm-ratelimit-remaining", HeaderValue::from(remaining));
            let retry_after_val = retry_after.to_string();
            if let Ok(val) = HeaderValue::from_str(&retry_after_val) {
                headers.insert("retry-after", val);
            } else {
                headers.insert("retry-after", HeaderValue::from_static("60"));
            }

            response
        }
    }
}
