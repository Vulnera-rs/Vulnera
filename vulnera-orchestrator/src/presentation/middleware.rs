//! HTTP middleware for the web server

use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Redirect, Response},
};
use chrono::Utc;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use uuid::Uuid;

use vulnera_core::application::errors::ApplicationError;
use vulnera_core::config::{RateLimitConfig, RateLimitStrategy};

use crate::presentation::models::ErrorResponse;

/// Convert ApplicationError to HTTP response
pub fn application_error_to_response(error: ApplicationError) -> Response {
    // Default to sanitizing errors; handlers can access AppState to get actual config
    // This is a fallback for errors that occur outside handler context
    let sanitize_errors = std::env::var("ENV").unwrap_or_default() == "production";

    let (status, code, message) = match error {
        ApplicationError::Domain(_) => (
            StatusCode::BAD_REQUEST,
            "DOMAIN_ERROR",
            "Invalid input provided",
        ),
        ApplicationError::RateLimited { .. } => (
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMITED",
            "Upstream rate limit exceeded. Please retry later.",
        ),
        ApplicationError::Parse(_) => (
            StatusCode::BAD_REQUEST,
            "PARSE_ERROR",
            "Failed to parse dependency file",
        ),
        ApplicationError::InvalidEcosystem { .. } => (
            StatusCode::BAD_REQUEST,
            "INVALID_ECOSYSTEM",
            "Unsupported ecosystem specified",
        ),
        ApplicationError::UnsupportedFormat { .. } => (
            StatusCode::BAD_REQUEST,
            "UNSUPPORTED_FORMAT",
            "File format not supported",
        ),
        ApplicationError::Configuration { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "CONFIGURATION_ERROR",
            if sanitize_errors {
                "Service temporarily unavailable"
            } else {
                "Service configuration error"
            },
        ),
        ApplicationError::NotFound { .. } => {
            (StatusCode::NOT_FOUND, "NOT_FOUND", "Resource not found")
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            if sanitize_errors {
                "An internal error occurred"
            } else {
                "Internal server error"
            },
        ),
    };

    // Log the concrete error with selected status and code
    tracing::error!(
        error = %error,
        http_status = %status,
        error_code = code,
        "Application error mapped to HTTP response"
    );

    let error_response = ErrorResponse {
        code: code.to_string(),
        message: message.to_string(),
        details: if sanitize_errors {
            None // Don't expose internal details in production
        } else {
            Some(serde_json::json!({ "error": error.to_string() }))
        },
        request_id: Uuid::new_v4(),
        timestamp: Utc::now(),
    };

    (status, Json(error_response)).into_response()
}

/// Security headers middleware
pub async fn security_headers_middleware(
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;

    // Add security headers
    let headers = response.headers_mut();

    // Strict-Transport-Security (HSTS)
    headers.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
    );

    // X-Frame-Options (prevent clickjacking)
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));

    // X-Content-Type-Options (prevent MIME sniffing)
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );

    // X-XSS-Protection (XSS protection)
    headers.insert(
        "x-xss-protection",
        HeaderValue::from_static("1; mode=block"),
    );

    // Referrer-Policy (control referrer information)
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // Content-Security-Policy (CSP)
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; img-src 'self' data: https:; font-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; connect-src 'self' https:; frame-ancestors 'none';"),
    );

    // Permissions-Policy (control browser features)
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), interest-cohort=()"),
    );

    response
}

/// HTTPS enforcement middleware
pub async fn https_enforcement_middleware(
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // Check if request is coming over HTTPS
    let is_https = request
        .headers()
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .map(|proto| proto == "https")
        .unwrap_or_else(|| {
            // Fallback: check the URI scheme (though this won't work behind a proxy)
            request.uri().scheme_str() == Some("https")
        });

    if !is_https {
        // Get the host header
        if let Some(host) = request.headers().get("host").and_then(|h| h.to_str().ok()) {
            let https_url = format!(
                "https://{}{}",
                host,
                request
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or("/")
            );

            // Return a redirect to HTTPS
            return Redirect::permanent(&https_url).into_response();
        }
    }

    // Continue with the request if HTTPS or if we can't determine
    next.run(request).await
}

/// Request logging middleware with timing and request ID
pub async fn logging_middleware(request: Request<axum::body::Body>, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let request_id = Uuid::new_v4();
    let start_time = Instant::now();

    tracing::info!(
        request_id = %request_id,
        method = %method,
        uri = %uri,
        "Processing request"
    );

    let response = next.run(request).await;
    let duration = start_time.elapsed();

    tracing::info!(
        request_id = %request_id,
        method = %method,
        uri = %uri,
        status = %response.status(),
        duration_ms = duration.as_millis(),
        "Request completed"
    );

    response
}

/// Middleware to scope a per-request GHSA token from headers.
/// Accepts X-GHSA-Token, X-GitHub-Token, or Authorization: Bearer|token <token>.
pub async fn ghsa_token_middleware(request: Request<axum::body::Body>, next: Next) -> Response {
    // Extract token from headers before moving the request into the next service
    let ghsa_token = {
        let headers = request.headers();
        headers
            .get("x-ghsa-token")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .or_else(|| {
                headers
                    .get("x-github-token")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
            .or_else(|| {
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| {
                        let s = s.trim();
                        if let Some(rest) = s.strip_prefix("token ") {
                            Some(rest.to_string())
                        } else {
                            s.strip_prefix("Bearer ").map(|rest| rest.to_string())
                        }
                    })
            })
    };

    if let Some(token) = ghsa_token {
        let git_token = token.clone();
        vulnera_core::infrastructure::api_clients::ghsa::with_request_ghsa_token(
            token,
            async move {
                crate::infrastructure::git::with_request_git_token(git_token, async move {
                    next.run(request).await
                })
                .await
            },
        )
        .await
    } else {
        next.run(request).await
    }
}

/// Token bucket state for rate limiting
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

/// Rate limiter state (shared across requests)
#[derive(Debug, Clone)]
pub struct RateLimiterState {
    /// Per-key token buckets (key depends on strategy: IP, API key, or "global")
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    /// Rate limit configuration
    config: RateLimitConfig,
    /// Cleanup task handle (for periodic cleanup)
    _cleanup_handle: Arc<tokio::task::JoinHandle<()>>,
}

impl RateLimiterState {
    /// Create a new rate limiter state
    pub fn new(config: RateLimitConfig) -> Self {
        let buckets = Arc::new(RwLock::new(HashMap::<String, TokenBucket>::new()));
        let buckets_clone = buckets.clone();

        // Start cleanup task to remove expired entries
        let cleanup_interval = Duration::from_secs(config.cleanup_interval_seconds);
        let cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                let mut buckets = buckets_clone.write().await;

                // Remove buckets that haven't been accessed recently (older than 1 hour)
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let expire_time = 3600; // 1 hour

                buckets.retain(|_, bucket| {
                    let elapsed = now.saturating_sub(bucket.last_refill);
                    elapsed < expire_time
                });

                if !buckets.is_empty() {
                    tracing::debug!(
                        buckets_count = buckets.len(),
                        "Rate limiter cleanup: retained buckets"
                    );
                }
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
        // Calculate refill rate per second based on requests per minute
        let refill_rate = self.config.requests_per_minute as f64 / 60.0;
        let capacity = self.config.requests_per_minute;

        let mut buckets = self.buckets.write().await;

        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(capacity, refill_rate));

        if bucket.try_consume() {
            Ok(())
        } else {
            let retry_after = bucket.retry_after();
            let limit = self.config.requests_per_minute;
            let remaining = bucket.remaining();
            Err((retry_after, limit, remaining))
        }
    }

    /// Get the rate limit key based on strategy
    fn get_key(&self, request: &Request) -> String {
        match self.config.strategy {
            RateLimitStrategy::Ip => {
                // Try to get IP from various headers (for proxied requests)
                request
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
                    .unwrap_or_else(|| "unknown-ip".to_string())
            }
            RateLimitStrategy::ApiKey => {
                // Get API key from Authorization header or X-API-Key header
                request
                    .headers()
                    .get("x-api-key")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string())
                    .or_else(|| {
                        request
                            .headers()
                            .get(axum::http::header::AUTHORIZATION)
                            .and_then(|h| h.to_str().ok())
                            .and_then(|s| {
                                s.strip_prefix("Bearer ")
                                    .or_else(|| s.strip_prefix("token "))
                                    .map(|s| s.to_string())
                            })
                    })
                    .unwrap_or_else(|| "no-api-key".to_string())
            }
            RateLimitStrategy::Global => "global".to_string(),
        }
    }
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    State(state): State<Arc<RateLimiterState>>,
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
            let headers = response.headers_mut();
            headers.insert(
                "x-ratelimit-limit",
                HeaderValue::from(state.config.requests_per_minute),
            );

            // Get current remaining tokens (approximate)
            let buckets = state.buckets.read().await;
            let remaining = buckets
                .get(&key)
                .map(|b| b.remaining())
                .unwrap_or(state.config.requests_per_minute);

            headers.insert("x-ratelimit-remaining", HeaderValue::from(remaining));

            // Reset time is current time + 1 minute
            let reset_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 60;

            let reset_time_val = reset_time.to_string();
            if let Ok(val) = HeaderValue::from_str(&reset_time_val) {
                headers.insert("x-ratelimit-reset", val);
            } else {
                headers.insert("x-ratelimit-reset", HeaderValue::from_static("0"));
            }

            response
        }
        Err((retry_after, limit, remaining)) => {
            // Rate limit exceeded
            tracing::warn!(
                key = %key,
                retry_after = retry_after,
                "Rate limit exceeded"
            );

            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(ErrorResponse {
                    code: "RATE_LIMIT_EXCEEDED".to_string(),
                    message: format!(
                        "Rate limit exceeded. Please retry after {} seconds.",
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
            headers.insert("x-ratelimit-limit", HeaderValue::from(limit));
            headers.insert("x-ratelimit-remaining", HeaderValue::from(remaining));
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
