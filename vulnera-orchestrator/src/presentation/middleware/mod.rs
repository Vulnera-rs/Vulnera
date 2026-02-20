//! HTTP middleware for the web server

use axum::{
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Redirect, Response},
};
use chrono::Utc;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

use vulnera_core::application::errors::ApplicationError;
use vulnera_core::infrastructure::auth::CsrfService;
use vulnera_core::infrastructure::rate_limiter::{
    RateLimiterService,
    types::{AuthEndpoint, RequestCost},
};

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
        ApplicationError::Authentication(_) => (
            StatusCode::UNAUTHORIZED,
            "AUTHENTICATION_ERROR",
            "Authentication failed",
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

    // Log at appropriate level based on status code
    // 4xx = client errors (warn level), 5xx = server errors (error level)
    if status.is_server_error() {
        tracing::error!(
            error = %error,
            http_status = %status,
            error_code = code,
            "Server error mapped to HTTP response"
        );
    } else if status.is_client_error() {
        tracing::warn!(
            error = %error,
            http_status = %status,
            error_code = code,
            "Client error mapped to HTTP response"
        );
    } else {
        tracing::debug!(
            error = %error,
            http_status = %status,
            error_code = code,
            "Application error mapped to HTTP response"
        );
    }

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

/// Middleware to scope a per-request GitHub token from headers for git operations.
/// Accepts X-GHSA-Token, X-GitHub-Token, or Authorization: Bearer|token <token>.
///
/// Note: Vulnerability queries now use vulnera-advisor which configures its token at startup.
/// This middleware now only passes the token for git/repository operations.
pub async fn ghsa_token_middleware(request: Request<axum::body::Body>, next: Next) -> Response {
    // Extract token from headers before moving the request into the next service
    let git_token = {
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

    if let Some(token) = git_token {
        crate::infrastructure::git::with_request_git_token(
            token,
            async move { next.run(request).await },
        )
        .await
    } else {
        next.run(request).await
    }
}

// ============================================================================
// Rate Limiter State (wrapper around vulnera-core RateLimiterService)
// ============================================================================

/// Shared state for rate limiting middleware
#[derive(Clone)]
pub struct RateLimiterState {
    /// The rate limiter service from vulnera-core
    pub service: Arc<RateLimiterService>,
}

impl RateLimiterState {
    /// Create a new rate limiter state
    pub fn new(service: Arc<RateLimiterService>) -> Self {
        Self { service }
    }
}

impl std::fmt::Debug for RateLimiterState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiterState")
            .field("enabled", &self.service.is_enabled())
            .finish()
    }
}

/// authentication info extracted before rate limiting
/// This is a lightweight version used by rate limiter to determine tiers
#[derive(Debug, Clone)]
pub struct EarlyAuthInfo {
    pub user_id: Option<uuid::Uuid>,
    pub api_key_id: Option<uuid::Uuid>,
    pub is_org_member: bool,
}

/// State for early auth extraction middleware
#[derive(Clone)]
pub struct EarlyAuthState {
    pub validate_token: Arc<vulnera_core::application::auth::use_cases::ValidateTokenUseCase>,
    pub validate_api_key: Arc<vulnera_core::application::auth::use_cases::ValidateApiKeyUseCase>,
}

/// Early authentication middleware - runs BEFORE rate limiting to properly identify users
///
/// This extracts authentication info from cookies/API keys and stores it in request extensions
pub async fn early_auth_middleware(
    State(state): State<Arc<EarlyAuthState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let mut auth_info = EarlyAuthInfo {
        user_id: None,
        api_key_id: None,
        is_org_member: false,
    };

    // Try API key first (X-API-Key header or Authorization: ApiKey ...)
    if let Some(api_key) = extract_api_key_from_headers(request.headers()) {
        // Check if it's the master key
        if vulnera_core::infrastructure::auth::is_master_key(&api_key) {
            // Master key - use a synthetic user ID for rate limiting
            auth_info.user_id = Some(uuid::Uuid::nil()); // Nil UUID for master key
            auth_info.api_key_id = Some(uuid::Uuid::new_v4()); // Synthetic API key ID
        } else {
            // Validate regular API key
            match state.validate_api_key.execute(&api_key).await {
                Ok(result) => {
                    auth_info.user_id = Some(result.user_id.into());
                    auth_info.api_key_id = Some(result.api_key_id.into());
                }
                Err(_) => {
                    // Invalid API key - will be treated as anonymous
                    // The actual auth extractor will return 401 later
                }
            }
        }
    }
    // Try cookie auth if no API key
    else if let Some(token) = extract_access_token_from_cookies(request.headers()) {
        match state.validate_token.execute(&token) {
            Ok((user_id, _email, _roles)) => {
                auth_info.user_id = Some(user_id.into());
            }
            Err(_) => {
                // Invalid/expired token - will be treated as anonymous
                // Token refresh or re-auth will be needed
            }
        }
    }

    // Store auth info in extensions for rate limiter
    request.extensions_mut().insert(auth_info);

    next.run(request).await
}

/// Extract API key from request headers
fn extract_api_key_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    // Check X-API-Key header first
    if let Some(key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return Some(key.to_string());
    }

    // Check Authorization header with "ApiKey" scheme
    if let Some(auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        && let Some(key) = auth.strip_prefix("ApiKey ")
    {
        return Some(key.to_string());
    }

    None
}

/// Extract access token from cookies
fn extract_access_token_from_cookies(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookies = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())?;

    cookies
        .split(';')
        .map(|s| s.trim())
        .find(|s| s.starts_with("access_token="))?
        .strip_prefix("access_token=")
        .map(|s| s.to_string())
}

/// Extract IP address from request
pub fn extract_ip(request: &Request) -> String {
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

/// Determine request cost based on method and path
pub fn determine_request_cost(method: &Method, path: &str) -> RequestCost {
    // LLM endpoints have highest cost
    if path.contains("/llm") || path.contains("/explain") || path.contains("/fix") {
        return RequestCost::Llm;
    }

    // Community-focused offline-capable modules are cost-free even if triggered via API
    if path.contains("/sast") || path.contains("/secrets") || path.contains("/api-security") {
        return RequestCost::Free;
    }

    // Analysis endpoints (including dependency scanning) have standard analysis cost
    if path.contains("/analyze") || path.contains("/scan") || path.contains("/check") {
        return RequestCost::Analysis;
    }

    // Write operations have medium cost
    if matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        return RequestCost::Post;
    }

    // Read operations have lowest cost
    RequestCost::Get
}

/// Routes that should be excluded from rate limiting
const RATE_LIMIT_EXCLUDED_PATHS: &[&str] =
    &["/docs", "/api-docs", "/health", "/metrics", "/favicon.ico"];

/// Auth routes that have special brute-force protection
const AUTH_RATE_LIMIT_PATHS: &[(&str, AuthEndpoint)] = &[
    ("/api/v1/auth/login", AuthEndpoint::Login),
    ("/api/v1/auth/register", AuthEndpoint::Register),
];

/// Check if a path should be excluded from rate limiting
fn should_skip_rate_limit(path: &str) -> bool {
    RATE_LIMIT_EXCLUDED_PATHS
        .iter()
        .any(|excluded| path.starts_with(excluded))
}

/// Check if a path is an auth endpoint (for brute-force protection)
fn get_auth_endpoint(path: &str) -> Option<AuthEndpoint> {
    AUTH_RATE_LIMIT_PATHS
        .iter()
        .find(|(p, _)| path.starts_with(p))
        .map(|(_, endpoint)| *endpoint)
}

/// Add IETF standard rate limit headers to response
fn add_rate_limit_headers(response: &mut Response, limit: u32, remaining: u32, reset_at: u64) {
    let headers = response.headers_mut();

    // IETF draft standard headers
    // https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-ratelimit-headers
    headers.insert("ratelimit-limit", HeaderValue::from(limit));
    headers.insert("ratelimit-remaining", HeaderValue::from(remaining));

    if let Ok(val) = HeaderValue::from_str(&reset_at.to_string()) {
        headers.insert("ratelimit-reset", val);
    }
}

/// Rate limiting middleware
///
/// Uses the unified rate limiter from vulnera-core with:
/// - Token bucket algorithm for general API rate limiting
/// - Tiered limits based on authentication (API Key > Cookie Auth > Anonymous)
/// - IETF standard rate limit headers
pub async fn rate_limit_middleware(
    State(state): State<Arc<RateLimiterState>>,
    request: Request,
    next: Next,
) -> Response {
    // Skip rate limiting if disabled
    if !state.service.is_enabled() {
        return next.run(request).await;
    }

    let path = request.uri().path().to_string();
    let method = request.method().clone();

    // Skip rate limiting for excluded paths (docs, health checks, static assets)
    if should_skip_rate_limit(&path) {
        return next.run(request).await;
    }

    // Extract request metadata
    let ip = extract_ip(&request);

    // Get authentication info from request extensions populated by early_auth_middleware
    let (user_id, api_key_id, is_org_member) = extract_auth_info(&request);

    // Determine request cost
    let cost = determine_request_cost(&method, &path);

    // Check rate limit
    let result = state
        .service
        .check_api_limit(&ip, user_id, api_key_id, is_org_member, cost)
        .await;

    if result.allowed {
        // Rate limit passed, continue with request
        let mut response = next.run(request).await;

        // Add rate limit headers
        add_rate_limit_headers(
            &mut response,
            result.limit,
            result.remaining,
            result.reset_at,
        );

        response
    } else {
        // Rate limit exceeded
        let retry_after = result.retry_after.unwrap_or(60);

        tracing::warn!(
            ip = %ip,
            tier = %result.tier,
            retry_after = retry_after,
            "Rate limit exceeded"
        );

        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                code: "RATE_LIMIT_EXCEEDED".to_string(),
                message: format!(
                    "Rate limit exceeded. Please retry after {} seconds.",
                    retry_after
                ),
                details: Some(serde_json::json!({
                    "retry_after": retry_after,
                    "limit": result.limit,
                    "remaining": result.remaining,
                    "tier": result.tier.as_str(),
                })),
                request_id: Uuid::new_v4(),
                timestamp: Utc::now(),
            }),
        )
            .into_response();

        // Add rate limit headers
        add_rate_limit_headers(&mut response, result.limit, 0, result.reset_at);

        // Add Retry-After header
        if let Ok(val) = HeaderValue::from_str(&retry_after.to_string()) {
            response.headers_mut().insert("retry-after", val);
        }

        response
    }
}

/// Auth rate limiting middleware for brute-force protection
///
/// Uses sliding window counter algorithm for stricter rate limiting
/// on authentication endpoints (login/register).
pub async fn auth_rate_limit_middleware(
    State(state): State<Arc<RateLimiterState>>,
    request: Request,
    next: Next,
) -> Response {
    // Skip if rate limiting is disabled
    if !state.service.is_enabled() {
        return next.run(request).await;
    }

    let path = request.uri().path();

    // Check if this is an auth endpoint
    let endpoint = match get_auth_endpoint(path) {
        Some(e) => e,
        None => return next.run(request).await,
    };

    let ip = extract_ip(&request);

    // Check auth rate limit
    let result = state.service.check_auth_limit(&ip, endpoint).await;

    if result.allowed {
        // Rate limit passed, continue with request
        next.run(request).await
    } else {
        // Rate limit exceeded (brute-force protection triggered)
        let lockout_until = result.lockout_until.unwrap_or(0);
        let retry_after = lockout_until.saturating_sub(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );

        tracing::warn!(
            ip = %ip,
            endpoint = %endpoint.as_str(),
            lockout_until = lockout_until,
            "Auth rate limit exceeded (brute-force protection)"
        );

        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                code: "AUTH_RATE_LIMIT_EXCEEDED".to_string(),
                message: format!(
                    "Too many {} attempts. Please try again later.",
                    endpoint.as_str()
                ),
                details: Some(serde_json::json!({
                    "retry_after": retry_after,
                    "lockout_until": lockout_until,
                    "endpoint": endpoint.as_str(),
                })),
                request_id: Uuid::new_v4(),
                timestamp: Utc::now(),
            }),
        )
            .into_response();

        // Add Retry-After header
        if let Ok(val) = HeaderValue::from_str(&retry_after.to_string()) {
            response.headers_mut().insert("retry-after", val);
        }

        response
    }
}

/// Extract authentication info from request extensions
/// Returns (user_id, api_key_id, is_org_member)
fn extract_auth_info(request: &Request) -> (Option<Uuid>, Option<Uuid>, bool) {
    // EarlyAuthInfo is set by early_auth_middleware before rate limiting.
    if let Some(early_auth) = request.extensions().get::<EarlyAuthInfo>()
        && early_auth.user_id.is_some()
    {
        return (
            early_auth.user_id,
            early_auth.api_key_id,
            early_auth.is_org_member,
        );
    }

    // Anonymous user
    (None, None, false)
}

/// State for CSRF validation middleware
#[derive(Debug, Clone)]
pub struct CsrfMiddlewareState {
    /// CSRF service for token validation
    pub csrf_service: Arc<CsrfService>,
}

impl CsrfMiddlewareState {
    pub fn new(csrf_service: Arc<CsrfService>) -> Self {
        Self { csrf_service }
    }
}

/// CSRF validation middleware
///
/// Validates CSRF tokens for state-changing requests (POST, PUT, PATCH, DELETE).
/// The CSRF token must be provided in the `X-CSRF-Token` header and must match
/// the token stored in the `csrf_token` cookie (set during authentication).
///
/// Safe methods (GET, HEAD, OPTIONS, TRACE) are allowed without CSRF validation.
/// Requests with `X-API-Key` header bypass CSRF (programmatic API access).
pub async fn csrf_validation_middleware(
    State(state): State<Arc<CsrfMiddlewareState>>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();

    // Safe methods don't need CSRF validation
    if matches!(
        method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    ) {
        return next.run(request).await;
    }

    // API key requests bypass CSRF (programmatic access)
    if request.headers().contains_key("x-api-key") {
        return next.run(request).await;
    }

    // Extract CSRF token from header
    let header_token = request
        .headers()
        .get("x-csrf-token")
        .and_then(|h| h.to_str().ok());

    // Extract CSRF token from cookie
    let cookie_token = extract_cookie(&request, "csrf_token");

    // Validate both tokens are present
    let (header_token, cookie_token) = match (header_token, cookie_token) {
        (Some(h), Some(c)) => (h.to_string(), c),
        (None, _) => {
            tracing::warn!(
                method = %method,
                uri = %request.uri(),
                "CSRF validation failed: missing X-CSRF-Token header"
            );
            return csrf_error_response("Missing CSRF token in X-CSRF-Token header");
        }
        (_, None) => {
            tracing::warn!(
                method = %method,
                uri = %request.uri(),
                "CSRF validation failed: missing csrf_token cookie"
            );
            return csrf_error_response("Missing CSRF token cookie");
        }
    };

    // Validate that header token matches cookie token (using constant-time comparison)
    if !state
        .csrf_service
        .validate_token(&header_token, &cookie_token)
    {
        tracing::warn!(
            method = %method,
            uri = %request.uri(),
            "CSRF validation failed: token mismatch"
        );
        return csrf_error_response("Invalid CSRF token");
    }

    // CSRF validation passed, continue with request
    next.run(request).await
}

/// Extract a cookie value from the request
fn extract_cookie(request: &Request, name: &str) -> Option<String> {
    request
        .headers()
        .get(axum::http::header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let cookie = cookie.trim();
                cookie
                    .strip_prefix(&format!("{}=", name))
                    .map(|value| value.to_string())
            })
        })
}

/// Generate a 403 Forbidden response for CSRF validation failures
fn csrf_error_response(message: &str) -> Response {
    let error_response = ErrorResponse {
        code: "CSRF_VALIDATION_FAILED".to_string(),
        message: message.to_string(),
        details: None,
        request_id: Uuid::new_v4(),
        timestamp: Utc::now(),
    };

    (StatusCode::FORBIDDEN, Json(error_response)).into_response()
}
