//! Authentication controller endpoints with HttpOnly cookie-based authentication

use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Json, Response},
};
use chrono::{Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

use vulnera_core::application::auth::use_cases::{
    GenerateApiKeyUseCase, ListApiKeysUseCase, LoginUseCase, RefreshTokenUseCase,
    RegisterUserUseCase, RevokeApiKeyUseCase, ValidateTokenUseCase,
};
use vulnera_core::config::CookieSameSite;
use vulnera_core::domain::auth::{
    errors::AuthError,
    value_objects::{ApiKeyId, Email},
};
use vulnera_core::infrastructure::auth::{CsrfService, TokenBlacklistService};

use crate::presentation::auth::extractors::{Auth, AuthState};
use crate::presentation::auth::models::*;
use crate::presentation::models::ErrorResponse;

/// State for auth endpoints
#[derive(Clone)]
pub struct AuthAppState {
    pub login_use_case: Arc<LoginUseCase>,
    pub register_use_case: Arc<RegisterUserUseCase>,
    pub refresh_token_use_case: Arc<RefreshTokenUseCase>,
    pub validate_token_use_case: Arc<ValidateTokenUseCase>,
    pub auth_state: AuthState,
    pub csrf_service: Arc<CsrfService>,
    pub token_ttl_hours: u64,
    pub refresh_token_ttl_hours: u64,
    pub api_key_ttl_days: Option<u64>,
    // Token blacklist for logout
    pub token_blacklist: Option<Arc<dyn TokenBlacklistService>>,
    pub blacklist_tokens_on_logout: bool,
    // Cookie configuration
    pub cookie_domain: Option<String>,
    pub cookie_secure: bool,
    pub cookie_same_site: CookieSameSite,
    pub cookie_path: String,
    pub refresh_cookie_path: String,
}

impl AuthAppState {
    /// Build a Set-Cookie header value for the access token
    fn build_access_token_cookie(&self, token: &str, max_age_secs: i64) -> String {
        let mut cookie = format!(
            "access_token={}; HttpOnly; Path={}; Max-Age={}; SameSite={}",
            token,
            self.cookie_path,
            max_age_secs,
            self.cookie_same_site.as_str()
        );

        if self.cookie_secure {
            cookie.push_str("; Secure");
        }

        if let Some(ref domain) = self.cookie_domain {
            cookie.push_str(&format!("; Domain={}", domain));
        }

        cookie
    }

    /// Build a Set-Cookie header value for the refresh token
    fn build_refresh_token_cookie(&self, token: &str, max_age_secs: i64) -> String {
        // Refresh token uses Strict SameSite for extra security
        let mut cookie = format!(
            "refresh_token={}; HttpOnly; Path={}; Max-Age={}; SameSite=Strict",
            token, self.refresh_cookie_path, max_age_secs
        );

        if self.cookie_secure {
            cookie.push_str("; Secure");
        }

        if let Some(ref domain) = self.cookie_domain {
            cookie.push_str(&format!("; Domain={}", domain));
        }

        cookie
    }

    /// Build a Set-Cookie header value for the CSRF token (NOT HttpOnly - must be readable by JS)
    fn build_csrf_cookie(&self, token: &str, max_age_secs: i64) -> String {
        let mut cookie = format!(
            "csrf_token={}; Path={}; Max-Age={}; SameSite={}",
            token,
            self.cookie_path,
            max_age_secs,
            self.cookie_same_site.as_str()
        );

        if self.cookie_secure {
            cookie.push_str("; Secure");
        }

        if let Some(ref domain) = self.cookie_domain {
            cookie.push_str(&format!("; Domain={}", domain));
        }

        cookie
    }

    /// Build Set-Cookie headers to clear all auth cookies (for logout)
    fn build_clear_cookies(&self) -> Vec<String> {
        vec![
            // Clear access token
            format!(
                "access_token=; HttpOnly; Path={}; Max-Age=0; SameSite={}{}{}",
                self.cookie_path,
                self.cookie_same_site.as_str(),
                if self.cookie_secure { "; Secure" } else { "" },
                self.cookie_domain
                    .as_ref()
                    .map(|d| format!("; Domain={}", d))
                    .unwrap_or_default()
            ),
            // Clear refresh token
            format!(
                "refresh_token=; HttpOnly; Path={}; Max-Age=0; SameSite=Strict{}{}",
                self.refresh_cookie_path,
                if self.cookie_secure { "; Secure" } else { "" },
                self.cookie_domain
                    .as_ref()
                    .map(|d| format!("; Domain={}", d))
                    .unwrap_or_default()
            ),
            // Clear CSRF token
            format!(
                "csrf_token=; Path={}; Max-Age=0; SameSite={}{}{}",
                self.cookie_path,
                self.cookie_same_site.as_str(),
                if self.cookie_secure { "; Secure" } else { "" },
                self.cookie_domain
                    .as_ref()
                    .map(|d| format!("; Domain={}", d))
                    .unwrap_or_default()
            ),
        ]
    }
}

/// Helper function to extract a cookie value from headers
pub fn extract_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(|s| s.trim())
        .find(|s| s.starts_with(&format!("{}=", cookie_name)))?
        .strip_prefix(&format!("{}=", cookie_name))
        .map(|s| s.to_string())
}

fn internal_cookie_error(message: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            code: "COOKIE_HEADER_BUILD_FAILED".to_string(),
            message: message.into(),
            details: None,
            request_id: Uuid::new_v4(),
            timestamp: Utc::now(),
        }),
    )
}

fn cookie_header_value(cookie: String) -> Result<HeaderValue, (StatusCode, Json<ErrorResponse>)> {
    HeaderValue::from_str(&cookie)
        .map_err(|e| internal_cookie_error(format!("Invalid Set-Cookie header value: {}", e)))
}

/// Login endpoint - sets HttpOnly cookies for tokens
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful - tokens set as HttpOnly cookies", body = AuthResponse),
        (status = 401, description = "Invalid credentials", body = ErrorResponse),
        (status = 422, description = "Validation error", body = ErrorResponse)
    )
)]
pub async fn login(
    State(state): State<AuthAppState>,
    axum::Json(request): axum::Json<LoginRequest>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    // Validate email
    let email = Email::new(request.email).map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ErrorResponse {
                code: "INVALID_EMAIL".to_string(),
                message: e,
                details: None,
                request_id: Uuid::new_v4(),
                timestamp: Utc::now(),
            }),
        )
    })?;

    // Execute login use case
    let result = state
        .login_use_case
        .execute(email, request.password)
        .await
        .map_err(|e| {
            let status = match e {
                AuthError::InvalidCredentials => StatusCode::UNAUTHORIZED,
                AuthError::InvalidEmail { .. } => StatusCode::UNPROCESSABLE_ENTITY,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };

            (
                status,
                Json(ErrorResponse {
                    code: "LOGIN_FAILED".to_string(),
                    message: format!("{}", e),
                    details: None,
                    request_id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                }),
            )
        })?;

    // Calculate cookie expiration times
    let access_token_max_age = (state.token_ttl_hours * 3600) as i64;
    let refresh_token_max_age = (state.token_ttl_hours * 30 * 3600) as i64; // 30x access token TTL

    // Generate CSRF token
    let csrf_token = state.csrf_service.generate_token();

    // Build response with cookies
    let mut headers = HeaderMap::new();

    headers.insert(
        header::SET_COOKIE,
        cookie_header_value(
            state.build_access_token_cookie(&result.access_token, access_token_max_age),
        )?,
    );

    headers.append(
        header::SET_COOKIE,
        cookie_header_value(
            state.build_refresh_token_cookie(&result.refresh_token, refresh_token_max_age),
        )?,
    );

    headers.append(
        header::SET_COOKIE,
        cookie_header_value(state.build_csrf_cookie(&csrf_token, access_token_max_age))?,
    );

    let body = AuthResponse {
        csrf_token,
        expires_in: state.token_ttl_hours * 3600,
        user_id: result.user_id.as_uuid(),
        email: result.email.as_str().to_string(),
        roles: result.roles.iter().map(|r| r.to_string()).collect(),
    };

    Ok((StatusCode::OK, headers, Json(body)).into_response())
}

/// Register new user endpoint - sets HttpOnly cookies for tokens
#[utoipa::path(
    post,
    path = "/api/v1/auth/register",
    tag = "auth",
    request_body = RegisterRequest,
    responses(
        (status = 200, description = "Registration successful - tokens set as HttpOnly cookies", body = AuthResponse),
        (status = 409, description = "Email already exists", body = ErrorResponse),
        (status = 422, description = "Validation error", body = ErrorResponse)
    )
)]
pub async fn register(
    State(state): State<AuthAppState>,
    axum::Json(request): axum::Json<RegisterRequest>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    // Validate email
    let email = Email::new(request.email.clone()).map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ErrorResponse {
                code: "INVALID_EMAIL".to_string(),
                message: e,
                details: None,
                request_id: Uuid::new_v4(),
                timestamp: Utc::now(),
            }),
        )
    })?;

    // Execute register use case
    let result = state
        .register_use_case
        .execute(email.clone(), request.password, request.roles.clone())
        .await
        .map_err(|e| {
            let status = match e {
                AuthError::EmailAlreadyExists { .. } => StatusCode::CONFLICT,
                AuthError::WeakPassword | AuthError::PasswordRequirementsNotMet { .. } => {
                    StatusCode::UNPROCESSABLE_ENTITY
                }
                AuthError::InvalidEmail { .. } => StatusCode::UNPROCESSABLE_ENTITY,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };

            (
                status,
                Json(ErrorResponse {
                    code: "REGISTRATION_FAILED".to_string(),
                    message: format!("{}", e),
                    details: None,
                    request_id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                }),
            )
        })?;

    // Calculate cookie expiration times
    let access_token_max_age = (state.token_ttl_hours * 3600) as i64;
    let refresh_token_max_age = (state.token_ttl_hours * 30 * 3600) as i64;

    // Generate CSRF token
    let csrf_token = state.csrf_service.generate_token();

    // Build response with cookies
    let mut headers = HeaderMap::new();

    headers.insert(
        header::SET_COOKIE,
        cookie_header_value(
            state.build_access_token_cookie(&result.access_token, access_token_max_age),
        )?,
    );

    headers.append(
        header::SET_COOKIE,
        cookie_header_value(
            state.build_refresh_token_cookie(&result.refresh_token, refresh_token_max_age),
        )?,
    );

    headers.append(
        header::SET_COOKIE,
        cookie_header_value(state.build_csrf_cookie(&csrf_token, access_token_max_age))?,
    );

    // Get roles for response
    let roles = request
        .roles
        .unwrap_or_else(|| vec![vulnera_core::domain::auth::value_objects::UserRole::User]);

    let body = AuthResponse {
        csrf_token,
        expires_in: state.token_ttl_hours * 3600,
        user_id: result.user_id.as_uuid(),
        email: email.as_str().to_string(),
        roles: roles.iter().map(|r| r.to_string()).collect(),
    };

    Ok((StatusCode::OK, headers, Json(body)).into_response())
}

/// Refresh token endpoint - reads refresh token from cookie, sets new access token cookie
#[utoipa::path(
    post,
    path = "/api/v1/auth/refresh",
    tag = "auth",
    responses(
        (status = 200, description = "Token refreshed - new access token set as HttpOnly cookie", body = RefreshResponse),
        (status = 401, description = "Invalid or expired refresh token", body = ErrorResponse)
    )
)]
pub async fn refresh_token(
    State(state): State<AuthAppState>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    // Extract refresh token from cookie
    let refresh_token_value = extract_cookie(&headers, "refresh_token").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                code: "REFRESH_FAILED".to_string(),
                message: "No refresh token provided".to_string(),
                details: None,
                request_id: Uuid::new_v4(),
                timestamp: Utc::now(),
            }),
        )
    })?;

    // Execute refresh use case with rotation (blacklists old refresh token, issues new one)
    let result = state
        .refresh_token_use_case
        .execute_with_rotation(&refresh_token_value)
        .await
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    code: "REFRESH_FAILED".to_string(),
                    message: format!("{}", e),
                    details: None,
                    request_id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                }),
            )
        })?;

    // Calculate cookie expiration times
    let access_token_max_age = (state.token_ttl_hours * 3600) as i64;
    let refresh_token_max_age = (state.refresh_token_ttl_hours * 3600) as i64;

    // Generate new CSRF token
    let csrf_token = state.csrf_service.generate_token();

    // Build response with new cookies (both access and rotated refresh token)
    let mut response_headers = HeaderMap::new();

    response_headers.insert(
        header::SET_COOKIE,
        cookie_header_value(
            state.build_access_token_cookie(&result.access_token, access_token_max_age),
        )?,
    );

    // Set rotated refresh token cookie
    response_headers.append(
        header::SET_COOKIE,
        cookie_header_value(
            state.build_refresh_token_cookie(&result.refresh_token, refresh_token_max_age),
        )?,
    );

    response_headers.append(
        header::SET_COOKIE,
        cookie_header_value(state.build_csrf_cookie(&csrf_token, access_token_max_age))?,
    );

    let body = RefreshResponse {
        csrf_token,
        expires_in: state.token_ttl_hours * 3600,
    };

    Ok((StatusCode::OK, response_headers, Json(body)).into_response())
}

/// Logout endpoint - clears auth cookies and optionally blacklists tokens
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "auth",
    responses(
        (status = 200, description = "Successfully logged out", body = LogoutResponse)
    )
)]
pub async fn logout(
    State(state): State<AuthAppState>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    // If blacklist is enabled, revoke all user tokens
    if state.blacklist_tokens_on_logout
        && let Some(ref blacklist) = state.token_blacklist
    {
        // Try to extract user from the access token cookie
        if let Some(access_token) = extract_cookie(&headers, "access_token") {
            // Get the user ID from the token (even if expired, we can still extract claims)
            if let Ok(claims) = state.validate_token_use_case.get_claims(&access_token)
                && let Ok(user_id) = claims.user_id()
            {
                // Revoke all tokens for this user
                // TTL should match the refresh token TTL to ensure all tokens are invalidated
                let ttl = std::time::Duration::from_secs(state.refresh_token_ttl_hours * 3600);

                if let Err(e) = blacklist.revoke_all_user_tokens(&user_id, ttl).await {
                    tracing::warn!(
                        user_id = %user_id,
                        error = %e,
                        "Failed to revoke user tokens on logout"
                    );
                    // Don't fail the logout - cookie clearing will still work
                } else {
                    tracing::info!(user_id = %user_id, "User tokens revoked on logout");
                }
            }
        }
    }

    // Build response with cleared cookies
    let mut response_headers = HeaderMap::new();

    for cookie in state.build_clear_cookies() {
        response_headers.append(header::SET_COOKIE, cookie_header_value(cookie)?);
    }

    let body = LogoutResponse {
        message: "Successfully logged out".to_string(),
    };

    Ok((StatusCode::OK, response_headers, Json(body)).into_response())
}

/// Create API key endpoint
#[utoipa::path(
    post,
    path = "/api/v1/auth/api-keys",
    tag = "auth",
    request_body = CreateApiKeyRequest,
    responses(
        (status = 200, description = "API key created", body = ApiKeyResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 422, description = "Validation error", body = ErrorResponse)
    ),
    security(
        ("CookieAuth" = [])
    )
)]
pub async fn create_api_key(
    Auth { user_id: auth, .. }: Auth,
    State(state): State<AuthAppState>,
    axum::Json(request): axum::Json<CreateApiKeyRequest>,
) -> Result<Json<ApiKeyResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Compute default API key expiration from configured auth policy
    let expires_at = request.expires_at.or_else(|| {
        state
            .api_key_ttl_days
            .map(|days| Utc::now() + Duration::days(days as i64))
    });

    // Get dependencies from state
    let api_key_repo = state.auth_state.api_key_repository.clone();
    let api_key_gen = state.auth_state.api_key_generator.clone();

    // Create generate use case
    let generate_use_case = GenerateApiKeyUseCase::new(api_key_repo, api_key_gen, auth);

    let (plaintext_key, api_key) = generate_use_case
        .execute(
            request.name.unwrap_or_else(|| "API Key".to_string()),
            expires_at,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    code: "API_KEY_CREATION_FAILED".to_string(),
                    message: format!("{}", e),
                    details: None,
                    request_id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                }),
            )
        })?;

    Ok(Json(ApiKeyResponse {
        id: api_key.api_key_id.as_uuid(),
        name: api_key.name,
        key: Some(plaintext_key), // Only shown once
        created_at: api_key.created_at,
        expires_at: api_key.expires_at,
    }))
}

/// List API keys endpoint
#[utoipa::path(
    get,
    path = "/api/v1/auth/api-keys",
    tag = "auth",
    responses(
        (status = 200, description = "List of API keys", body = ApiKeyListResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    security(
        ("CookieAuth" = [])
    )
)]
pub async fn list_api_keys(
    Auth { user_id: auth, .. }: Auth,
    State(state): State<AuthAppState>,
) -> Result<Json<ApiKeyListResponse>, (StatusCode, Json<ErrorResponse>)> {
    let api_key_repo = state.auth_state.api_key_repository.clone();

    let list_use_case = ListApiKeysUseCase::new(api_key_repo, auth);

    let api_keys = list_use_case.execute().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                code: "API_KEY_LIST_FAILED".to_string(),
                message: format!("{}", e),
                details: None,
                request_id: Uuid::new_v4(),
                timestamp: Utc::now(),
            }),
        )
    })?;

    // Convert to DTOs with masked keys
    let api_key_items = api_keys
        .into_iter()
        .map(|api_key| {
            // Note: We cannot use ApiKeyGenerator.mask_key() here because we only have
            // the key_hash stored in the database, not the plaintext key. The plaintext
            // key is only available once during creation and is never stored for security.
            // Instead, we create a consistent masked display using the key ID.
            let masked_key = format!("vuln_****...{}", &api_key.api_key_id.as_str()[..8]);

            ApiKeyListItem {
                id: api_key.api_key_id.as_uuid(),
                name: api_key.name,
                masked_key,
                created_at: api_key.created_at,
                last_used_at: api_key.last_used_at,
                expires_at: api_key.expires_at,
            }
        })
        .collect();

    Ok(Json(ApiKeyListResponse {
        api_keys: api_key_items,
    }))
}

/// Revoke API key endpoint
#[utoipa::path(
    delete,
    path = "/api/v1/auth/api-keys/{key_id}",
    tag = "auth",
    params(
        ("key_id" = Uuid, Path, description = "API key ID")
    ),
    responses(
        (status = 204, description = "API key revoked"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 404, description = "API key not found", body = ErrorResponse)
    ),
    security(
        ("CookieAuth" = [])
    )
)]
pub async fn revoke_api_key(
    Auth { user_id: auth, .. }: Auth,
    Path(key_id): Path<Uuid>,
    State(state): State<AuthAppState>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let api_key_id = ApiKeyId::from(key_id);

    let api_key_repo = state.auth_state.api_key_repository.clone();

    let revoke_use_case = RevokeApiKeyUseCase::new(api_key_repo, auth);

    revoke_use_case.execute(api_key_id).await.map_err(|e| {
        let status = match e {
            AuthError::ApiKeyNotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (
            status,
            Json(ErrorResponse {
                code: "API_KEY_REVOKE_FAILED".to_string(),
                message: format!("{}", e),
                details: None,
                request_id: Uuid::new_v4(),
                timestamp: Utc::now(),
            }),
        )
    })?;

    Ok(StatusCode::NO_CONTENT)
}
