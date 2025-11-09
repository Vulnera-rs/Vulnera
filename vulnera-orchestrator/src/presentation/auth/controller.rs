//! Authentication controller endpoints

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use chrono::{Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

use vulnera_core::application::auth::use_cases::{
    GenerateApiKeyUseCase, ListApiKeysUseCase, LoginUseCase, RefreshTokenUseCase,
    RegisterUserUseCase, RevokeApiKeyUseCase,
};
use vulnera_core::domain::auth::{
    errors::AuthError,
    value_objects::{ApiKeyId, Email},
};

use crate::presentation::auth::extractors::{Auth, AuthState};
use crate::presentation::auth::models::*;
use crate::presentation::models::ErrorResponse;

/// State for auth endpoints
#[derive(Clone)]
pub struct AuthAppState {
    pub login_use_case: Arc<LoginUseCase>,
    pub register_use_case: Arc<RegisterUserUseCase>,
    pub refresh_token_use_case: Arc<RefreshTokenUseCase>,
    pub auth_state: AuthState,
    pub token_ttl_hours: u64,
}

/// Login endpoint
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = TokenResponse),
        (status = 401, description = "Invalid credentials", body = ErrorResponse),
        (status = 422, description = "Validation error", body = ErrorResponse)
    )
)]
pub async fn login(
    State(state): State<AuthAppState>,
    axum::Json(request): axum::Json<LoginRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<ErrorResponse>)> {
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

    // Get token TTL from state
    let expires_in = state.token_ttl_hours * 3600;

    Ok(Json(TokenResponse {
        access_token: result.access_token,
        refresh_token: result.refresh_token,
        token_type: "Bearer".to_string(),
        expires_in,
    }))
}

/// Register new user endpoint
#[utoipa::path(
    post,
    path = "/api/v1/auth/register",
    tag = "auth",
    request_body = RegisterRequest,
    responses(
        (status = 200, description = "Registration successful", body = TokenResponse),
        (status = 409, description = "Email already exists", body = ErrorResponse),
        (status = 422, description = "Validation error", body = ErrorResponse)
    )
)]
pub async fn register(
    State(state): State<AuthAppState>,
    axum::Json(request): axum::Json<RegisterRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<ErrorResponse>)> {
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

    // Execute register use case
    let result = state
        .register_use_case
        .execute(email, request.password, request.roles)
        .await
        .map_err(|e| {
            let status = match e {
                AuthError::EmailAlreadyExists { .. } => StatusCode::CONFLICT,
                AuthError::WeakPassword => StatusCode::UNPROCESSABLE_ENTITY,
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

    // Get token TTL from state
    let expires_in = state.token_ttl_hours * 3600;

    Ok(Json(TokenResponse {
        access_token: result.access_token,
        refresh_token: result.refresh_token,
        token_type: "Bearer".to_string(),
        expires_in,
    }))
}

/// Refresh token endpoint
#[utoipa::path(
    post,
    path = "/api/v1/auth/refresh",
    tag = "auth",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "Token refreshed", body = TokenResponse),
        (status = 401, description = "Invalid or expired refresh token", body = ErrorResponse)
    )
)]
pub async fn refresh_token(
    State(state): State<AuthAppState>,
    axum::Json(request): axum::Json<RefreshRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let access_token = state
        .refresh_token_use_case
        .execute(&request.refresh_token)
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

    // Get token TTL from state
    let expires_in = state.token_ttl_hours * 3600;

    Ok(Json(TokenResponse {
        access_token,
        refresh_token: request.refresh_token, // Return same refresh token
        token_type: "Bearer".to_string(),
        expires_in,
    }))
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
        ("Bearer" = [])
    )
)]
pub async fn create_api_key(
    Auth { user_id: auth, .. }: Auth,
    State(state): State<AuthAppState>,
    axum::Json(request): axum::Json<CreateApiKeyRequest>,
) -> Result<Json<ApiKeyResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Get config for API key TTL
    // For now, calculate expires_at from config
    let expires_at = request.expires_at.or_else(|| {
        // Default: 1 year from now
        Some(Utc::now() + Duration::days(365))
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
        ("Bearer" = [])
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
        ("Bearer" = [])
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
