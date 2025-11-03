//! Authentication extractors for Axum

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::application::auth::use_cases::{ValidateApiKeyUseCase, ValidateTokenUseCase};
use crate::application::errors::ApplicationError;
use crate::domain::auth::value_objects::{Email, UserId, UserRole};

/// Authenticated user information from JWT token
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: UserId,
    pub email: Email,
    pub roles: Vec<UserRole>,
}

/// Authenticated user information from API key
#[derive(Debug, Clone)]
pub struct ApiKeyAuth {
    pub user_id: UserId,
    pub email: Email,
    pub api_key_id: crate::domain::auth::value_objects::ApiKeyId,
}

/// Authentication method used
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Jwt,
    ApiKey,
}

/// Generic authentication extractor that accepts either JWT or API key
#[derive(Debug, Clone)]
pub struct Auth {
    pub user_id: UserId,
    pub email: Email,
    pub roles: Vec<UserRole>,
    pub auth_method: AuthMethod,
}

/// State for authentication extractors
#[derive(Clone)]
pub struct AuthState {
    pub validate_token: Arc<ValidateTokenUseCase>,
    pub validate_api_key: Arc<ValidateApiKeyUseCase>,
    pub user_repository: Arc<dyn crate::domain::auth::repositories::IUserRepository>,
    pub api_key_repository: Arc<dyn crate::domain::auth::repositories::IApiKeyRepository>,
    pub api_key_generator: Arc<crate::infrastructure::auth::ApiKeyGenerator>,
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AuthErrorResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Get AuthState from extensions
        let auth_state = parts
            .extensions
            .get::<AuthState>()
            .ok_or_else(|| AuthErrorResponse {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                error: ApplicationError::Configuration {
                    message: "Auth state not found in request extensions".to_string(),
                },
            })?;

        // Extract Authorization header
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| AuthErrorResponse {
                status: StatusCode::UNAUTHORIZED,
                error: ApplicationError::Authentication(
                    crate::domain::auth::errors::AuthError::InvalidToken,
                ),
            })?;

        // Parse Bearer token
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AuthErrorResponse {
                status: StatusCode::UNAUTHORIZED,
                error: ApplicationError::Authentication(
                    crate::domain::auth::errors::AuthError::InvalidToken,
                ),
            })?;

        // Validate token
        let (user_id, email, roles) =
            auth_state
                .validate_token
                .execute(token)
                .map_err(|e| AuthErrorResponse {
                    status: StatusCode::UNAUTHORIZED,
                    error: ApplicationError::Authentication(e),
                })?;

        Ok(AuthUser {
            user_id,
            email,
            roles,
        })
    }
}

impl<S> FromRequestParts<S> for ApiKeyAuth
where
    S: Send + Sync,
{
    type Rejection = AuthErrorResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Get AuthState from extensions
        let auth_state = parts
            .extensions
            .get::<AuthState>()
            .ok_or_else(|| AuthErrorResponse {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                error: ApplicationError::Configuration {
                    message: "Auth state not found in request extensions".to_string(),
                },
            })?;

        // Try to extract API key from Authorization header or X-API-Key header
        let api_key = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("ApiKey "))
            .map(|s| s.to_string())
            .or_else(|| {
                parts
                    .headers
                    .get("X-API-Key")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string())
            })
            .ok_or_else(|| AuthErrorResponse {
                status: StatusCode::UNAUTHORIZED,
                error: ApplicationError::Authentication(
                    crate::domain::auth::errors::AuthError::ApiKeyInvalid,
                ),
            })?;

        // Validate API key
        let user_id = auth_state
            .validate_api_key
            .execute(&api_key)
            .await
            .map_err(|e| AuthErrorResponse {
                status: StatusCode::UNAUTHORIZED,
                error: ApplicationError::Authentication(e),
            })?;

        // Get user to get email
        let user = auth_state
            .user_repository
            .find_by_id(&user_id)
            .await
            .map_err(|e| AuthErrorResponse {
                status: StatusCode::UNAUTHORIZED,
                error: ApplicationError::Authentication(e),
            })?
            .ok_or_else(|| AuthErrorResponse {
                status: StatusCode::UNAUTHORIZED,
                error: ApplicationError::Authentication(
                    crate::domain::auth::errors::AuthError::UserIdNotFound {
                        user_id: user_id.as_str(),
                    },
                ),
            })?;

        // For API key auth, we don't have the api_key_id in the extractor
        // We'll use a placeholder - in practice, you might want to return it from ValidateApiKeyUseCase
        Ok(ApiKeyAuth {
            user_id,
            email: user.email,
            api_key_id: crate::domain::auth::value_objects::ApiKeyId::generate(), // Placeholder
        })
    }
}

impl<S> FromRequestParts<S> for Auth
where
    S: Send + Sync,
{
    type Rejection = AuthErrorResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Get AuthState from extensions
        let auth_state = parts
            .extensions
            .get::<AuthState>()
            .ok_or_else(|| AuthErrorResponse {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                error: ApplicationError::Configuration {
                    message: "Auth state not found in request extensions".to_string(),
                },
            })?;

        // Try JWT Bearer token first
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok());

        if let Some(header) = auth_header {
            // Try JWT Bearer token
            if let Some(token) = header.strip_prefix("Bearer ") {
                match auth_state.validate_token.execute(token) {
                    Ok((user_id, email, roles)) => {
                        return Ok(Auth {
                            user_id,
                            email,
                            roles,
                            auth_method: AuthMethod::Jwt,
                        });
                    }
                    Err(_) => {
                        // JWT validation failed, try API key below
                    }
                }
            }

            // Try API key from Authorization header
            if let Some(api_key) = header.strip_prefix("ApiKey ") {
                match auth_state.validate_api_key.execute(api_key).await {
                    Ok(user_id) => {
                        let user = auth_state
                            .user_repository
                            .find_by_id(&user_id)
                            .await
                            .map_err(|e| AuthErrorResponse {
                                status: StatusCode::UNAUTHORIZED,
                                error: ApplicationError::Authentication(e),
                            })?
                            .ok_or_else(|| AuthErrorResponse {
                                status: StatusCode::UNAUTHORIZED,
                                error: ApplicationError::Authentication(
                                    crate::domain::auth::errors::AuthError::UserIdNotFound {
                                        user_id: user_id.as_str(),
                                    },
                                ),
                            })?;

                        return Ok(Auth {
                            user_id,
                            email: user.email,
                            roles: user.roles,
                            auth_method: AuthMethod::ApiKey,
                        });
                    }
                    Err(_) => {
                        // API key validation failed
                    }
                }
            }
        }

        // Try X-API-Key header
        if let Some(api_key) = parts.headers.get("X-API-Key").and_then(|h| h.to_str().ok()) {
            match auth_state.validate_api_key.execute(api_key).await {
                Ok(user_id) => {
                    let user = auth_state
                        .user_repository
                        .find_by_id(&user_id)
                        .await
                        .map_err(|e| AuthErrorResponse {
                            status: StatusCode::UNAUTHORIZED,
                            error: ApplicationError::Authentication(e),
                        })?
                        .ok_or_else(|| AuthErrorResponse {
                            status: StatusCode::UNAUTHORIZED,
                            error: ApplicationError::Authentication(
                                crate::domain::auth::errors::AuthError::UserIdNotFound {
                                    user_id: user_id.as_str(),
                                },
                            ),
                        })?;

                    return Ok(Auth {
                        user_id,
                        email: user.email,
                        roles: user.roles,
                        auth_method: AuthMethod::ApiKey,
                    });
                }
                Err(e) => {
                    return Err(AuthErrorResponse {
                        status: StatusCode::UNAUTHORIZED,
                        error: ApplicationError::Authentication(e),
                    });
                }
            }
        }

        // No valid authentication found
        Err(AuthErrorResponse {
            status: StatusCode::UNAUTHORIZED,
            error: ApplicationError::Authentication(
                crate::domain::auth::errors::AuthError::InvalidToken,
            ),
        })
    }
}

/// Error response for authentication failures
#[derive(Debug)]
pub struct AuthErrorResponse {
    pub status: StatusCode,
    pub error: ApplicationError,
}

impl IntoResponse for AuthErrorResponse {
    fn into_response(self) -> Response {
        let status = self.status;
        let error_response = crate::presentation::models::ErrorResponse {
            code: match self.error {
                ApplicationError::Authentication(ref auth_err) => match auth_err {
                    crate::domain::auth::errors::AuthError::InvalidToken => "INVALID_TOKEN",
                    crate::domain::auth::errors::AuthError::TokenExpired => "TOKEN_EXPIRED",
                    crate::domain::auth::errors::AuthError::InvalidCredentials => {
                        "INVALID_CREDENTIALS"
                    }
                    crate::domain::auth::errors::AuthError::ApiKeyInvalid => "API_KEY_INVALID",
                    crate::domain::auth::errors::AuthError::ApiKeyExpired => "API_KEY_EXPIRED",
                    _ => "AUTHENTICATION_ERROR",
                },
                _ => "AUTHENTICATION_ERROR",
            }
            .to_string(),
            message: format!("{}", self.error),
            details: None,
            request_id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
        };

        (status, axum::Json(error_response)).into_response()
    }
}
