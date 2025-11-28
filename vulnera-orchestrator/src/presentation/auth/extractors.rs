//! Authentication extractors for Axum (Cookie-based authentication)

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use vulnera_core::application::auth::use_cases::{ValidateApiKeyUseCase, ValidateTokenUseCase};
use vulnera_core::application::errors::ApplicationError;
use vulnera_core::domain::auth::value_objects::{ApiKeyId, Email, UserId, UserRole};

use crate::presentation::middleware::application_error_to_response;

/// Authenticated user information from JWT token (cookie-based)
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
    pub api_key_id: vulnera_core::domain::auth::value_objects::ApiKeyId,
}

/// Authentication method used
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Cookie,
    ApiKey,
}

/// Generic authentication extractor that accepts either Cookie or API key
#[derive(Debug, Clone)]
pub struct Auth {
    pub user_id: UserId,
    pub email: Email,
    pub roles: Vec<UserRole>,
    pub auth_method: AuthMethod,
    pub api_key_id: Option<ApiKeyId>,
    pub is_master_key: bool,
}

/// State for authentication extractors
#[derive(Clone)]
pub struct AuthState {
    pub validate_token: Arc<ValidateTokenUseCase>,
    pub validate_api_key: Arc<ValidateApiKeyUseCase>,
    pub user_repository: Arc<dyn vulnera_core::domain::auth::repositories::IUserRepository>,
    pub api_key_repository: Arc<dyn vulnera_core::domain::auth::repositories::IApiKeyRepository>,
    pub api_key_generator: Arc<vulnera_core::infrastructure::auth::ApiKeyGenerator>,
}

/// Helper function to extract a cookie value from request parts
fn extract_cookie_from_parts(parts: &Parts, cookie_name: &str) -> Option<String> {
    parts
        .headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(|s| s.trim())
        .find(|s| s.starts_with(&format!("{}=", cookie_name)))?
        .strip_prefix(&format!("{}=", cookie_name))
        .map(|s| s.to_string())
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

        // Extract access token from cookie
        let token =
            extract_cookie_from_parts(parts, "access_token").ok_or_else(|| AuthErrorResponse {
                status: StatusCode::UNAUTHORIZED,
                error: ApplicationError::Authentication(
                    vulnera_core::domain::auth::errors::AuthError::InvalidToken,
                ),
            })?;

        // Validate token
        let (user_id, email, roles) =
            auth_state
                .validate_token
                .execute(&token)
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
                    vulnera_core::domain::auth::errors::AuthError::ApiKeyInvalid,
                ),
            })?;

        // Check if this is the master API key (dev/extension use)
        if vulnera_core::infrastructure::auth::is_master_key(&api_key) {
            // Create a synthetic master user with admin privileges
            let master_user_id = UserId::generate();
            let master_email = Email::new("master@vulnera.local".to_string())
                .unwrap_or_else(|_| Email::new("master@local".to_string()).unwrap());
            let master_api_key_id = ApiKeyId::generate();

            tracing::info!("Master API key authenticated from {:?}", parts.uri);

            return Ok(ApiKeyAuth {
                user_id: master_user_id,
                email: master_email,
                api_key_id: master_api_key_id,
            });
        }

        // Validate API key against database (normal flow)
        let validation = auth_state
            .validate_api_key
            .execute(&api_key)
            .await
            .map_err(|e| AuthErrorResponse {
                status: StatusCode::UNAUTHORIZED,
                error: ApplicationError::Authentication(e),
            })?;
        let user_id = validation.user_id;

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
                    vulnera_core::domain::auth::errors::AuthError::UserIdNotFound {
                        user_id: user_id.as_str(),
                    },
                ),
            })?;

        // For API key auth, we don't have the api_key_id in the extractor
        Ok(ApiKeyAuth {
            user_id,
            email: user.email,
            api_key_id: validation.api_key_id,
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

        // Try cookie-based JWT authentication first
        if let Some(token) = extract_cookie_from_parts(parts, "access_token") {
            match auth_state.validate_token.execute(&token) {
                Ok((user_id, email, roles)) => {
                    return Ok(Auth {
                        user_id,
                        email,
                        roles,
                        auth_method: AuthMethod::Cookie,
                        api_key_id: None,
                        is_master_key: false,
                    });
                }
                Err(_) => {
                    // Cookie token validation failed, try API key below
                }
            }
        }

        // Try X-API-Key header (for programmatic access)
        if let Some(api_key) = parts.headers.get("X-API-Key").and_then(|h| h.to_str().ok()) {
            // Check if this is the master API key (dev/extension use)
            if vulnera_core::infrastructure::auth::is_master_key(api_key) {
                // Create a synthetic master user with admin privileges
                let master_user_id = vulnera_core::domain::auth::value_objects::UserId::generate();
                let master_email = vulnera_core::domain::auth::value_objects::Email::new(
                    "master@vulnera.local".to_string(),
                )
                .unwrap_or_else(|_| {
                    vulnera_core::domain::auth::value_objects::Email::new(
                        "master@local".to_string(),
                    )
                    .unwrap()
                });

                tracing::info!("Master API key authenticated from {:?}", parts.uri);

                return Ok(Auth {
                    user_id: master_user_id,
                    email: master_email,
                    roles: vec![vulnera_core::domain::auth::value_objects::UserRole::Admin],
                    auth_method: AuthMethod::ApiKey,
                    api_key_id: None,
                    is_master_key: true,
                });
            }

            match auth_state.validate_api_key.execute(api_key).await {
                Ok(validation) => {
                    let user_id = validation.user_id;
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
                                vulnera_core::domain::auth::errors::AuthError::UserIdNotFound {
                                    user_id: user_id.as_str(),
                                },
                            ),
                        })?;

                    return Ok(Auth {
                        user_id,
                        email: user.email,
                        roles: user.roles,
                        auth_method: AuthMethod::ApiKey,
                        api_key_id: Some(validation.api_key_id),
                        is_master_key: false,
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
                vulnera_core::domain::auth::errors::AuthError::InvalidToken,
            ),
        })
    }
}

/// Optional API key authentication extractor
/// Returns None if no API key is provided, Some(ApiKeyAuth) if valid API key is found
/// Uses X-API-Key header only (for programmatic access)
#[derive(Debug, Clone)]
pub struct OptionalApiKeyAuth(pub Option<ApiKeyAuth>);

impl<S> FromRequestParts<S> for OptionalApiKeyAuth
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

        // Try to extract API key from X-API-Key header only
        let api_key = parts.headers.get("X-API-Key").and_then(|h| h.to_str().ok());

        // If no API key found, return None (optional auth)
        let api_key = match api_key {
            Some(key) => key,
            None => return Ok(OptionalApiKeyAuth(None)),
        };

        // Check if this is the master API key (dev/extension use)
        if vulnera_core::infrastructure::auth::is_master_key(api_key) {
            // Create a synthetic master user with admin privileges
            let master_user_id = UserId::generate();
            let master_email = Email::new("master@vulnera.local".to_string())
                .unwrap_or_else(|_| Email::new("master@local".to_string()).unwrap());
            let master_api_key_id = ApiKeyId::generate();

            tracing::info!("Master API key authenticated from {:?}", parts.uri);

            return Ok(OptionalApiKeyAuth(Some(ApiKeyAuth {
                user_id: master_user_id,
                email: master_email,
                api_key_id: master_api_key_id,
            })));
        }

        // Validate API key
        let validation = auth_state
            .validate_api_key
            .execute(api_key)
            .await
            .map_err(|_| AuthErrorResponse {
                status: StatusCode::UNAUTHORIZED,
                error: ApplicationError::Authentication(
                    vulnera_core::domain::auth::errors::AuthError::ApiKeyInvalid,
                ),
            })?;
        let user_id = validation.user_id;

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
                    vulnera_core::domain::auth::errors::AuthError::UserIdNotFound {
                        user_id: user_id.as_str(),
                    },
                ),
            })?;

        Ok(OptionalApiKeyAuth(Some(ApiKeyAuth {
            user_id,
            email: user.email,
            api_key_id: validation.api_key_id,
        })))
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
        application_error_to_response(self.error)
    }
}

/// Helper trait for checking user roles
pub trait HasRole {
    /// Check if the user has admin role
    fn is_admin(&self) -> bool;

    /// Check if the user has a specific role
    fn has_role(&self, role: UserRole) -> bool;

    /// Require admin role or return error
    fn require_admin(&self) -> Result<(), AuthErrorResponse> {
        if !self.is_admin() {
            return Err(AuthErrorResponse {
                status: StatusCode::FORBIDDEN,
                error: ApplicationError::Authentication(
                    vulnera_core::domain::auth::errors::AuthError::InsufficientPermissions,
                ),
            });
        }
        Ok(())
    }
}

impl HasRole for Auth {
    fn is_admin(&self) -> bool {
        self.roles.iter().any(|r| r.is_admin())
    }

    fn has_role(&self, role: UserRole) -> bool {
        self.roles.contains(&role)
    }
}

impl HasRole for AuthUser {
    fn is_admin(&self) -> bool {
        self.roles.iter().any(|r| r.is_admin())
    }

    fn has_role(&self, role: UserRole) -> bool {
        self.roles.contains(&role)
    }
}

/// Optional authentication extractor - returns None if no valid auth is provided
/// This is useful for endpoints that can work with or without authentication
#[derive(Debug, Clone)]
pub struct OptionalAuth(pub Option<Auth>);

impl<S> FromRequestParts<S> for OptionalAuth
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Try to extract Auth, but don't fail if it's missing
        // We need to check if AuthState is available first
        let auth_state_available = parts.extensions.get::<AuthState>().is_some();

        if !auth_state_available {
            return Ok(OptionalAuth(None));
        }

        // Try to extract Auth, but don't fail if it's missing
        match Auth::from_request_parts(parts, _state).await {
            Ok(auth) => Ok(OptionalAuth(Some(auth))),
            Err(_) => Ok(OptionalAuth(None)),
        }
    }
}
