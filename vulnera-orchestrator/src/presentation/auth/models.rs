//! Authentication DTOs for API requests and responses

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use vulnera_core::domain::auth::value_objects::UserRole;

/// Login request DTO
#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    /// User email address
    #[schema(example = "user@example.com")]
    pub email: String,
    /// User password
    #[schema(example = "secure_password_123")]
    pub password: String,
}

/// Register new user request DTO
#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    /// User email address
    #[schema(example = "newuser@example.com")]
    pub email: String,
    /// User password (minimum 8 characters)
    #[schema(example = "secure_password_123")]
    pub password: String,
    /// Optional user roles (defaults to ["User"] if not provided)
    #[schema(example = json!(["user"]))]
    pub roles: Option<Vec<UserRole>>,
}

/// Authentication response DTO (cookie-based)
///
/// Tokens are set as HttpOnly cookies. This response contains only
/// the CSRF token (for client-side header submission) and metadata.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthResponse {
    /// CSRF token - must be included in X-CSRF-Token header for state-changing requests
    #[schema(example = "dGhpc2lzYWNzcmZ0b2tlbmV4YW1wbGU")]
    pub csrf_token: String,
    /// Access token expiration time in seconds
    #[schema(example = 86400)]
    pub expires_in: u64,
    /// User ID
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub user_id: Uuid,
    /// User email
    #[schema(example = "user@example.com")]
    pub email: String,
    /// User roles
    #[schema(example = json!(["user"]))]
    pub roles: Vec<String>,
}

/// Refresh token response DTO (cookie-based)
///
/// New access token is set as HttpOnly cookie. This response contains
/// the new CSRF token and metadata.
#[derive(Debug, Serialize, ToSchema)]
pub struct RefreshResponse {
    /// New CSRF token - must be included in X-CSRF-Token header for state-changing requests
    #[schema(example = "bmV3Y3NyZnRva2VuZXhhbXBsZQ")]
    pub csrf_token: String,
    /// New access token expiration time in seconds
    #[schema(example = 86400)]
    pub expires_in: u64,
}

/// Logout response DTO
#[derive(Debug, Serialize, ToSchema)]
pub struct LogoutResponse {
    /// Logout status message
    #[schema(example = "Successfully logged out")]
    pub message: String,
}

/// Create API key request DTO
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateApiKeyRequest {
    /// Human-readable name for the API key
    #[schema(example = "VS Code Extension")]
    pub name: Option<String>,
    /// Optional expiration date (ISO 8601 format)
    #[schema(example = "2025-12-31T23:59:59Z")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// API key response DTO (returned when creating a new key)
#[derive(Debug, Serialize, ToSchema)]
pub struct ApiKeyResponse {
    /// API key ID
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub id: Uuid,
    /// Human-readable name
    #[schema(example = "VS Code Extension")]
    pub name: String,
    /// Plaintext API key (only shown once, on creation)
    #[schema(example = "vuln_a1b2c3d4e5f6...")]
    pub key: Option<String>,
    /// Creation timestamp
    #[schema(example = "2024-01-15T10:30:00Z")]
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp (None if no expiration)
    #[schema(example = "2025-01-15T10:30:00Z")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// API key list item DTO (for listing keys without exposing plaintext)
#[derive(Debug, Serialize, ToSchema)]
pub struct ApiKeyListItem {
    /// API key ID
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub id: Uuid,
    /// Human-readable name
    #[schema(example = "VS Code Extension")]
    pub name: String,
    /// Masked API key for display (e.g., "vuln_abcd...xyz")
    #[schema(example = "vuln_abcd...xyz")]
    pub masked_key: String,
    /// Creation timestamp
    #[schema(example = "2024-01-15T10:30:00Z")]
    pub created_at: DateTime<Utc>,
    /// Last usage timestamp (None if never used)
    #[schema(example = "2024-01-20T14:30:00Z")]
    pub last_used_at: Option<DateTime<Utc>>,
    /// Expiration timestamp (None if no expiration)
    #[schema(example = "2025-01-15T10:30:00Z")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// API key list response DTO
#[derive(Debug, Serialize, ToSchema)]
pub struct ApiKeyListResponse {
    /// List of API keys
    pub api_keys: Vec<ApiKeyListItem>,
}
