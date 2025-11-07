//! Authentication DTOs for API requests and responses

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::domain::auth::value_objects::UserRole;

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

/// Token response DTO
#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    /// JWT access token
    #[schema(example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub access_token: String,
    /// JWT refresh token
    #[schema(example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub refresh_token: String,
    /// Token type (always "Bearer")
    #[schema(example = "Bearer")]
    pub token_type: String,
    /// Access token expiration time in seconds
    #[schema(example = 86400)]
    pub expires_in: u64,
}

/// Refresh token request DTO
#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshRequest {
    /// Refresh token
    #[schema(example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub refresh_token: String,
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





