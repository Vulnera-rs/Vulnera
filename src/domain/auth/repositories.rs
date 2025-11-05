//! Authentication repository traits

use async_trait::async_trait;
use chrono::DateTime;
use chrono::Utc;

use super::entities::{ApiKey, User};
use super::errors::AuthError;
use super::value_objects::{ApiKeyHash, ApiKeyId, Email, UserId};

/// User repository trait for user persistence
#[async_trait]
pub trait IUserRepository: Send + Sync {
    /// Find a user by email address
    async fn find_by_email(&self, email: &Email) -> Result<Option<User>, AuthError>;

    /// Find a user by user ID
    async fn find_by_id(&self, user_id: &UserId) -> Result<Option<User>, AuthError>;

    /// Create a new user
    async fn create(&self, user: &User) -> Result<(), AuthError>;

    /// Update an existing user
    async fn update(&self, user: &User) -> Result<(), AuthError>;

    /// Delete a user by ID
    async fn delete(&self, user_id: &UserId) -> Result<(), AuthError>;
}

/// API Key repository trait for API key persistence
#[async_trait]
pub trait IApiKeyRepository: Send + Sync {
    /// Find an API key by its hash
    async fn find_by_hash(&self, key_hash: &ApiKeyHash) -> Result<Option<ApiKey>, AuthError>;

    /// Find all API keys for a user
    async fn find_by_user_id(&self, user_id: &UserId) -> Result<Vec<ApiKey>, AuthError>;

    /// Find an API key by ID
    async fn find_by_id(&self, key_id: &ApiKeyId) -> Result<Option<ApiKey>, AuthError>;

    /// Create a new API key
    async fn create(&self, api_key: &ApiKey) -> Result<(), AuthError>;

    /// Update the last_used_at timestamp for an API key
    async fn update_last_used(&self, key_id: &ApiKeyId, used_at: DateTime<Utc>) -> Result<(), AuthError>;

    /// Revoke an API key (soft delete)
    async fn revoke(&self, key_id: &ApiKeyId) -> Result<(), AuthError>;

    /// Delete an API key permanently
    async fn delete(&self, key_id: &ApiKeyId) -> Result<(), AuthError>;
}



