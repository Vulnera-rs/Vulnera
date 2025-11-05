//! SQLx implementation of API Key repository

use async_trait::async_trait;
use chrono::DateTime;
use chrono::Utc;
use sqlx::PgPool;
use std::sync::Arc;

use crate::domain::auth::{
    entities::ApiKey,
    errors::AuthError,
    repositories::IApiKeyRepository,
    value_objects::{ApiKeyHash, ApiKeyId, UserId},
};

/// SQLx implementation of API Key repository
pub struct SqlxApiKeyRepository {
    pool: Arc<PgPool>,
}

impl SqlxApiKeyRepository {
    /// Create a new SQLx API key repository
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl IApiKeyRepository for SqlxApiKeyRepository {
    async fn find_by_hash(&self, key_hash: &ApiKeyHash) -> Result<Option<ApiKey>, AuthError> {
        let hash_str = key_hash.as_str();

        let row = sqlx::query!(
            r#"
            SELECT id, user_id, key_hash, name, last_used_at, expires_at, created_at, revoked_at
            FROM api_keys
            WHERE key_hash = $1
            "#,
            hash_str
        )
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error finding API key by hash: {}", e);
            AuthError::ApiKeyNotFound
        })?;

        match row {
            Some(row) => {
                let api_key_id = ApiKeyId::from(row.id);
                let user_id = UserId::from(row.user_id);
                let key_hash = ApiKeyHash::from(row.key_hash);

                Ok(Some(ApiKey {
                    api_key_id,
                    user_id,
                    key_hash,
                    name: row.name,
                    last_used_at: row.last_used_at,
                    created_at: row.created_at,
                    expires_at: row.expires_at,
                    revoked_at: row.revoked_at,
                }))
            }
            None => Ok(None),
        }
    }

    async fn find_by_user_id(&self, user_id: &UserId) -> Result<Vec<ApiKey>, AuthError> {
        let user_uuid = user_id.as_uuid();

        let rows = sqlx::query!(
            r#"
            SELECT id, user_id, key_hash, name, last_used_at, expires_at, created_at, revoked_at
            FROM api_keys
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
            user_uuid
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error finding API keys by user_id: {}", e);
            AuthError::UserIdNotFound {
                user_id: user_id.as_str(),
            }
        })?;

        let api_keys = rows
            .into_iter()
            .map(|row| {
                let api_key_id = ApiKeyId::from(row.id);
                let user_id = UserId::from(row.user_id);
                let key_hash = ApiKeyHash::from(row.key_hash);

                ApiKey {
                    api_key_id,
                    user_id,
                    key_hash,
                    name: row.name,
                    last_used_at: row.last_used_at,
                    created_at: row.created_at,
                    expires_at: row.expires_at,
                    revoked_at: row.revoked_at,
                }
            })
            .collect();

        Ok(api_keys)
    }

    async fn find_by_id(&self, key_id: &ApiKeyId) -> Result<Option<ApiKey>, AuthError> {
        let key_uuid = key_id.as_uuid();

        let row = sqlx::query!(
            r#"
            SELECT id, user_id, key_hash, name, last_used_at, expires_at, created_at, revoked_at
            FROM api_keys
            WHERE id = $1
            "#,
            key_uuid
        )
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error finding API key by id: {}", e);
            AuthError::ApiKeyNotFound
        })?;

        match row {
            Some(row) => {
                let api_key_id = ApiKeyId::from(row.id);
                let user_id = UserId::from(row.user_id);
                let key_hash = ApiKeyHash::from(row.key_hash);

                Ok(Some(ApiKey {
                    api_key_id,
                    user_id,
                    key_hash,
                    name: row.name,
                    last_used_at: row.last_used_at,
                    created_at: row.created_at,
                    expires_at: row.expires_at,
                    revoked_at: row.revoked_at,
                }))
            }
            None => Ok(None),
        }
    }

    async fn create(&self, api_key: &ApiKey) -> Result<(), AuthError> {
        let key_uuid = api_key.api_key_id.as_uuid();
        let user_uuid = api_key.user_id.as_uuid();
        let hash_str = api_key.key_hash.as_str();

        sqlx::query!(
            r#"
            INSERT INTO api_keys (id, user_id, key_hash, name, last_used_at, expires_at, created_at, revoked_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            key_uuid,
            user_uuid,
            hash_str,
            api_key.name,
            api_key.last_used_at,
            api_key.expires_at,
            api_key.created_at,
            api_key.revoked_at
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error creating API key: {}", e);
            AuthError::ApiKeyNotFound
        })?;

        Ok(())
    }

    async fn update_last_used(
        &self,
        key_id: &ApiKeyId,
        used_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let key_uuid = key_id.as_uuid();

        let result = sqlx::query!(
            r#"
            UPDATE api_keys
            SET last_used_at = $2
            WHERE id = $1
            "#,
            key_uuid,
            used_at
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error updating API key last_used_at: {}", e);
            AuthError::ApiKeyNotFound
        })?;

        if result.rows_affected() == 0 {
            return Err(AuthError::ApiKeyNotFound);
        }

        Ok(())
    }

    async fn revoke(&self, key_id: &ApiKeyId) -> Result<(), AuthError> {
        let key_uuid = key_id.as_uuid();
        let revoked_at = Utc::now();

        let result = sqlx::query!(
            r#"
            UPDATE api_keys
            SET revoked_at = $2
            WHERE id = $1 AND revoked_at IS NULL
            "#,
            key_uuid,
            revoked_at
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error revoking API key: {}", e);
            AuthError::ApiKeyNotFound
        })?;

        if result.rows_affected() == 0 {
            return Err(AuthError::ApiKeyNotFound);
        }

        Ok(())
    }

    async fn delete(&self, key_id: &ApiKeyId) -> Result<(), AuthError> {
        let key_uuid = key_id.as_uuid();

        let result = sqlx::query!(
            r#"
            DELETE FROM api_keys
            WHERE id = $1
            "#,
            key_uuid
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error deleting API key: {}", e);
            AuthError::ApiKeyNotFound
        })?;

        if result.rows_affected() == 0 {
            return Err(AuthError::ApiKeyNotFound);
        }

        Ok(())
    }
}
