//! SQLx implementation of User repository

use async_trait::async_trait;
use sqlx::PgPool;
use std::str::FromStr;
use std::sync::Arc;

use crate::domain::auth::{
    entities::User,
    errors::AuthError,
    repositories::IUserRepository,
    value_objects::{Email, UserId, UserRole},
};

/// SQLx implementation of User repository
pub struct SqlxUserRepository {
    pool: Arc<PgPool>,
}

impl SqlxUserRepository {
    /// Create a new SQLx user repository
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl IUserRepository for SqlxUserRepository {
    #[tracing::instrument(skip(self), fields(email = %email.as_str()))]
    async fn find_by_email(&self, email: &Email) -> Result<Option<User>, AuthError> {
        let email_str = email.as_str();

        let row = sqlx::query!(
            r#"
            SELECT id, email, password_hash, roles, created_at, updated_at
            FROM users
            WHERE email = $1
            "#,
            email_str
        )
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error finding user by email: {}", e);
            // Check if it's a "relation does not exist" error (table missing)
            let error_msg = e.to_string();
            if error_msg.contains("relation") && error_msg.contains("does not exist") {
                AuthError::DatabaseError {
                    message: format!(
                        "Database table 'users' does not exist. Please run migrations: {}",
                        error_msg
                    ),
                }
            } else if error_msg.contains("permission denied") {
                AuthError::DatabaseError {
                    message: format!(
                        "Database permission denied. Check user permissions: {}",
                        error_msg
                    ),
                }
            } else {
                AuthError::DatabaseError {
                    message: format!(
                        "Database error while checking user existence: {}",
                        error_msg
                    ),
                }
            }
        })?;

        match row {
            Some(row) => {
                let user_id = UserId::from(row.id);
                let email_str = row.email.clone();
                let email = Email::new(email_str.clone())
                    .map_err(|_| AuthError::InvalidEmail { email: email_str })?;
                let password_hash =
                    crate::domain::auth::value_objects::PasswordHash::from(row.password_hash);

                // Parse roles from JSONB
                let roles: Vec<String> =
                    serde_json::from_value(row.roles).unwrap_or_else(|_| vec![]);
                let roles = roles
                    .iter()
                    .filter_map(|r| UserRole::from_str(r).ok())
                    .collect();

                Ok(Some(User {
                    user_id,
                    email,
                    password_hash,
                    roles,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                }))
            }
            None => Ok(None),
        }
    }

    #[tracing::instrument(skip(self), fields(user_id = %user_id.as_str()))]
    async fn find_by_id(&self, user_id: &UserId) -> Result<Option<User>, AuthError> {
        let user_uuid = user_id.as_uuid();

        let row = sqlx::query!(
            r#"
            SELECT id, email, password_hash, roles, created_at, updated_at
            FROM users
            WHERE id = $1
            "#,
            user_uuid
        )
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error finding user by id: {}", e);
            let error_msg = e.to_string();
            if error_msg.contains("relation") && error_msg.contains("does not exist") {
                AuthError::DatabaseError {
                    message: format!(
                        "Database table 'users' does not exist. Please run migrations: {}",
                        error_msg
                    ),
                }
            } else {
                AuthError::DatabaseError {
                    message: format!("Database error while finding user: {}", error_msg),
                }
            }
        })?;

        match row {
            Some(row) => {
                let user_id = UserId::from(row.id);
                let email_str = row.email.clone();
                let email = Email::new(email_str.clone())
                    .map_err(|_| AuthError::InvalidEmail { email: email_str })?;
                let password_hash =
                    crate::domain::auth::value_objects::PasswordHash::from(row.password_hash);

                // Parse roles from JSONB
                let roles: Vec<String> =
                    serde_json::from_value(row.roles).unwrap_or_else(|_| vec![]);
                let roles = roles
                    .iter()
                    .filter_map(|r| UserRole::from_str(r).ok())
                    .collect();

                Ok(Some(User {
                    user_id,
                    email,
                    password_hash,
                    roles,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                }))
            }
            None => Ok(None),
        }
    }

    #[tracing::instrument(skip(self, user), fields(user_id = %user.user_id.as_str(), email = %user.email.as_str()))]
    async fn create(&self, user: &User) -> Result<(), AuthError> {
        let user_uuid = user.user_id.as_uuid();
        let email_str = user.email.as_str();
        let password_hash_str = user.password_hash.as_str();

        // Serialize roles to JSON
        let roles_json = serde_json::to_value(
            user.roles
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<String>>(),
        )
        .map_err(|e| {
            tracing::error!("Failed to serialize roles: {}", e);
            AuthError::InvalidEmail {
                email: email_str.to_string(),
            }
        })?;

        sqlx::query!(
            r#"
            INSERT INTO users (id, email, password_hash, roles, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            user_uuid,
            email_str,
            password_hash_str,
            roles_json,
            user.created_at,
            user.updated_at
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error creating user: {}", e);
            if let Some(db_err) = e.as_database_error()
                && db_err.constraint() == Some("users_email_key")
            {
                return AuthError::EmailAlreadyExists {
                    email: email_str.to_string(),
                };
            }
            AuthError::InvalidEmail {
                email: email_str.to_string(),
            }
        })?;

        Ok(())
    }

    #[tracing::instrument(skip(self, user), fields(user_id = %user.user_id.as_str()))]
    async fn update(&self, user: &User) -> Result<(), AuthError> {
        let user_uuid = user.user_id.as_uuid();
        let email_str = user.email.as_str();
        let password_hash_str = user.password_hash.as_str();

        // Serialize roles to JSON
        let roles_json = serde_json::to_value(
            user.roles
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<String>>(),
        )
        .map_err(|e| {
            tracing::error!("Failed to serialize roles: {}", e);
            AuthError::InvalidEmail {
                email: email_str.to_string(),
            }
        })?;

        // Update updated_at manually since trigger may not be available
        let updated_at = chrono::Utc::now();

        sqlx::query!(
            r#"
            UPDATE users
            SET email = $2, password_hash = $3, roles = $4, updated_at = $5
            WHERE id = $1
            "#,
            user_uuid,
            email_str,
            password_hash_str,
            roles_json,
            updated_at
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error updating user: {}", e);
            if let Some(db_err) = e.as_database_error()
                && db_err.constraint() == Some("users_email_key")
            {
                return AuthError::EmailAlreadyExists {
                    email: email_str.to_string(),
                };
            }
            AuthError::UserIdNotFound {
                user_id: user.user_id.as_str(),
            }
        })?;

        Ok(())
    }

    #[tracing::instrument(skip(self), fields(user_id = %user_id.as_str()))]
    async fn delete(&self, user_id: &UserId) -> Result<(), AuthError> {
        let user_uuid = user_id.as_uuid();

        let result = sqlx::query!(
            r#"
            DELETE FROM users
            WHERE id = $1
            "#,
            user_uuid
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error deleting user: {}", e);
            AuthError::UserIdNotFound {
                user_id: user_id.as_str(),
            }
        })?;

        if result.rows_affected() == 0 {
            return Err(AuthError::UserIdNotFound {
                user_id: user_id.as_str(),
            });
        }

        Ok(())
    }
}
