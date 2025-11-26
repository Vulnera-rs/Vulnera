//! SQLx implementation of Organization repository

use async_trait::async_trait;
use sqlx::PgPool;
use std::sync::Arc;

use crate::domain::auth::value_objects::UserId;
use crate::domain::organization::{
    entities::Organization, errors::OrganizationError, repositories::IOrganizationRepository,
    value_objects::OrganizationId,
};

/// SQLx implementation of Organization repository
pub struct SqlxOrganizationRepository {
    pool: Arc<PgPool>,
}

impl SqlxOrganizationRepository {
    /// Create a new SQLx organization repository
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl IOrganizationRepository for SqlxOrganizationRepository {
    async fn find_by_id(
        &self,
        org_id: &OrganizationId,
    ) -> Result<Option<Organization>, OrganizationError> {
        let org_uuid = org_id.as_uuid();

        let row = sqlx::query!(
            r#"
            SELECT id, owner_id, name, description, created_at, updated_at
            FROM organizations
            WHERE id = $1
            "#,
            org_uuid
        )
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error finding organization by id: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        match row {
            Some(row) => Ok(Some(Organization::with_id(
                OrganizationId::from(row.id),
                UserId::from(row.owner_id),
                row.name,
                row.description,
                row.created_at,
                row.updated_at,
            ))),
            None => Ok(None),
        }
    }

    async fn find_by_owner_and_name(
        &self,
        owner_id: &UserId,
        name: &str,
    ) -> Result<Option<Organization>, OrganizationError> {
        let owner_uuid = owner_id.as_uuid();

        let row = sqlx::query!(
            r#"
            SELECT id, owner_id, name, description, created_at, updated_at
            FROM organizations
            WHERE owner_id = $1 AND name = $2
            "#,
            owner_uuid,
            name
        )
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!(
                "Database error finding organization by owner and name: {}",
                e
            );
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        match row {
            Some(row) => Ok(Some(Organization::with_id(
                OrganizationId::from(row.id),
                UserId::from(row.owner_id),
                row.name,
                row.description,
                row.created_at,
                row.updated_at,
            ))),
            None => Ok(None),
        }
    }

    async fn find_by_owner_id(
        &self,
        owner_id: &UserId,
    ) -> Result<Vec<Organization>, OrganizationError> {
        let owner_uuid = owner_id.as_uuid();

        let rows = sqlx::query!(
            r#"
            SELECT id, owner_id, name, description, created_at, updated_at
            FROM organizations
            WHERE owner_id = $1
            ORDER BY created_at DESC
            "#,
            owner_uuid
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error finding organizations by owner: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(rows
            .into_iter()
            .map(|row| {
                Organization::with_id(
                    OrganizationId::from(row.id),
                    UserId::from(row.owner_id),
                    row.name,
                    row.description,
                    row.created_at,
                    row.updated_at,
                )
            })
            .collect())
    }

    async fn create(&self, org: &Organization) -> Result<(), OrganizationError> {
        let org_uuid = org.id.as_uuid();
        let owner_uuid = org.owner_id.as_uuid();

        sqlx::query!(
            r#"
            INSERT INTO organizations (id, owner_id, name, description, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            org_uuid,
            owner_uuid,
            org.name,
            org.description,
            org.created_at,
            org.updated_at
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error creating organization: {}", e);
            if let Some(db_err) = e.as_database_error() {
                if db_err.constraint() == Some("idx_organizations_owner_name") {
                    return OrganizationError::NameAlreadyExists {
                        name: org.name.clone(),
                    };
                }
            }
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(())
    }

    async fn update(&self, org: &Organization) -> Result<(), OrganizationError> {
        let org_uuid = org.id.as_uuid();
        let owner_uuid = org.owner_id.as_uuid();
        let updated_at = chrono::Utc::now();

        let result = sqlx::query!(
            r#"
            UPDATE organizations
            SET owner_id = $2, name = $3, description = $4, updated_at = $5
            WHERE id = $1
            "#,
            org_uuid,
            owner_uuid,
            org.name,
            org.description,
            updated_at
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error updating organization: {}", e);
            if let Some(db_err) = e.as_database_error() {
                if db_err.constraint() == Some("idx_organizations_owner_name") {
                    return OrganizationError::NameAlreadyExists {
                        name: org.name.clone(),
                    };
                }
            }
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        if result.rows_affected() == 0 {
            return Err(OrganizationError::NotFound {
                id: org.id.to_string(),
            });
        }

        Ok(())
    }

    async fn delete(&self, org_id: &OrganizationId) -> Result<(), OrganizationError> {
        let org_uuid = org_id.as_uuid();

        let result = sqlx::query!(
            r#"
            DELETE FROM organizations
            WHERE id = $1
            "#,
            org_uuid
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error deleting organization: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        if result.rows_affected() == 0 {
            return Err(OrganizationError::NotFound {
                id: org_id.to_string(),
            });
        }

        Ok(())
    }

    async fn list_all(
        &self,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<Organization>, OrganizationError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, owner_id, name, description, created_at, updated_at
            FROM organizations
            ORDER BY created_at DESC
            OFFSET $1
            LIMIT $2
            "#,
            offset,
            limit
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error listing organizations: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(rows
            .into_iter()
            .map(|row| {
                Organization::with_id(
                    OrganizationId::from(row.id),
                    UserId::from(row.owner_id),
                    row.name,
                    row.description,
                    row.created_at,
                    row.updated_at,
                )
            })
            .collect())
    }

    async fn count_all(&self) -> Result<i64, OrganizationError> {
        let result = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM organizations
            "#
        )
        .fetch_one(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error counting organizations: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(result)
    }
}
