//! SQLx implementation of Organization Member repository

use async_trait::async_trait;
use sqlx::PgPool;
use std::sync::Arc;

use crate::domain::auth::value_objects::UserId;
use crate::domain::organization::{
    errors::OrganizationError,
    repositories::IOrganizationMemberRepository,
    value_objects::{OrganizationId, OrganizationMember},
};

/// SQLx implementation of Organization Member repository
pub struct SqlxOrganizationMemberRepository {
    pool: Arc<PgPool>,
}

impl SqlxOrganizationMemberRepository {
    /// Create a new SQLx organization member repository
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl IOrganizationMemberRepository for SqlxOrganizationMemberRepository {
    async fn add_member(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<(), OrganizationError> {
        let org_uuid = org_id.as_uuid();
        let user_uuid = user_id.as_uuid();

        sqlx::query!(
            r#"
            INSERT INTO organization_members (organization_id, user_id, joined_at)
            VALUES ($1, $2, NOW())
            "#,
            org_uuid,
            user_uuid
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error adding member: {}", e);
            if let Some(db_err) = e.as_database_error()
                && db_err.constraint() == Some("idx_organization_members_org_user")
            {
                return OrganizationError::AlreadyMember {
                    user_id: user_id.to_string(),
                    org_id: org_id.to_string(),
                };
            }
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(())
    }

    async fn remove_member(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<(), OrganizationError> {
        let org_uuid = org_id.as_uuid();
        let user_uuid = user_id.as_uuid();

        let result = sqlx::query!(
            r#"
            DELETE FROM organization_members
            WHERE organization_id = $1 AND user_id = $2
            "#,
            org_uuid,
            user_uuid
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error removing member: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        if result.rows_affected() == 0 {
            return Err(OrganizationError::NotAMember {
                user_id: user_id.to_string(),
                org_id: org_id.to_string(),
            });
        }

        Ok(())
    }

    async fn find_by_organization(
        &self,
        org_id: &OrganizationId,
    ) -> Result<Vec<OrganizationMember>, OrganizationError> {
        let org_uuid = org_id.as_uuid();

        let rows = sqlx::query!(
            r#"
            SELECT user_id, joined_at
            FROM organization_members
            WHERE organization_id = $1
            ORDER BY joined_at DESC
            "#,
            org_uuid
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error finding members: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(rows
            .into_iter()
            .map(|row| OrganizationMember::with_joined_at(UserId::from(row.user_id), row.joined_at))
            .collect())
    }

    async fn find_organizations_by_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<OrganizationId>, OrganizationError> {
        let user_uuid = user_id.as_uuid();

        let rows = sqlx::query!(
            r#"
            SELECT organization_id
            FROM organization_members
            WHERE user_id = $1
            "#,
            user_uuid
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error finding user organizations: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(rows
            .into_iter()
            .map(|row| OrganizationId::from(row.organization_id))
            .collect())
    }

    async fn is_member(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<bool, OrganizationError> {
        let org_uuid = org_id.as_uuid();
        let user_uuid = user_id.as_uuid();

        let result = sqlx::query_scalar!(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM organization_members
                WHERE organization_id = $1 AND user_id = $2
            ) as "exists!"
            "#,
            org_uuid,
            user_uuid
        )
        .fetch_one(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error checking membership: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(result)
    }

    async fn count_members(&self, org_id: &OrganizationId) -> Result<i64, OrganizationError> {
        let org_uuid = org_id.as_uuid();

        let result = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM organization_members
            WHERE organization_id = $1
            "#,
            org_uuid
        )
        .fetch_one(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error counting members: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(result)
    }
}
