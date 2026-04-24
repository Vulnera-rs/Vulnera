//! SQLx implementation of Subscription Limits repository

use async_trait::async_trait;
use sqlx::PgPool;
use std::str::FromStr;
use std::sync::Arc;

use crate::domain::organization::{
    entities::SubscriptionLimits,
    errors::OrganizationError,
    repositories::ISubscriptionLimitsRepository,
    value_objects::{OrganizationId, SubscriptionTier},
};

/// SQLx implementation of Subscription Limits repository
pub struct SqlxSubscriptionLimitsRepository {
    pool: Arc<PgPool>,
}

impl SqlxSubscriptionLimitsRepository {
    /// Create a new SQLx subscription limits repository
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ISubscriptionLimitsRepository for SqlxSubscriptionLimitsRepository {
    async fn find_by_org(
        &self,
        org_id: &OrganizationId,
    ) -> Result<Option<SubscriptionLimits>, OrganizationError> {
        let org_uuid = org_id.as_uuid();

        let row = sqlx::query!(
            r#"
            SELECT id, organization_id, tier, 
                   max_scans_monthly, max_api_calls_monthly, max_members, 
                   max_repos, max_private_repos, scan_results_retention_days,
                   features, created_at, updated_at
            FROM subscription_limits
            WHERE organization_id = $1
            "#,
            org_uuid
        )
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error finding subscription limits: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        match row {
            Some(row) => {
                let tier = SubscriptionTier::from_str(&row.tier).unwrap_or_default();
                Ok(Some(SubscriptionLimits {
                    id: row.id,
                    organization_id: OrganizationId::from(row.organization_id),
                    tier,
                    max_scans_monthly: row.max_scans_monthly as u32,
                    max_api_calls_monthly: row.max_api_calls_monthly as u32,
                    max_members: row.max_members as u32,
                    max_repos: row.max_repos as u32,
                    max_private_repos: row.max_private_repos as u32,
                    scan_results_retention_days: row.scan_results_retention_days as u32,
                    features: row.features,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                }))
            }
            None => Ok(None),
        }
    }

    async fn create(&self, limits: &SubscriptionLimits) -> Result<(), OrganizationError> {
        let org_uuid = limits.organization_id.as_uuid();

        sqlx::query!(
            r#"
            INSERT INTO subscription_limits (
                id, organization_id, tier,
                max_scans_monthly, max_api_calls_monthly, max_members,
                max_repos, max_private_repos, scan_results_retention_days,
                features, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
            limits.id,
            org_uuid,
            limits.tier.to_string(),
            limits.max_scans_monthly as i32,
            limits.max_api_calls_monthly as i32,
            limits.max_members as i32,
            limits.max_repos as i32,
            limits.max_private_repos as i32,
            limits.scan_results_retention_days as i32,
            limits.features,
            limits.created_at,
            limits.updated_at
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error creating subscription limits: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(())
    }

    async fn update(&self, limits: &SubscriptionLimits) -> Result<(), OrganizationError> {
        let org_uuid = limits.organization_id.as_uuid();
        let updated_at = chrono::Utc::now();

        let result = sqlx::query!(
            r#"
            UPDATE subscription_limits
            SET tier = $2,
                max_scans_monthly = $3,
                max_api_calls_monthly = $4,
                max_members = $5,
                max_repos = $6,
                max_private_repos = $7,
                scan_results_retention_days = $8,
                features = $9,
                updated_at = $10
            WHERE organization_id = $1
            "#,
            org_uuid,
            limits.tier.to_string(),
            limits.max_scans_monthly as i32,
            limits.max_api_calls_monthly as i32,
            limits.max_members as i32,
            limits.max_repos as i32,
            limits.max_private_repos as i32,
            limits.scan_results_retention_days as i32,
            limits.features,
            updated_at
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error updating subscription limits: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        if result.rows_affected() == 0 {
            return Err(OrganizationError::NotFound {
                id: limits.organization_id.to_string(),
            });
        }

        Ok(())
    }

    async fn delete(&self, org_id: &OrganizationId) -> Result<(), OrganizationError> {
        let org_uuid = org_id.as_uuid();

        let result = sqlx::query!(
            r#"
            DELETE FROM subscription_limits
            WHERE organization_id = $1
            "#,
            org_uuid
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error deleting subscription limits: {}", e);
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
}
