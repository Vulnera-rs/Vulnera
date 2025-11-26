//! SQLx implementation of User Stats Monthly repository

use async_trait::async_trait;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::domain::organization::{
    entities::UserStatsMonthly,
    errors::OrganizationError,
    repositories::IUserStatsMonthlyRepository,
    value_objects::OrganizationId,
};

/// SQLx implementation of User Stats Monthly repository
pub struct SqlxUserStatsMonthlyRepository {
    pool: Arc<PgPool>,
}

impl SqlxUserStatsMonthlyRepository {
    /// Create a new SQLx user stats monthly repository
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl IUserStatsMonthlyRepository for SqlxUserStatsMonthlyRepository {
    async fn find_by_org_and_month(
        &self,
        org_id: &OrganizationId,
        year_month: &str,
    ) -> Result<Option<UserStatsMonthly>, OrganizationError> {
        let org_uuid = org_id.as_uuid();

        let row = sqlx::query!(
            r#"
            SELECT id, organization_id, year_month, 
                   findings_count, findings_critical, findings_high, 
                   findings_medium, findings_low, findings_info,
                   reports_generated, api_calls_used, scans_completed, scans_failed,
                   sast_findings, secrets_findings, dependency_findings, api_findings,
                   created_at, updated_at
            FROM user_stats_monthly
            WHERE organization_id = $1 AND year_month = $2
            "#,
            org_uuid,
            year_month
        )
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error finding stats: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        match row {
            Some(row) => Ok(Some(UserStatsMonthly {
                id: row.id,
                organization_id: OrganizationId::from(row.organization_id),
                year_month: row.year_month,
                findings_count: row.findings_count as u32,
                findings_critical: row.findings_critical as u32,
                findings_high: row.findings_high as u32,
                findings_medium: row.findings_medium as u32,
                findings_low: row.findings_low as u32,
                findings_info: row.findings_info as u32,
                reports_generated: row.reports_generated as u32,
                api_calls_used: row.api_calls_used as u32,
                scans_completed: row.scans_completed as u32,
                scans_failed: row.scans_failed as u32,
                sast_findings: row.sast_findings as u32,
                secrets_findings: row.secrets_findings as u32,
                dependency_findings: row.dependency_findings as u32,
                api_findings: row.api_findings as u32,
                created_at: row.created_at,
                updated_at: row.updated_at,
            })),
            None => Ok(None),
        }
    }

    async fn find_by_org_range(
        &self,
        org_id: &OrganizationId,
        from_month: &str,
        to_month: &str,
    ) -> Result<Vec<UserStatsMonthly>, OrganizationError> {
        let org_uuid = org_id.as_uuid();

        let rows = sqlx::query!(
            r#"
            SELECT id, organization_id, year_month, 
                   findings_count, findings_critical, findings_high, 
                   findings_medium, findings_low, findings_info,
                   reports_generated, api_calls_used, scans_completed, scans_failed,
                   sast_findings, secrets_findings, dependency_findings, api_findings,
                   created_at, updated_at
            FROM user_stats_monthly
            WHERE organization_id = $1 AND year_month >= $2 AND year_month <= $3
            ORDER BY year_month DESC
            "#,
            org_uuid,
            from_month,
            to_month
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error finding stats range: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(rows
            .into_iter()
            .map(|row| UserStatsMonthly {
                id: row.id,
                organization_id: OrganizationId::from(row.organization_id),
                year_month: row.year_month,
                findings_count: row.findings_count as u32,
                findings_critical: row.findings_critical as u32,
                findings_high: row.findings_high as u32,
                findings_medium: row.findings_medium as u32,
                findings_low: row.findings_low as u32,
                findings_info: row.findings_info as u32,
                reports_generated: row.reports_generated as u32,
                api_calls_used: row.api_calls_used as u32,
                scans_completed: row.scans_completed as u32,
                scans_failed: row.scans_failed as u32,
                sast_findings: row.sast_findings as u32,
                secrets_findings: row.secrets_findings as u32,
                dependency_findings: row.dependency_findings as u32,
                api_findings: row.api_findings as u32,
                created_at: row.created_at,
                updated_at: row.updated_at,
            })
            .collect())
    }

    async fn upsert(&self, stats: &UserStatsMonthly) -> Result<(), OrganizationError> {
        let org_uuid = stats.organization_id.as_uuid();

        sqlx::query!(
            r#"
            INSERT INTO user_stats_monthly (
                id, organization_id, year_month,
                findings_count, findings_critical, findings_high,
                findings_medium, findings_low, findings_info,
                reports_generated, api_calls_used, scans_completed, scans_failed,
                sast_findings, secrets_findings, dependency_findings, api_findings,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
            ON CONFLICT (organization_id, year_month)
            DO UPDATE SET
                findings_count = EXCLUDED.findings_count,
                findings_critical = EXCLUDED.findings_critical,
                findings_high = EXCLUDED.findings_high,
                findings_medium = EXCLUDED.findings_medium,
                findings_low = EXCLUDED.findings_low,
                findings_info = EXCLUDED.findings_info,
                reports_generated = EXCLUDED.reports_generated,
                api_calls_used = EXCLUDED.api_calls_used,
                scans_completed = EXCLUDED.scans_completed,
                scans_failed = EXCLUDED.scans_failed,
                sast_findings = EXCLUDED.sast_findings,
                secrets_findings = EXCLUDED.secrets_findings,
                dependency_findings = EXCLUDED.dependency_findings,
                api_findings = EXCLUDED.api_findings,
                updated_at = NOW()
            "#,
            stats.id,
            org_uuid,
            stats.year_month,
            stats.findings_count as i32,
            stats.findings_critical as i32,
            stats.findings_high as i32,
            stats.findings_medium as i32,
            stats.findings_low as i32,
            stats.findings_info as i32,
            stats.reports_generated as i32,
            stats.api_calls_used as i32,
            stats.scans_completed as i32,
            stats.scans_failed as i32,
            stats.sast_findings as i32,
            stats.secrets_findings as i32,
            stats.dependency_findings as i32,
            stats.api_findings as i32,
            stats.created_at,
            stats.updated_at
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error upserting stats: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(())
    }

    async fn increment_scan_completed(
        &self,
        org_id: &OrganizationId,
        year_month: &str,
    ) -> Result<(), OrganizationError> {
        let org_uuid = org_id.as_uuid();

        sqlx::query!(
            r#"
            INSERT INTO user_stats_monthly (id, organization_id, year_month, scans_completed)
            VALUES ($1, $2, $3, 1)
            ON CONFLICT (organization_id, year_month)
            DO UPDATE SET 
                scans_completed = user_stats_monthly.scans_completed + 1,
                updated_at = NOW()
            "#,
            Uuid::new_v4(),
            org_uuid,
            year_month
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error incrementing scans: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(())
    }

    async fn increment_api_calls(
        &self,
        org_id: &OrganizationId,
        year_month: &str,
        count: u32,
    ) -> Result<(), OrganizationError> {
        let org_uuid = org_id.as_uuid();

        sqlx::query!(
            r#"
            INSERT INTO user_stats_monthly (id, organization_id, year_month, api_calls_used)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (organization_id, year_month)
            DO UPDATE SET 
                api_calls_used = user_stats_monthly.api_calls_used + $4,
                updated_at = NOW()
            "#,
            Uuid::new_v4(),
            org_uuid,
            year_month,
            count as i32
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error incrementing API calls: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(())
    }

    async fn add_findings(
        &self,
        org_id: &OrganizationId,
        year_month: &str,
        critical: u32,
        high: u32,
        medium: u32,
        low: u32,
        info: u32,
    ) -> Result<(), OrganizationError> {
        let org_uuid = org_id.as_uuid();
        let total = critical + high + medium + low + info;

        sqlx::query!(
            r#"
            INSERT INTO user_stats_monthly (
                id, organization_id, year_month,
                findings_count, findings_critical, findings_high,
                findings_medium, findings_low, findings_info
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (organization_id, year_month)
            DO UPDATE SET 
                findings_count = user_stats_monthly.findings_count + $4,
                findings_critical = user_stats_monthly.findings_critical + $5,
                findings_high = user_stats_monthly.findings_high + $6,
                findings_medium = user_stats_monthly.findings_medium + $7,
                findings_low = user_stats_monthly.findings_low + $8,
                findings_info = user_stats_monthly.findings_info + $9,
                updated_at = NOW()
            "#,
            Uuid::new_v4(),
            org_uuid,
            year_month,
            total as i32,
            critical as i32,
            high as i32,
            medium as i32,
            low as i32,
            info as i32
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error adding findings: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(())
    }
}
