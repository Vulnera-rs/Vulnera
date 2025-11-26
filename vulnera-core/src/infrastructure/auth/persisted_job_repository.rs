//! SQLx implementation of Persisted Job Results repository

use async_trait::async_trait;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::domain::auth::value_objects::UserId;
use crate::domain::organization::{
    errors::OrganizationError,
    repositories::{IPersistedJobResultRepository, PersistedJobResult},
    value_objects::OrganizationId,
};

/// SQLx implementation of Persisted Job Results repository
pub struct SqlxPersistedJobResultRepository {
    pool: Arc<PgPool>,
}

impl SqlxPersistedJobResultRepository {
    /// Create a new SQLx persisted job result repository
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl IPersistedJobResultRepository for SqlxPersistedJobResultRepository {
    async fn save(&self, job: &PersistedJobResult) -> Result<(), OrganizationError> {
        let org_uuid = job.organization_id.map(|id| id.as_uuid());
        let user_uuid = job.user_id.map(|id| id.as_uuid());

        sqlx::query!(
            r#"
            INSERT INTO persisted_job_results (
                job_id, organization_id, user_id, project_id, source_type, source_uri, status,
                findings_json, module_results_json, summary_json, findings_by_type_json,
                total_findings, findings_critical, findings_high, findings_medium, findings_low, findings_info,
                created_at, started_at, completed_at, error_message
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
            ON CONFLICT (job_id)
            DO UPDATE SET
                status = EXCLUDED.status,
                findings_json = EXCLUDED.findings_json,
                module_results_json = EXCLUDED.module_results_json,
                summary_json = EXCLUDED.summary_json,
                findings_by_type_json = EXCLUDED.findings_by_type_json,
                total_findings = EXCLUDED.total_findings,
                findings_critical = EXCLUDED.findings_critical,
                findings_high = EXCLUDED.findings_high,
                findings_medium = EXCLUDED.findings_medium,
                findings_low = EXCLUDED.findings_low,
                findings_info = EXCLUDED.findings_info,
                started_at = EXCLUDED.started_at,
                completed_at = EXCLUDED.completed_at,
                error_message = EXCLUDED.error_message
            "#,
            job.job_id,
            org_uuid,
            user_uuid,
            job.project_id,
            job.source_type,
            job.source_uri,
            job.status,
            job.findings_json,
            job.module_results_json,
            job.summary_json,
            job.findings_by_type_json,
            job.total_findings as i32,
            job.findings_critical as i32,
            job.findings_high as i32,
            job.findings_medium as i32,
            job.findings_low as i32,
            job.findings_info as i32,
            job.created_at,
            job.started_at,
            job.completed_at,
            job.error_message
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error saving job result: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(())
    }

    async fn find_by_id(&self, job_id: Uuid) -> Result<Option<PersistedJobResult>, OrganizationError> {
        let row = sqlx::query!(
            r#"
            SELECT job_id, organization_id, user_id, project_id, source_type, source_uri, status,
                   findings_json, module_results_json, summary_json, findings_by_type_json,
                   total_findings, findings_critical, findings_high, findings_medium, findings_low, findings_info,
                   created_at, started_at, completed_at, error_message
            FROM persisted_job_results
            WHERE job_id = $1
            "#,
            job_id
        )
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error finding job result: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        match row {
            Some(row) => Ok(Some(PersistedJobResult {
                job_id: row.job_id,
                organization_id: row.organization_id.map(OrganizationId::from),
                user_id: row.user_id.map(UserId::from),
                project_id: row.project_id,
                source_type: row.source_type,
                source_uri: row.source_uri,
                status: row.status,
                findings_json: row.findings_json,
                module_results_json: row.module_results_json,
                summary_json: row.summary_json,
                findings_by_type_json: row.findings_by_type_json,
                total_findings: row.total_findings as u32,
                findings_critical: row.findings_critical as u32,
                findings_high: row.findings_high as u32,
                findings_medium: row.findings_medium as u32,
                findings_low: row.findings_low as u32,
                findings_info: row.findings_info as u32,
                created_at: row.created_at,
                started_at: row.started_at,
                completed_at: row.completed_at,
                error_message: row.error_message,
            })),
            None => Ok(None),
        }
    }

    async fn find_by_org(
        &self,
        org_id: &OrganizationId,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<PersistedJobResult>, OrganizationError> {
        let org_uuid = org_id.as_uuid();

        let rows = sqlx::query!(
            r#"
            SELECT job_id, organization_id, user_id, project_id, source_type, source_uri, status,
                   findings_json, module_results_json, summary_json, findings_by_type_json,
                   total_findings, findings_critical, findings_high, findings_medium, findings_low, findings_info,
                   created_at, started_at, completed_at, error_message
            FROM persisted_job_results
            WHERE organization_id = $1
            ORDER BY created_at DESC
            OFFSET $2
            LIMIT $3
            "#,
            org_uuid,
            offset,
            limit
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error finding org job results: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(rows
            .into_iter()
            .map(|row| PersistedJobResult {
                job_id: row.job_id,
                organization_id: row.organization_id.map(OrganizationId::from),
                user_id: row.user_id.map(UserId::from),
                project_id: row.project_id,
                source_type: row.source_type,
                source_uri: row.source_uri,
                status: row.status,
                findings_json: row.findings_json,
                module_results_json: row.module_results_json,
                summary_json: row.summary_json,
                findings_by_type_json: row.findings_by_type_json,
                total_findings: row.total_findings as u32,
                findings_critical: row.findings_critical as u32,
                findings_high: row.findings_high as u32,
                findings_medium: row.findings_medium as u32,
                findings_low: row.findings_low as u32,
                findings_info: row.findings_info as u32,
                created_at: row.created_at,
                started_at: row.started_at,
                completed_at: row.completed_at,
                error_message: row.error_message,
            })
            .collect())
    }

    async fn find_by_user(
        &self,
        user_id: &UserId,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<PersistedJobResult>, OrganizationError> {
        let user_uuid = user_id.as_uuid();

        let rows = sqlx::query!(
            r#"
            SELECT job_id, organization_id, user_id, project_id, source_type, source_uri, status,
                   findings_json, module_results_json, summary_json, findings_by_type_json,
                   total_findings, findings_critical, findings_high, findings_medium, findings_low, findings_info,
                   created_at, started_at, completed_at, error_message
            FROM persisted_job_results
            WHERE user_id = $1
            ORDER BY created_at DESC
            OFFSET $2
            LIMIT $3
            "#,
            user_uuid,
            offset,
            limit
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error finding user job results: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(rows
            .into_iter()
            .map(|row| PersistedJobResult {
                job_id: row.job_id,
                organization_id: row.organization_id.map(OrganizationId::from),
                user_id: row.user_id.map(UserId::from),
                project_id: row.project_id,
                source_type: row.source_type,
                source_uri: row.source_uri,
                status: row.status,
                findings_json: row.findings_json,
                module_results_json: row.module_results_json,
                summary_json: row.summary_json,
                findings_by_type_json: row.findings_by_type_json,
                total_findings: row.total_findings as u32,
                findings_critical: row.findings_critical as u32,
                findings_high: row.findings_high as u32,
                findings_medium: row.findings_medium as u32,
                findings_low: row.findings_low as u32,
                findings_info: row.findings_info as u32,
                created_at: row.created_at,
                started_at: row.started_at,
                completed_at: row.completed_at,
                error_message: row.error_message,
            })
            .collect())
    }

    async fn count_by_org(&self, org_id: &OrganizationId) -> Result<i64, OrganizationError> {
        let org_uuid = org_id.as_uuid();

        let result = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM persisted_job_results
            WHERE organization_id = $1
            "#,
            org_uuid
        )
        .fetch_one(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error counting org job results: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(result)
    }

    async fn delete(&self, job_id: Uuid) -> Result<(), OrganizationError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM persisted_job_results
            WHERE job_id = $1
            "#,
            job_id
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error deleting job result: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        if result.rows_affected() == 0 {
            return Err(OrganizationError::NotFound {
                id: job_id.to_string(),
            });
        }

        Ok(())
    }
}
