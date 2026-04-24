//! SQLx implementation of Analysis Events repository

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

use crate::domain::auth::value_objects::UserId;
use crate::domain::organization::{
    entities::AnalysisEvent,
    errors::OrganizationError,
    repositories::IAnalysisEventRepository,
    value_objects::{AnalysisEventType, OrganizationId},
};

/// SQLx implementation of Analysis Events repository
pub struct SqlxAnalysisEventRepository {
    pool: Arc<PgPool>,
}

impl SqlxAnalysisEventRepository {
    /// Create a new SQLx analysis event repository
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl IAnalysisEventRepository for SqlxAnalysisEventRepository {
    async fn record(&self, event: &AnalysisEvent) -> Result<(), OrganizationError> {
        let org_uuid = event.organization_id.map(|id| id.as_uuid());
        let user_uuid = event.user_id.map(|id| id.as_uuid());

        sqlx::query!(
            r#"
            INSERT INTO analysis_events (id, organization_id, user_id, job_id, event_type, metadata, timestamp)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            event.id,
            org_uuid,
            user_uuid,
            event.job_id,
            event.event_type.to_string(),
            event.metadata,
            event.timestamp
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error recording event: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(())
    }

    async fn find_by_org_and_range(
        &self,
        org_id: &OrganizationId,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<AnalysisEvent>, OrganizationError> {
        let org_uuid = org_id.as_uuid();

        let rows = sqlx::query!(
            r#"
            SELECT id, organization_id, user_id, job_id, event_type, metadata, timestamp
            FROM analysis_events
            WHERE organization_id = $1 AND timestamp >= $2 AND timestamp <= $3
            ORDER BY timestamp DESC
            "#,
            org_uuid,
            from,
            to
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error finding events: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let event_type = AnalysisEventType::from_str(&row.event_type).map_err(|_| {
                OrganizationError::InternalError {
                    message: format!("Invalid event type: {}", row.event_type),
                }
            })?;

            events.push(AnalysisEvent {
                id: row.id,
                organization_id: row.organization_id.map(OrganizationId::from),
                user_id: row.user_id.map(UserId::from),
                job_id: row.job_id,
                event_type,
                metadata: row.metadata,
                timestamp: row.timestamp,
            });
        }

        Ok(events)
    }

    async fn find_by_job(&self, job_id: Uuid) -> Result<Vec<AnalysisEvent>, OrganizationError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, organization_id, user_id, job_id, event_type, metadata, timestamp
            FROM analysis_events
            WHERE job_id = $1
            ORDER BY timestamp ASC
            "#,
            job_id
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error finding job events: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let event_type = AnalysisEventType::from_str(&row.event_type).map_err(|_| {
                OrganizationError::InternalError {
                    message: format!("Invalid event type: {}", row.event_type),
                }
            })?;

            events.push(AnalysisEvent {
                id: row.id,
                organization_id: row.organization_id.map(OrganizationId::from),
                user_id: row.user_id.map(UserId::from),
                job_id: row.job_id,
                event_type,
                metadata: row.metadata,
                timestamp: row.timestamp,
            });
        }

        Ok(events)
    }

    async fn count_by_type(
        &self,
        org_id: &OrganizationId,
        event_type: AnalysisEventType,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<i64, OrganizationError> {
        let org_uuid = org_id.as_uuid();
        let event_type_str = event_type.to_string();

        let result = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM analysis_events
            WHERE organization_id = $1 
              AND event_type = $2 
              AND timestamp >= $3 
              AND timestamp <= $4
            "#,
            org_uuid,
            event_type_str,
            from,
            to
        )
        .fetch_one(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error counting events: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(result)
    }

    async fn delete_older_than(&self, cutoff: DateTime<Utc>) -> Result<u64, OrganizationError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM analysis_events
            WHERE timestamp < $1
            "#,
            cutoff
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error deleting old events: {}", e);
            OrganizationError::DatabaseError {
                message: e.to_string(),
            }
        })?;

        Ok(result.rows_affected())
    }
}
