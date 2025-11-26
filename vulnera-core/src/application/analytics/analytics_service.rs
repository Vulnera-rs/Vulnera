//! Analytics aggregation service
//!
//! Provides dual-write capability: records events and maintains aggregates
//! for efficient dashboard queries.

use std::sync::Arc;

use chrono::{Datelike, Utc};
use tracing::{info, instrument};
use uuid::Uuid;

use crate::domain::auth::value_objects::UserId;
use crate::domain::organization::{
    entities::{AnalysisEvent, UserStatsMonthly},
    errors::OrganizationError,
    repositories::{IAnalysisEventRepository, IUserStatsMonthlyRepository},
    value_objects::{AnalysisEventType, OrganizationId},
};

/// Analytics aggregation service that handles dual-write for events and stats
pub struct AnalyticsAggregationService {
    events_repository: Arc<dyn IAnalysisEventRepository>,
    stats_repository: Arc<dyn IUserStatsMonthlyRepository>,
}

impl AnalyticsAggregationService {
    pub fn new(
        events_repository: Arc<dyn IAnalysisEventRepository>,
        stats_repository: Arc<dyn IUserStatsMonthlyRepository>,
    ) -> Self {
        Self {
            events_repository,
            stats_repository,
        }
    }

    /// Get current year-month string in format "YYYY-MM"
    fn current_year_month() -> String {
        let now = Utc::now();
        format!("{:04}-{:02}", now.year(), now.month())
    }

    /// Records an analysis event and updates the corresponding monthly stats
    ///
    /// This implements dual-write: the event is stored for detailed querying,
    /// and the aggregate stats are updated for fast dashboard loading.
    #[instrument(skip(self, metadata), fields(org_id = %org_id, event_type = ?event_type))]
    pub async fn record_analysis_event(
        &self,
        org_id: OrganizationId,
        user_id: Option<UserId>,
        job_id: Uuid,
        event_type: AnalysisEventType,
        metadata: serde_json::Value,
    ) -> Result<(), OrganizationError> {
        // Create and store the event
        let event = AnalysisEvent::new(Some(org_id), user_id, Some(job_id), event_type, metadata);
        self.events_repository.record(&event).await?;

        let year_month = Self::current_year_month();

        // Update aggregate stats based on event type
        match event_type {
            AnalysisEventType::JobStarted | AnalysisEventType::JobCompleted => {
                self.stats_repository
                    .increment_scan_completed(&org_id, &year_month)
                    .await?;
            }
            AnalysisEventType::FindingsRecorded => {
                // Findings recorded is a general event - specific findings added via add_findings
            }
            AnalysisEventType::ReportGenerated => {
                // Could add reports_generated increment here
            }
            AnalysisEventType::ApiCallMade => {
                self.stats_repository
                    .increment_api_calls(&org_id, &year_month, 1)
                    .await?;
            }
            AnalysisEventType::JobFailed => {
                // Could track failed scans
            }
        }

        info!("Recorded analysis event: {:?}", event_type);
        Ok(())
    }

    /// Batch record API calls (used for high-frequency operations)
    ///
    /// For very high-frequency events like API calls, this allows batching
    /// to reduce database pressure.
    #[instrument(skip(self), fields(org_id = %org_id, count = count))]
    pub async fn record_api_calls_batch(
        &self,
        org_id: OrganizationId,
        count: u32,
    ) -> Result<(), OrganizationError> {
        let year_month = Self::current_year_month();

        self.stats_repository
            .increment_api_calls(&org_id, &year_month, count)
            .await?;

        Ok(())
    }

    /// Records scan completion with findings breakdown
    #[instrument(skip(self), fields(org_id = %org_id, job_id = %job_id))]
    pub async fn record_scan_completed(
        &self,
        org_id: OrganizationId,
        user_id: Option<UserId>,
        job_id: Uuid,
        findings_critical: u32,
        findings_high: u32,
        findings_medium: u32,
        findings_low: u32,
        findings_info: u32,
    ) -> Result<(), OrganizationError> {
        let metadata = serde_json::json!({
            "findings_critical": findings_critical,
            "findings_high": findings_high,
            "findings_medium": findings_medium,
            "findings_low": findings_low,
            "findings_info": findings_info,
            "total_findings": findings_critical + findings_high + findings_medium + findings_low + findings_info
        });

        // Record the event
        self.record_analysis_event(
            org_id,
            user_id,
            job_id,
            AnalysisEventType::JobCompleted,
            metadata,
        )
        .await?;

        // Update findings aggregates
        let year_month = Self::current_year_month();
        self.stats_repository
            .add_findings(
                &org_id,
                &year_month,
                findings_critical,
                findings_high,
                findings_medium,
                findings_low,
                findings_info,
            )
            .await?;

        Ok(())
    }

    /// Records scan failure
    #[instrument(skip(self), fields(org_id = %org_id, job_id = %job_id))]
    pub async fn record_scan_failed(
        &self,
        org_id: OrganizationId,
        user_id: Option<UserId>,
        job_id: Uuid,
        reason: String,
    ) -> Result<(), OrganizationError> {
        let metadata = serde_json::json!({
            "error": reason,
            "timestamp": Utc::now().to_rfc3339()
        });

        self.record_analysis_event(
            org_id,
            user_id,
            job_id,
            AnalysisEventType::JobFailed,
            metadata,
        )
        .await
    }

    /// Cleanup old events (for use by background job)
    ///
    /// Events older than 24 months are deleted to control storage growth.
    /// The aggregate stats remain for historical reporting.
    #[instrument(skip(self))]
    pub async fn cleanup_old_events(&self, months_to_keep: u32) -> Result<u64, OrganizationError> {
        let cutoff = Utc::now() - chrono::Duration::days((months_to_keep * 30) as i64);

        let deleted = self.events_repository.delete_older_than(cutoff).await?;

        if deleted > 0 {
            info!(
                "Cleaned up {} analysis events older than {} months",
                deleted, months_to_keep
            );
        }

        Ok(deleted)
    }

    /// Get aggregate stats for a time range (for dashboard)
    #[instrument(skip(self), fields(org_id = %org_id))]
    pub async fn get_stats_for_range(
        &self,
        org_id: OrganizationId,
        start_month: &str,
        end_month: &str,
    ) -> Result<Vec<UserStatsMonthly>, OrganizationError> {
        self.stats_repository
            .find_by_org_range(&org_id, start_month, end_month)
            .await
    }

    /// Get detailed events for a specific job (for job details page)
    #[instrument(skip(self), fields(job_id = %job_id))]
    pub async fn get_events_for_job(
        &self,
        job_id: Uuid,
    ) -> Result<Vec<AnalysisEvent>, OrganizationError> {
        self.events_repository.find_by_job(job_id).await
    }
}

/// Trait for components that need to record analytics events
///
/// This allows modules to record events without taking a direct dependency
/// on the analytics service.
#[async_trait::async_trait]
pub trait AnalyticsRecorder: Send + Sync {
    /// Record a scan started event
    async fn on_scan_started(
        &self,
        org_id: OrganizationId,
        user_id: Option<UserId>,
        job_id: Uuid,
    ) -> Result<(), OrganizationError>;

    /// Record a scan completed event with findings breakdown
    async fn on_scan_completed(
        &self,
        org_id: OrganizationId,
        user_id: Option<UserId>,
        job_id: Uuid,
        findings_critical: u32,
        findings_high: u32,
        findings_medium: u32,
        findings_low: u32,
        findings_info: u32,
    ) -> Result<(), OrganizationError>;

    /// Record an API call
    async fn on_api_call(&self, org_id: OrganizationId) -> Result<(), OrganizationError>;

    /// Record a report generated
    async fn on_report_generated(
        &self,
        org_id: OrganizationId,
        user_id: Option<UserId>,
        job_id: Uuid,
    ) -> Result<(), OrganizationError>;
}

#[async_trait::async_trait]
impl AnalyticsRecorder for AnalyticsAggregationService {
    async fn on_scan_started(
        &self,
        org_id: OrganizationId,
        user_id: Option<UserId>,
        job_id: Uuid,
    ) -> Result<(), OrganizationError> {
        self.record_analysis_event(
            org_id,
            user_id,
            job_id,
            AnalysisEventType::JobStarted,
            serde_json::json!({}),
        )
        .await
    }

    async fn on_scan_completed(
        &self,
        org_id: OrganizationId,
        user_id: Option<UserId>,
        job_id: Uuid,
        findings_critical: u32,
        findings_high: u32,
        findings_medium: u32,
        findings_low: u32,
        findings_info: u32,
    ) -> Result<(), OrganizationError> {
        self.record_scan_completed(
            org_id,
            user_id,
            job_id,
            findings_critical,
            findings_high,
            findings_medium,
            findings_low,
            findings_info,
        )
        .await
    }

    async fn on_api_call(&self, org_id: OrganizationId) -> Result<(), OrganizationError> {
        self.record_api_calls_batch(org_id, 1).await
    }

    async fn on_report_generated(
        &self,
        org_id: OrganizationId,
        user_id: Option<UserId>,
        job_id: Uuid,
    ) -> Result<(), OrganizationError> {
        self.record_analysis_event(
            org_id,
            user_id,
            job_id,
            AnalysisEventType::ReportGenerated,
            serde_json::json!({}),
        )
        .await
    }
}

/// No-op analytics recorder for testing or when analytics is disabled
pub struct NoOpAnalyticsRecorder;

#[async_trait::async_trait]
impl AnalyticsRecorder for NoOpAnalyticsRecorder {
    async fn on_scan_started(
        &self,
        _org_id: OrganizationId,
        _user_id: Option<UserId>,
        _job_id: Uuid,
    ) -> Result<(), OrganizationError> {
        Ok(())
    }

    async fn on_scan_completed(
        &self,
        _org_id: OrganizationId,
        _user_id: Option<UserId>,
        _job_id: Uuid,
        _findings_critical: u32,
        _findings_high: u32,
        _findings_medium: u32,
        _findings_low: u32,
        _findings_info: u32,
    ) -> Result<(), OrganizationError> {
        Ok(())
    }

    async fn on_api_call(&self, _org_id: OrganizationId) -> Result<(), OrganizationError> {
        Ok(())
    }

    async fn on_report_generated(
        &self,
        _org_id: OrganizationId,
        _user_id: Option<UserId>,
        _job_id: Uuid,
    ) -> Result<(), OrganizationError> {
        Ok(())
    }
}
