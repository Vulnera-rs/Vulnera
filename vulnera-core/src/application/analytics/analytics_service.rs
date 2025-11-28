//! Analytics aggregation service
//!
//! Provides dual-write capability: records events and maintains aggregates
//! for efficient dashboard queries. Supports both organization-level and
//! user-level (personal) analytics tracking.

use std::sync::Arc;

use chrono::{Datelike, Utc};
use tracing::{info, instrument};
use uuid::Uuid;

use crate::domain::auth::value_objects::UserId;
use crate::domain::organization::{
    entities::{AnalysisEvent, PersonalStatsMonthly, UserStatsMonthly},
    errors::OrganizationError,
    repositories::{
        IAnalysisEventRepository, IPersonalStatsMonthlyRepository, IUserStatsMonthlyRepository,
    },
    value_objects::{AnalysisEventType, OrganizationId, StatsSubject},
};

/// Analytics aggregation service that handles dual-write for events and stats
///
/// Supports both organization-level analytics (for teams) and personal analytics
/// (for individual users not in organizations).
pub struct AnalyticsAggregationService {
    events_repository: Arc<dyn IAnalysisEventRepository>,
    org_stats_repository: Arc<dyn IUserStatsMonthlyRepository>,
    personal_stats_repository: Arc<dyn IPersonalStatsMonthlyRepository>,
    enable_user_level_tracking: bool,
}

impl AnalyticsAggregationService {
    pub fn new(
        events_repository: Arc<dyn IAnalysisEventRepository>,
        org_stats_repository: Arc<dyn IUserStatsMonthlyRepository>,
        personal_stats_repository: Arc<dyn IPersonalStatsMonthlyRepository>,
        enable_user_level_tracking: bool,
    ) -> Self {
        Self {
            events_repository,
            org_stats_repository,
            personal_stats_repository,
            enable_user_level_tracking,
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
    /// Supports both organization and personal (user-level) stats tracking.
    #[instrument(skip(self, metadata), fields(subject = %subject, event_type = ?event_type))]
    pub async fn record_analysis_event(
        &self,
        subject: StatsSubject,
        user_id: Option<UserId>,
        job_id: Uuid,
        event_type: AnalysisEventType,
        metadata: serde_json::Value,
    ) -> Result<(), OrganizationError> {
        // Extract org_id and actual_user_id based on subject
        let (org_id, actual_user_id) = match &subject {
            StatsSubject::Organization(org) => (Some(*org), user_id),
            StatsSubject::User(uid) => (None, Some(*uid)),
        };

        // Create and store the event
        let event = AnalysisEvent::new(org_id, actual_user_id, Some(job_id), event_type, metadata);
        self.events_repository.record(&event).await?;

        let year_month = Self::current_year_month();

        // Update aggregate stats based on subject type and event
        match event_type {
            AnalysisEventType::JobStarted | AnalysisEventType::JobCompleted => {
                self.increment_scan_completed_for_subject(&subject, &year_month)
                    .await?;
            }
            AnalysisEventType::FindingsRecorded => {
                // Findings recorded is a general event - specific findings added via add_findings
            }
            AnalysisEventType::ReportGenerated => {
                // Could add reports_generated increment here
            }
            AnalysisEventType::ApiCallMade => {
                self.increment_api_calls_for_subject(&subject, &year_month, 1)
                    .await?;
            }
            AnalysisEventType::JobFailed => {
                // Could track failed scans
            }
        }

        info!("Recorded analysis event: {:?} for {}", event_type, subject);
        Ok(())
    }

    /// Internal helper to increment scan count based on subject type
    async fn increment_scan_completed_for_subject(
        &self,
        subject: &StatsSubject,
        year_month: &str,
    ) -> Result<(), OrganizationError> {
        match subject {
            StatsSubject::Organization(org_id) => {
                self.org_stats_repository
                    .increment_scan_completed(org_id, year_month)
                    .await
            }
            StatsSubject::User(user_id) => {
                if self.enable_user_level_tracking {
                    self.personal_stats_repository
                        .increment_scan_completed(user_id, year_month)
                        .await
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Internal helper to increment API calls based on subject type
    async fn increment_api_calls_for_subject(
        &self,
        subject: &StatsSubject,
        year_month: &str,
        count: u32,
    ) -> Result<(), OrganizationError> {
        match subject {
            StatsSubject::Organization(org_id) => {
                self.org_stats_repository
                    .increment_api_calls(org_id, year_month, count)
                    .await
            }
            StatsSubject::User(user_id) => {
                if self.enable_user_level_tracking {
                    self.personal_stats_repository
                        .increment_api_calls(user_id, year_month, count)
                        .await
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Internal helper to add findings based on subject type
    /// Note: When subject is Organization, we also track personal stats for the user if available
    async fn add_findings_for_subject(
        &self,
        subject: &StatsSubject,
        year_month: &str,
        critical: u32,
        high: u32,
        medium: u32,
        low: u32,
        info: u32,
    ) -> Result<(), OrganizationError> {
        match subject {
            StatsSubject::Organization(org_id) => {
                // Always track at organization level
                self.org_stats_repository
                    .add_findings(org_id, year_month, critical, high, medium, low, info)
                    .await
            }
            StatsSubject::User(user_id) => {
                if self.enable_user_level_tracking {
                    self.personal_stats_repository
                        .add_findings(user_id, year_month, critical, high, medium, low, info)
                        .await
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Batch record API calls (used for high-frequency operations)
    ///
    /// For very high-frequency events like API calls, this allows batching
    /// to reduce database pressure.
    #[instrument(skip(self), fields(subject = %subject, count = count))]
    pub async fn record_api_calls_batch(
        &self,
        subject: StatsSubject,
        count: u32,
    ) -> Result<(), OrganizationError> {
        let year_month = Self::current_year_month();
        self.increment_api_calls_for_subject(&subject, &year_month, count)
            .await
    }

    /// Records scan completion with findings breakdown
    /// When subject is Organization, also tracks personal stats if user_id is available
    #[instrument(skip(self), fields(subject = %subject, job_id = %job_id))]
    pub async fn record_scan_completed(
        &self,
        subject: StatsSubject,
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
            subject.clone(),
            user_id.clone(),
            job_id,
            AnalysisEventType::JobCompleted,
            metadata,
        )
        .await?;

        // Update findings aggregates
        let year_month = Self::current_year_month();
        self.add_findings_for_subject(
            &subject,
            &year_month,
            findings_critical,
            findings_high,
            findings_medium,
            findings_low,
            findings_info,
        )
        .await?;

        // Also track personal stats when subject is organization and user_id is available
        if let (StatsSubject::Organization(_), Some(user)) = (&subject, &user_id) {
            if self.enable_user_level_tracking {
                if let Err(e) = self
                    .add_findings_for_subject(
                        &StatsSubject::User(user.clone()),
                        &year_month,
                        findings_critical,
                        findings_high,
                        findings_medium,
                        findings_low,
                        findings_info,
                    )
                    .await
                {
                    // Log but don't fail - personal stats are secondary
                    tracing::warn!(
                        job_id = %job_id,
                        user_id = %user,
                        error = %e,
                        "Failed to record personal stats (non-fatal)"
                    );
                }
            }
        }

        Ok(())
    }

    /// Records scan failure
    #[instrument(skip(self), fields(subject = %subject, job_id = %job_id))]
    pub async fn record_scan_failed(
        &self,
        subject: StatsSubject,
        user_id: Option<UserId>,
        job_id: Uuid,
        reason: String,
    ) -> Result<(), OrganizationError> {
        let metadata = serde_json::json!({
            "error": reason,
            "timestamp": Utc::now().to_rfc3339()
        });

        self.record_analysis_event(
            subject,
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

    /// Get aggregate stats for organization for a time range (for dashboard)
    #[instrument(skip(self), fields(org_id = %org_id))]
    pub async fn get_org_stats_for_range(
        &self,
        org_id: OrganizationId,
        start_month: &str,
        end_month: &str,
    ) -> Result<Vec<UserStatsMonthly>, OrganizationError> {
        self.org_stats_repository
            .find_by_org_range(&org_id, start_month, end_month)
            .await
    }

    /// Get aggregate personal stats for a user for a time range (for dashboard)
    #[instrument(skip(self), fields(user_id = %user_id))]
    pub async fn get_personal_stats_for_range(
        &self,
        user_id: UserId,
        start_month: &str,
        end_month: &str,
    ) -> Result<Vec<PersonalStatsMonthly>, OrganizationError> {
        self.personal_stats_repository
            .find_by_user_range(&user_id, start_month, end_month)
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
/// on the analytics service. Uses `StatsSubject` to support both organization
/// and personal analytics tracking.
#[async_trait::async_trait]
pub trait AnalyticsRecorder: Send + Sync {
    /// Record a scan started event
    async fn on_scan_started(
        &self,
        subject: StatsSubject,
        user_id: Option<UserId>,
        job_id: Uuid,
    ) -> Result<(), OrganizationError>;

    /// Record a scan completed event with findings breakdown
    async fn on_scan_completed(
        &self,
        subject: StatsSubject,
        user_id: Option<UserId>,
        job_id: Uuid,
        findings_critical: u32,
        findings_high: u32,
        findings_medium: u32,
        findings_low: u32,
        findings_info: u32,
    ) -> Result<(), OrganizationError>;

    /// Record an API call
    async fn on_api_call(&self, subject: StatsSubject) -> Result<(), OrganizationError>;

    /// Record a report generated
    async fn on_report_generated(
        &self,
        subject: StatsSubject,
        user_id: Option<UserId>,
        job_id: Uuid,
    ) -> Result<(), OrganizationError>;
}

#[async_trait::async_trait]
impl AnalyticsRecorder for AnalyticsAggregationService {
    async fn on_scan_started(
        &self,
        subject: StatsSubject,
        user_id: Option<UserId>,
        job_id: Uuid,
    ) -> Result<(), OrganizationError> {
        self.record_analysis_event(
            subject,
            user_id,
            job_id,
            AnalysisEventType::JobStarted,
            serde_json::json!({}),
        )
        .await
    }

    async fn on_scan_completed(
        &self,
        subject: StatsSubject,
        user_id: Option<UserId>,
        job_id: Uuid,
        findings_critical: u32,
        findings_high: u32,
        findings_medium: u32,
        findings_low: u32,
        findings_info: u32,
    ) -> Result<(), OrganizationError> {
        self.record_scan_completed(
            subject,
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

    async fn on_api_call(&self, subject: StatsSubject) -> Result<(), OrganizationError> {
        self.record_api_calls_batch(subject, 1).await
    }

    async fn on_report_generated(
        &self,
        subject: StatsSubject,
        user_id: Option<UserId>,
        job_id: Uuid,
    ) -> Result<(), OrganizationError> {
        self.record_analysis_event(
            subject,
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
        _subject: StatsSubject,
        _user_id: Option<UserId>,
        _job_id: Uuid,
    ) -> Result<(), OrganizationError> {
        Ok(())
    }

    async fn on_scan_completed(
        &self,
        _subject: StatsSubject,
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

    async fn on_api_call(&self, _subject: StatsSubject) -> Result<(), OrganizationError> {
        Ok(())
    }

    async fn on_report_generated(
        &self,
        _subject: StatsSubject,
        _user_id: Option<UserId>,
        _job_id: Uuid,
    ) -> Result<(), OrganizationError> {
        Ok(())
    }
}
