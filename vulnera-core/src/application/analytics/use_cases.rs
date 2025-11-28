//! Analytics use cases
//!
//! Application-level use cases for dashboard and analytics operations.

use std::sync::Arc;

use chrono::{Datelike, Utc};
use tracing::instrument;

use crate::domain::organization::{
    Organization,
    entities::{SubscriptionLimits, UserStatsMonthly},
    errors::OrganizationError,
    repositories::{
        IOrganizationRepository, IPersistedJobResultRepository, ISubscriptionLimitsRepository,
        IUserStatsMonthlyRepository, PersistedJobResult,
    },
    value_objects::{OrganizationId, SubscriptionTier},
};

/// Dashboard overview data for an organization
#[derive(Debug, Clone)]
pub struct DashboardOverview {
    pub organization: Organization,
    pub current_month_stats: Option<UserStatsMonthly>,
    pub previous_month_stats: Option<UserStatsMonthly>,
    pub subscription_limits: Option<SubscriptionLimits>,
    pub recent_jobs: Vec<PersistedJobResult>,
    pub quota_usage: QuotaUsage,
}

/// Quota usage summary
#[derive(Debug, Clone)]
pub struct QuotaUsage {
    pub scans_used: u32,
    pub scans_limit: Option<u32>,
    pub scans_percentage: f64,
    pub api_calls_used: u32,
    pub api_calls_limit: Option<u32>,
    pub api_calls_percentage: f64,
    pub is_over_quota: bool,
}

/// Monthly analytics summary
#[derive(Debug, Clone)]
pub struct MonthlyAnalytics {
    pub year_month: String,
    pub total_scans: u32,
    pub total_findings: u32,
    pub findings_by_severity: FindingsBySeverity,
    pub total_reports: u32,
    pub total_api_calls: u32,
}

#[derive(Debug, Clone)]
pub struct FindingsBySeverity {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

/// Use case for getting dashboard overview
pub struct GetDashboardOverviewUseCase {
    org_repository: Arc<dyn IOrganizationRepository>,
    stats_repository: Arc<dyn IUserStatsMonthlyRepository>,
    limits_repository: Arc<dyn ISubscriptionLimitsRepository>,
    job_repository: Arc<dyn IPersistedJobResultRepository>,
}

impl GetDashboardOverviewUseCase {
    pub fn new(
        org_repository: Arc<dyn IOrganizationRepository>,
        stats_repository: Arc<dyn IUserStatsMonthlyRepository>,
        limits_repository: Arc<dyn ISubscriptionLimitsRepository>,
        job_repository: Arc<dyn IPersistedJobResultRepository>,
    ) -> Self {
        Self {
            org_repository,
            stats_repository,
            limits_repository,
            job_repository,
        }
    }

    #[instrument(skip(self), fields(org_id = %org_id))]
    pub async fn execute(
        &self,
        org_id: OrganizationId,
    ) -> Result<DashboardOverview, OrganizationError> {
        // Fetch organization
        let organization =
            self.org_repository
                .find_by_id(&org_id)
                .await?
                .ok_or(OrganizationError::NotFound {
                    id: org_id.to_string(),
                })?;

        // Get current month stats
        let now = Utc::now();
        let current_month = format!("{:04}-{:02}", now.year(), now.month());
        let current_month_stats = self
            .stats_repository
            .find_by_org_and_month(&org_id, &current_month)
            .await?;

        // Get previous month stats for trend calculation
        let prev_month_date = now
            .checked_sub_months(chrono::Months::new(1))
            .unwrap_or(now);
        let previous_month = format!(
            "{:04}-{:02}",
            prev_month_date.year(),
            prev_month_date.month()
        );
        let previous_month_stats = self
            .stats_repository
            .find_by_org_and_month(&org_id, &previous_month)
            .await?;

        // Get subscription limits
        let subscription_limits = self.limits_repository.find_by_org(&org_id).await?;

        // Get recent jobs (last 10)
        let recent_jobs = self.job_repository.find_by_org(&org_id, 0, 10).await?;

        // Calculate quota usage
        let quota_usage = calculate_quota_usage(&current_month_stats, &subscription_limits);

        Ok(DashboardOverview {
            organization,
            current_month_stats,
            previous_month_stats,
            subscription_limits,
            recent_jobs,
            quota_usage,
        })
    }
}

/// Use case for getting monthly analytics
pub struct GetMonthlyAnalyticsUseCase {
    stats_repository: Arc<dyn IUserStatsMonthlyRepository>,
}

impl GetMonthlyAnalyticsUseCase {
    pub fn new(stats_repository: Arc<dyn IUserStatsMonthlyRepository>) -> Self {
        Self { stats_repository }
    }

    #[instrument(skip(self), fields(org_id = %org_id))]
    pub async fn execute(
        &self,
        org_id: OrganizationId,
        start_month: &str,
        end_month: &str,
    ) -> Result<Vec<MonthlyAnalytics>, OrganizationError> {
        let stats = self
            .stats_repository
            .find_by_org_range(&org_id, start_month, end_month)
            .await?;

        let analytics: Vec<MonthlyAnalytics> = stats
            .into_iter()
            .map(|s| MonthlyAnalytics {
                year_month: s.year_month.clone(),
                total_scans: s.scans_completed,
                total_findings: s.findings_count,
                findings_by_severity: FindingsBySeverity {
                    critical: s.findings_critical,
                    high: s.findings_high,
                    medium: s.findings_medium,
                    low: s.findings_low,
                    info: s.findings_info,
                },
                total_reports: s.reports_generated,
                total_api_calls: s.api_calls_used,
            })
            .collect();

        Ok(analytics)
    }
}

/// Use case for checking quota limits before operations
pub struct CheckQuotaUseCase {
    stats_repository: Arc<dyn IUserStatsMonthlyRepository>,
    limits_repository: Arc<dyn ISubscriptionLimitsRepository>,
}

impl CheckQuotaUseCase {
    pub fn new(
        stats_repository: Arc<dyn IUserStatsMonthlyRepository>,
        limits_repository: Arc<dyn ISubscriptionLimitsRepository>,
    ) -> Self {
        Self {
            stats_repository,
            limits_repository,
        }
    }

    /// Check if the organization can perform a scan
    #[instrument(skip(self), fields(org_id = %org_id))]
    pub async fn can_perform_scan(
        &self,
        org_id: OrganizationId,
    ) -> Result<bool, OrganizationError> {
        let now = Utc::now();
        let current_month = format!("{:04}-{:02}", now.year(), now.month());

        let stats = self
            .stats_repository
            .find_by_org_and_month(&org_id, &current_month)
            .await?;

        let limits = self.limits_repository.find_by_org(&org_id).await?;

        // If no limits set (free tier or unlimited), allow
        let Some(limits) = limits else {
            return Ok(true);
        };

        let current_scans = stats.map(|s| s.scans_completed).unwrap_or(0);
        let max_scans = limits.max_scans_monthly;

        // Allow if within limit
        Ok(current_scans < max_scans)
    }

    /// Check if the organization can make API calls
    #[instrument(skip(self), fields(org_id = %org_id))]
    pub async fn can_make_api_call(
        &self,
        org_id: OrganizationId,
    ) -> Result<bool, OrganizationError> {
        let now = Utc::now();
        let current_month = format!("{:04}-{:02}", now.year(), now.month());

        let stats = self
            .stats_repository
            .find_by_org_and_month(&org_id, &current_month)
            .await?;

        let limits = self.limits_repository.find_by_org(&org_id).await?;

        let Some(limits) = limits else {
            return Ok(true);
        };

        let current_calls = stats.map(|s| s.api_calls_used).unwrap_or(0);
        let max_calls = limits.max_api_calls_monthly;

        Ok(current_calls < max_calls)
    }

    /// Get detailed quota status
    #[instrument(skip(self), fields(org_id = %org_id))]
    pub async fn get_quota_status(
        &self,
        org_id: OrganizationId,
    ) -> Result<QuotaUsage, OrganizationError> {
        let now = Utc::now();
        let current_month = format!("{:04}-{:02}", now.year(), now.month());

        let stats = self
            .stats_repository
            .find_by_org_and_month(&org_id, &current_month)
            .await?;

        let limits = self.limits_repository.find_by_org(&org_id).await?;

        Ok(calculate_quota_usage(&stats, &limits))
    }
}

/// Use case for initializing subscription limits for a new organization
pub struct InitializeSubscriptionUseCase {
    limits_repository: Arc<dyn ISubscriptionLimitsRepository>,
}

impl InitializeSubscriptionUseCase {
    pub fn new(limits_repository: Arc<dyn ISubscriptionLimitsRepository>) -> Self {
        Self { limits_repository }
    }

    /// Initialize subscription limits for a new organization with default free tier
    #[instrument(skip(self), fields(org_id = %org_id))]
    pub async fn execute(
        &self,
        org_id: OrganizationId,
        tier: Option<SubscriptionTier>,
    ) -> Result<SubscriptionLimits, OrganizationError> {
        let tier = tier.unwrap_or(SubscriptionTier::Free);
        let limits = create_default_limits(org_id, tier);

        self.limits_repository.create(&limits).await?;

        Ok(limits)
    }
}

// Helper function to calculate quota usage
fn calculate_quota_usage(
    stats: &Option<UserStatsMonthly>,
    limits: &Option<SubscriptionLimits>,
) -> QuotaUsage {
    let scans_used = stats.as_ref().map(|s| s.scans_completed).unwrap_or(0);
    let api_calls_used = stats.as_ref().map(|s| s.api_calls_used).unwrap_or(0);

    let scans_limit = limits.as_ref().map(|l| l.max_scans_monthly);
    let api_calls_limit = limits.as_ref().map(|l| l.max_api_calls_monthly);

    let scans_percentage = scans_limit
        .map(|limit| (scans_used as f64 / limit as f64) * 100.0)
        .unwrap_or(0.0);

    let api_calls_percentage = api_calls_limit
        .map(|limit| (api_calls_used as f64 / limit as f64) * 100.0)
        .unwrap_or(0.0);

    let is_over_quota = scans_limit.map(|l| scans_used > l).unwrap_or(false)
        || api_calls_limit.map(|l| api_calls_used > l).unwrap_or(false);

    QuotaUsage {
        scans_used,
        scans_limit,
        scans_percentage,
        api_calls_used,
        api_calls_limit,
        api_calls_percentage,
        is_over_quota,
    }
}

// Helper to create default limits based on tier
fn create_default_limits(org_id: OrganizationId, tier: SubscriptionTier) -> SubscriptionLimits {
    let mut limits = SubscriptionLimits::new_free(org_id);
    if tier != SubscriptionTier::Free {
        limits.upgrade_tier(tier);
    }
    limits
}
