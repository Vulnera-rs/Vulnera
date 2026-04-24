//! Organization repository traits

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::domain::auth::value_objects::UserId;

use super::entities::{
    AnalysisEvent, Organization, PersonalStatsMonthly, SubscriptionLimits, UserStatsMonthly,
};
use super::errors::OrganizationError;
use super::value_objects::{AnalysisEventType, OrganizationId, OrganizationMember};

/// Organization repository trait for organization persistence
#[async_trait]
pub trait IOrganizationRepository: Send + Sync {
    /// Find an organization by ID
    async fn find_by_id(
        &self,
        org_id: &OrganizationId,
    ) -> Result<Option<Organization>, OrganizationError>;

    /// Find an organization by owner ID and name
    async fn find_by_owner_and_name(
        &self,
        owner_id: &UserId,
        name: &str,
    ) -> Result<Option<Organization>, OrganizationError>;

    /// Find all organizations owned by a user
    async fn find_by_owner_id(
        &self,
        owner_id: &UserId,
    ) -> Result<Vec<Organization>, OrganizationError>;

    /// Create a new organization
    async fn create(&self, org: &Organization) -> Result<(), OrganizationError>;

    /// Update an existing organization
    async fn update(&self, org: &Organization) -> Result<(), OrganizationError>;

    /// Delete an organization by ID
    async fn delete(&self, org_id: &OrganizationId) -> Result<(), OrganizationError>;

    /// List all organizations (admin only, paginated)
    async fn list_all(
        &self,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<Organization>, OrganizationError>;

    /// Count total organizations
    async fn count_all(&self) -> Result<i64, OrganizationError>;
}

/// Organization member repository trait for membership persistence
#[async_trait]
pub trait IOrganizationMemberRepository: Send + Sync {
    /// Add a member to an organization
    async fn add_member(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<(), OrganizationError>;

    /// Remove a member from an organization
    async fn remove_member(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<(), OrganizationError>;

    /// Find all members of an organization
    async fn find_by_organization(
        &self,
        org_id: &OrganizationId,
    ) -> Result<Vec<OrganizationMember>, OrganizationError>;

    /// Find all organizations a user is a member of (not owner)
    async fn find_organizations_by_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<OrganizationId>, OrganizationError>;

    /// Check if a user is a member of an organization
    async fn is_member(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<bool, OrganizationError>;

    /// Get member count for an organization
    async fn count_members(&self, org_id: &OrganizationId) -> Result<i64, OrganizationError>;
}

/// User stats monthly repository trait
#[async_trait]
pub trait IUserStatsMonthlyRepository: Send + Sync {
    /// Find stats for an organization and month
    async fn find_by_org_and_month(
        &self,
        org_id: &OrganizationId,
        year_month: &str,
    ) -> Result<Option<UserStatsMonthly>, OrganizationError>;

    /// Get stats for an organization over multiple months
    async fn find_by_org_range(
        &self,
        org_id: &OrganizationId,
        from_month: &str,
        to_month: &str,
    ) -> Result<Vec<UserStatsMonthly>, OrganizationError>;

    /// Create or update stats (upsert)
    async fn upsert(&self, stats: &UserStatsMonthly) -> Result<(), OrganizationError>;

    /// Increment scan count for current month
    async fn increment_scan_completed(
        &self,
        org_id: &OrganizationId,
        year_month: &str,
    ) -> Result<(), OrganizationError>;

    /// Increment API call count for current month
    async fn increment_api_calls(
        &self,
        org_id: &OrganizationId,
        year_month: &str,
        count: u32,
    ) -> Result<(), OrganizationError>;

    /// Add findings for current month
    async fn add_findings(
        &self,
        org_id: &OrganizationId,
        year_month: &str,
        critical: u32,
        high: u32,
        medium: u32,
        low: u32,
        info: u32,
    ) -> Result<(), OrganizationError>;
}

/// Personal (user-level) monthly stats repository trait
///
/// This tracks analytics for individual users independent of organizations.
/// Users can have personal stats even without belonging to any organization.
#[async_trait]
pub trait IPersonalStatsMonthlyRepository: Send + Sync {
    /// Find stats for a user in a specific month
    async fn find_by_user_and_month(
        &self,
        user_id: &UserId,
        year_month: &str,
    ) -> Result<Option<PersonalStatsMonthly>, OrganizationError>;

    /// Find stats for a user within a month range
    async fn find_by_user_range(
        &self,
        user_id: &UserId,
        from_month: &str,
        to_month: &str,
    ) -> Result<Vec<PersonalStatsMonthly>, OrganizationError>;

    /// Upsert monthly stats for a user
    async fn upsert(&self, stats: &PersonalStatsMonthly) -> Result<(), OrganizationError>;

    /// Increment scan count for current month
    async fn increment_scan_completed(
        &self,
        user_id: &UserId,
        year_month: &str,
    ) -> Result<(), OrganizationError>;

    /// Increment API call count for current month
    async fn increment_api_calls(
        &self,
        user_id: &UserId,
        year_month: &str,
        count: u32,
    ) -> Result<(), OrganizationError>;

    /// Add findings for current month
    async fn add_findings(
        &self,
        user_id: &UserId,
        year_month: &str,
        critical: u32,
        high: u32,
        medium: u32,
        low: u32,
        info: u32,
    ) -> Result<(), OrganizationError>;
}

/// Subscription limits repository trait
#[async_trait]
pub trait ISubscriptionLimitsRepository: Send + Sync {
    /// Find subscription limits for an organization
    async fn find_by_org(
        &self,
        org_id: &OrganizationId,
    ) -> Result<Option<SubscriptionLimits>, OrganizationError>;

    /// Create subscription limits
    async fn create(&self, limits: &SubscriptionLimits) -> Result<(), OrganizationError>;

    /// Update subscription limits
    async fn update(&self, limits: &SubscriptionLimits) -> Result<(), OrganizationError>;

    /// Delete subscription limits
    async fn delete(&self, org_id: &OrganizationId) -> Result<(), OrganizationError>;
}

/// Analysis events repository trait for time-series event tracking
#[async_trait]
pub trait IAnalysisEventRepository: Send + Sync {
    /// Record a new analysis event
    async fn record(&self, event: &AnalysisEvent) -> Result<(), OrganizationError>;

    /// Find events for an organization within a time range
    async fn find_by_org_and_range(
        &self,
        org_id: &OrganizationId,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<AnalysisEvent>, OrganizationError>;

    /// Find events for a specific job
    async fn find_by_job(&self, job_id: Uuid) -> Result<Vec<AnalysisEvent>, OrganizationError>;

    /// Count events by type for an organization within a time range
    async fn count_by_type(
        &self,
        org_id: &OrganizationId,
        event_type: AnalysisEventType,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<i64, OrganizationError>;

    /// Delete events older than a given timestamp (cleanup)
    async fn delete_older_than(&self, cutoff: DateTime<Utc>) -> Result<u64, OrganizationError>;
}

/// Persisted job results repository trait for long-term storage
#[async_trait]
pub trait IPersistedJobResultRepository: Send + Sync {
    /// Save a job result
    async fn save(&self, job: &PersistedJobResult) -> Result<(), OrganizationError>;

    /// Find a job result by ID
    async fn find_by_id(
        &self,
        job_id: Uuid,
    ) -> Result<Option<PersistedJobResult>, OrganizationError>;

    /// Find job results for an organization (paginated)
    async fn find_by_org(
        &self,
        org_id: &OrganizationId,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<PersistedJobResult>, OrganizationError>;

    /// Find job results for a user (paginated)
    async fn find_by_user(
        &self,
        user_id: &UserId,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<PersistedJobResult>, OrganizationError>;

    /// Count job results for an organization
    async fn count_by_org(&self, org_id: &OrganizationId) -> Result<i64, OrganizationError>;

    /// Delete a job result
    async fn delete(&self, job_id: Uuid) -> Result<(), OrganizationError>;
}

/// Persisted job result entity (stored in PostgreSQL for long-term access)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedJobResult {
    /// Job ID (same as AnalysisJob.job_id)
    pub job_id: Uuid,
    /// Organization (if authenticated)
    pub organization_id: Option<OrganizationId>,
    /// User who initiated the job (if authenticated)
    pub user_id: Option<UserId>,
    /// Project identifier
    pub project_id: String,
    /// Source type (git, file_upload, etc.)
    pub source_type: String,
    /// Source URI
    pub source_uri: String,
    /// Job status
    pub status: String,
    /// All findings (JSONB)
    pub findings_json: serde_json::Value,
    /// Module results (JSONB)
    pub module_results_json: serde_json::Value,
    /// Summary (JSONB)
    pub summary_json: Option<serde_json::Value>,
    /// Findings by type (JSONB)
    pub findings_by_type_json: Option<serde_json::Value>,
    /// Total findings count
    pub total_findings: u32,
    /// Critical findings
    pub findings_critical: u32,
    /// High findings
    pub findings_high: u32,
    /// Medium findings
    pub findings_medium: u32,
    /// Low findings
    pub findings_low: u32,
    /// Info findings
    pub findings_info: u32,
    /// When the job was created
    pub created_at: DateTime<Utc>,
    /// When the job started
    pub started_at: Option<DateTime<Utc>>,
    /// When the job completed
    pub completed_at: Option<DateTime<Utc>>,
    /// Error message (if failed)
    pub error_message: Option<String>,
}

impl PersistedJobResult {
    /// Create a new persisted job result
    pub fn new(
        job_id: Uuid,
        organization_id: Option<OrganizationId>,
        user_id: Option<UserId>,
        project_id: String,
        source_type: String,
        source_uri: String,
    ) -> Self {
        Self {
            job_id,
            organization_id,
            user_id,
            project_id,
            source_type,
            source_uri,
            status: "Pending".to_string(),
            findings_json: serde_json::json!([]),
            module_results_json: serde_json::json!([]),
            summary_json: None,
            findings_by_type_json: None,
            total_findings: 0,
            findings_critical: 0,
            findings_high: 0,
            findings_medium: 0,
            findings_low: 0,
            findings_info: 0,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            error_message: None,
        }
    }
}
