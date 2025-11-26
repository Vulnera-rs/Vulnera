//! Organization value objects

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

use crate::domain::auth::value_objects::UserId;

/// Organization ID value object
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OrganizationId(pub Uuid);

impl OrganizationId {
    /// Create a new OrganizationId from UUID
    pub fn new(id: Uuid) -> Self {
        Self(id)
    }

    /// Generate a new random OrganizationId
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Get as string
    pub fn as_str(&self) -> String {
        self.0.to_string()
    }
}

impl From<Uuid> for OrganizationId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<OrganizationId> for Uuid {
    fn from(org_id: OrganizationId) -> Self {
        org_id.0
    }
}

impl fmt::Display for OrganizationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Organization member value object
///
/// Represents a non-owner member of an organization.
/// The owner is tracked separately in `Organization.owner_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationMember {
    /// User ID of the member
    pub user_id: UserId,
    /// When the user joined the organization
    pub joined_at: DateTime<Utc>,
}

impl OrganizationMember {
    /// Create a new organization member
    pub fn new(user_id: UserId) -> Self {
        Self {
            user_id,
            joined_at: Utc::now(),
        }
    }

    /// Create a member with a specific join date (for DB hydration)
    pub fn with_joined_at(user_id: UserId, joined_at: DateTime<Utc>) -> Self {
        Self { user_id, joined_at }
    }
}

/// Organization name value object with validation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OrganizationName(String);

impl OrganizationName {
    /// Minimum name length
    pub const MIN_LENGTH: usize = 2;
    /// Maximum name length
    pub const MAX_LENGTH: usize = 100;

    /// Create a new OrganizationName with validation
    pub fn new(name: String) -> Result<Self, String> {
        let name = name.trim().to_string();

        if name.is_empty() {
            return Err("Organization name cannot be empty".to_string());
        }

        if name.len() < Self::MIN_LENGTH {
            return Err(format!(
                "Organization name must be at least {} characters",
                Self::MIN_LENGTH
            ));
        }

        if name.len() > Self::MAX_LENGTH {
            return Err(format!(
                "Organization name cannot exceed {} characters",
                Self::MAX_LENGTH
            ));
        }

        // Basic sanitization - allow alphanumeric, spaces, hyphens, underscores
        let valid_chars = name
            .chars()
            .all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_');

        if !valid_chars {
            return Err(
                "Organization name can only contain letters, numbers, spaces, hyphens, and underscores"
                    .to_string(),
            );
        }

        Ok(OrganizationName(name))
    }

    /// Get the inner string value
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get as owned string
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for OrganizationName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Subscription tier for an organization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionTier {
    /// Free tier - limited features
    #[default]
    Free,
    /// Starter tier - basic paid features
    Starter,
    /// Professional tier - advanced features
    Professional,
    /// Enterprise tier - all features + custom support
    Enterprise,
}

impl SubscriptionTier {
    /// Get default scan limit for this tier
    pub fn default_scan_limit(&self) -> u32 {
        match self {
            SubscriptionTier::Free => 5,
            SubscriptionTier::Starter => 500,
            SubscriptionTier::Professional => 2000,
            SubscriptionTier::Enterprise => u32::MAX, // Unlimited
        }
    }

    /// Get default API call limit for this tier
    pub fn default_api_call_limit(&self) -> u32 {
        match self {
            SubscriptionTier::Free => 1000,
            SubscriptionTier::Starter => 10_000,
            SubscriptionTier::Professional => 50_000,
            SubscriptionTier::Enterprise => u32::MAX, // Unlimited
        }
    }

    /// Get default member limit for this tier
    pub fn default_member_limit(&self) -> u32 {
        match self {
            SubscriptionTier::Free => 1,
            SubscriptionTier::Starter => 5,
            SubscriptionTier::Professional => 25,
            SubscriptionTier::Enterprise => u32::MAX, // Unlimited
        }
    }
}

impl fmt::Display for SubscriptionTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubscriptionTier::Free => write!(f, "free"),
            SubscriptionTier::Starter => write!(f, "starter"),
            SubscriptionTier::Professional => write!(f, "professional"),
            SubscriptionTier::Enterprise => write!(f, "enterprise"),
        }
    }
}

impl std::str::FromStr for SubscriptionTier {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "free" => Ok(SubscriptionTier::Free),
            "starter" => Ok(SubscriptionTier::Starter),
            "professional" => Ok(SubscriptionTier::Professional),
            "enterprise" => Ok(SubscriptionTier::Enterprise),
            _ => Err(format!("Unknown subscription tier: {}", s)),
        }
    }
}

/// Analysis event type for tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisEventType {
    /// Job was started
    JobStarted,
    /// Job completed successfully
    JobCompleted,
    /// Job failed
    JobFailed,
    /// Findings were recorded
    FindingsRecorded,
    /// API call was made
    ApiCallMade,
    /// Report was generated
    ReportGenerated,
}

impl fmt::Display for AnalysisEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnalysisEventType::JobStarted => write!(f, "job_started"),
            AnalysisEventType::JobCompleted => write!(f, "job_completed"),
            AnalysisEventType::JobFailed => write!(f, "job_failed"),
            AnalysisEventType::FindingsRecorded => write!(f, "findings_recorded"),
            AnalysisEventType::ApiCallMade => write!(f, "api_call_made"),
            AnalysisEventType::ReportGenerated => write!(f, "report_generated"),
        }
    }
}

impl std::str::FromStr for AnalysisEventType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "job_started" | "jobstarted" => Ok(AnalysisEventType::JobStarted),
            "job_completed" | "jobcompleted" => Ok(AnalysisEventType::JobCompleted),
            "job_failed" | "jobfailed" => Ok(AnalysisEventType::JobFailed),
            "findings_recorded" | "findingsrecorded" => Ok(AnalysisEventType::FindingsRecorded),
            "api_call_made" | "apicallmade" => Ok(AnalysisEventType::ApiCallMade),
            "report_generated" | "reportgenerated" => Ok(AnalysisEventType::ReportGenerated),
            _ => Err(format!("Unknown event type: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_organization_id() {
        let uuid = Uuid::new_v4();
        let org_id = OrganizationId::new(uuid);
        assert_eq!(org_id.as_uuid(), uuid);
        assert_eq!(OrganizationId::from(uuid), org_id);
    }

    #[test]
    fn test_organization_name_validation() {
        // Valid names
        assert!(OrganizationName::new("Acme Corp".to_string()).is_ok());
        assert!(OrganizationName::new("My-Team_123".to_string()).is_ok());
        assert!(OrganizationName::new("AB".to_string()).is_ok()); // Min length

        // Invalid names
        assert!(OrganizationName::new("".to_string()).is_err());
        assert!(OrganizationName::new("A".to_string()).is_err()); // Too short
        assert!(OrganizationName::new("Test@Org".to_string()).is_err()); // Invalid char
        assert!(OrganizationName::new("a".repeat(101)).is_err()); // Too long
    }

    #[test]
    fn test_organization_member() {
        let user_id = UserId::generate();
        let member = OrganizationMember::new(user_id);
        assert_eq!(member.user_id, user_id);
        assert!(member.joined_at <= Utc::now());
    }

    #[test]
    fn test_subscription_tier_defaults() {
        assert_eq!(SubscriptionTier::Free.default_scan_limit(), 5);
        assert_eq!(SubscriptionTier::Starter.default_scan_limit(), 500);
        assert_eq!(
            SubscriptionTier::Professional.default_api_call_limit(),
            50_000
        );
        assert_eq!(
            SubscriptionTier::Enterprise.default_member_limit(),
            u32::MAX
        );
    }

    #[test]
    fn test_subscription_tier_parsing() {
        assert_eq!(
            "free".parse::<SubscriptionTier>().unwrap(),
            SubscriptionTier::Free
        );
        assert_eq!(
            "STARTER".parse::<SubscriptionTier>().unwrap(),
            SubscriptionTier::Starter
        );
        assert!("invalid".parse::<SubscriptionTier>().is_err());
    }

    #[test]
    fn test_analysis_event_type_parsing() {
        assert_eq!(
            "job_started".parse::<AnalysisEventType>().unwrap(),
            AnalysisEventType::JobStarted
        );
        assert_eq!(
            "JobCompleted".parse::<AnalysisEventType>().unwrap(),
            AnalysisEventType::JobCompleted
        );
    }
}
