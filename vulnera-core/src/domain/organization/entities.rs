//! Organization domain entities

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::auth::value_objects::UserId;

use super::errors::OrganizationError;
use super::value_objects::{
    OrganizationId, OrganizationMember, OrganizationName, SubscriptionTier,
};

/// Organization aggregate root
///
/// Represents a team organization for grouping users and tracking usage/analytics.
/// Each organization has exactly one owner (who has full control) and zero or more members.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    /// Unique organization identifier
    pub id: OrganizationId,
    /// User who owns this organization (has full control)
    pub owner_id: UserId,
    /// Organization display name
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// Members of the organization (excludes owner)
    #[serde(skip)]
    pub members: Vec<OrganizationMember>,
    /// Account creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

impl Organization {
    /// Create a new organization
    pub fn new(owner_id: UserId, name: OrganizationName) -> Self {
        let now = Utc::now();
        Self {
            id: OrganizationId::generate(),
            owner_id,
            name: name.into_string(),
            description: None,
            members: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Create an organization with a specific ID
    pub fn with_id(
        id: OrganizationId,
        owner_id: UserId,
        name: String,
        description: Option<String>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            owner_id,
            name,
            description,
            members: Vec::new(),
            created_at,
            updated_at,
        }
    }

    /// Set description
    pub fn set_description(&mut self, description: Option<String>) {
        self.description = description;
        self.updated_at = Utc::now();
    }

    /// Update organization name
    pub fn update_name(&mut self, name: OrganizationName) {
        self.name = name.into_string();
        self.updated_at = Utc::now();
    }

    /// Check if a user is the owner
    pub fn is_owner(&self, user_id: &UserId) -> bool {
        self.owner_id == *user_id
    }

    /// Check if a user is a member (not owner)
    pub fn is_member(&self, user_id: &UserId) -> bool {
        self.members.iter().any(|m| m.user_id == *user_id)
    }

    /// Check if a user belongs to this organization (owner or member)
    pub fn belongs_to(&self, user_id: &UserId) -> bool {
        self.is_owner(user_id) || self.is_member(user_id)
    }

    /// Check if a user can manage members (only owner can)
    pub fn can_manage_members(&self, user_id: &UserId) -> bool {
        self.is_owner(user_id)
    }

    /// Add a member to the organization
    ///
    /// Only the owner can add members. Returns error if:
    /// - The user is already a member or owner
    /// - The caller is not the owner (checked at use case level)
    pub fn add_member(&mut self, user_id: UserId) -> Result<(), OrganizationError> {
        // Cannot add owner as member
        if self.is_owner(&user_id) {
            return Err(OrganizationError::AlreadyMember {
                user_id: user_id.to_string(),
                org_id: self.id.to_string(),
            });
        }

        // Cannot add existing member
        if self.is_member(&user_id) {
            return Err(OrganizationError::AlreadyMember {
                user_id: user_id.to_string(),
                org_id: self.id.to_string(),
            });
        }

        self.members.push(OrganizationMember::new(user_id));
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Remove a member from the organization
    ///
    /// Cannot remove the owner. Returns error if:
    /// - The user is the owner
    /// - The user is not a member
    pub fn remove_member(&mut self, user_id: &UserId) -> Result<(), OrganizationError> {
        // Cannot remove owner
        if self.is_owner(user_id) {
            return Err(OrganizationError::CannotRemoveOwner);
        }

        // Check if user is a member
        if !self.is_member(user_id) {
            return Err(OrganizationError::NotAMember {
                user_id: user_id.to_string(),
                org_id: self.id.to_string(),
            });
        }

        self.members.retain(|m| m.user_id != *user_id);
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Get all members (excluding owner)
    pub fn get_members(&self) -> &[OrganizationMember] {
        &self.members
    }

    /// Get total member count (including owner)
    pub fn total_members(&self) -> usize {
        self.members.len() + 1 // +1 for owner
    }

    /// Set members list (for DB hydration)
    pub fn set_members(&mut self, members: Vec<OrganizationMember>) {
        self.members = members;
    }

    /// Transfer ownership to another user
    ///
    /// The new owner must be a current member. The old owner becomes a member.
    pub fn transfer_ownership(&mut self, new_owner_id: UserId) -> Result<(), OrganizationError> {
        // New owner must be a current member
        if !self.is_member(&new_owner_id) {
            return Err(OrganizationError::NotAMember {
                user_id: new_owner_id.to_string(),
                org_id: self.id.to_string(),
            });
        }

        // Remove new owner from members
        self.members.retain(|m| m.user_id != new_owner_id);

        // Add old owner as member
        let old_owner_id = self.owner_id;
        self.members.push(OrganizationMember::new(old_owner_id));

        // Set new owner
        self.owner_id = new_owner_id;
        self.updated_at = Utc::now();

        Ok(())
    }
}

/// Monthly statistics for an organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserStatsMonthly {
    /// Unique identifier
    pub id: Uuid,
    /// Organization this stats belong to
    pub organization_id: OrganizationId,
    /// Year-month key (format: YYYY-MM)
    pub year_month: String,

    /// Total findings discovered
    pub findings_count: u32,
    /// Critical severity findings
    pub findings_critical: u32,
    /// High severity findings
    pub findings_high: u32,
    /// Medium severity findings
    pub findings_medium: u32,
    /// Low severity findings
    pub findings_low: u32,
    /// Info severity findings
    pub findings_info: u32,

    /// Reports generated
    pub reports_generated: u32,
    /// API calls made
    pub api_calls_used: u32,
    /// Scans completed successfully
    pub scans_completed: u32,
    /// Scans that failed
    pub scans_failed: u32,

    /// SAST module findings
    pub sast_findings: u32,
    /// Secrets module findings
    pub secrets_findings: u32,
    /// Dependency module findings
    pub dependency_findings: u32,
    /// API security module findings
    pub api_findings: u32,

    /// Record creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

impl UserStatsMonthly {
    /// Create new monthly stats for an organization
    pub fn new(organization_id: OrganizationId, year_month: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            organization_id,
            year_month,
            findings_count: 0,
            findings_critical: 0,
            findings_high: 0,
            findings_medium: 0,
            findings_low: 0,
            findings_info: 0,
            reports_generated: 0,
            api_calls_used: 0,
            scans_completed: 0,
            scans_failed: 0,
            sast_findings: 0,
            secrets_findings: 0,
            dependency_findings: 0,
            api_findings: 0,
            created_at: now,
            updated_at: now,
        }
    }

    /// Increment scan completed count
    pub fn increment_scans_completed(&mut self) {
        self.scans_completed += 1;
        self.updated_at = Utc::now();
    }

    /// Increment scan failed count
    pub fn increment_scans_failed(&mut self) {
        self.scans_failed += 1;
        self.updated_at = Utc::now();
    }

    /// Increment API calls
    pub fn increment_api_calls(&mut self, count: u32) {
        self.api_calls_used += count;
        self.updated_at = Utc::now();
    }

    /// Increment reports generated
    pub fn increment_reports(&mut self) {
        self.reports_generated += 1;
        self.updated_at = Utc::now();
    }

    /// Add findings by severity
    pub fn add_findings(&mut self, critical: u32, high: u32, medium: u32, low: u32, info: u32) {
        self.findings_critical += critical;
        self.findings_high += high;
        self.findings_medium += medium;
        self.findings_low += low;
        self.findings_info += info;
        self.findings_count += critical + high + medium + low + info;
        self.updated_at = Utc::now();
    }

    /// Add findings by module type
    pub fn add_module_findings(&mut self, sast: u32, secrets: u32, dependency: u32, api: u32) {
        self.sast_findings += sast;
        self.secrets_findings += secrets;
        self.dependency_findings += dependency;
        self.api_findings += api;
        self.updated_at = Utc::now();
    }
}

/// Subscription limits for an organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionLimits {
    /// Unique identifier
    pub id: Uuid,
    /// Organization this limit belongs to
    pub organization_id: OrganizationId,
    /// Subscription tier
    pub tier: SubscriptionTier,
    /// Maximum scans per month
    pub max_scans_monthly: u32,
    /// Maximum API calls per month
    pub max_api_calls_monthly: u32,
    /// Maximum members
    pub max_members: u32,
    /// Maximum repositories
    pub max_repos: u32,
    /// Maximum private repositories
    pub max_private_repos: u32,
    /// Scan results retention days
    pub scan_results_retention_days: u32,
    /// Feature flags (extensible)
    pub features: serde_json::Value,
    /// Record creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

impl SubscriptionLimits {
    /// Create new subscription limits for an organization with default free tier
    pub fn new_free(organization_id: OrganizationId) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            organization_id,
            tier: SubscriptionTier::Free,
            max_scans_monthly: SubscriptionTier::Free.default_scan_limit(),
            max_api_calls_monthly: SubscriptionTier::Free.default_api_call_limit(),
            max_members: SubscriptionTier::Free.default_member_limit(),
            max_repos: 3,
            max_private_repos: 0,
            scan_results_retention_days: 30,
            features: serde_json::json!({
                "dependency_analysis": true,
                "sast": false,
                "secrets_detection": false,
                "api_security": false,
                "custom_rules": false,
                "priority_support": false,
                "sso": false,
                "compliance_reports": false
            }),
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if a feature is enabled
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features
            .get(feature)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// Upgrade to a new tier
    pub fn upgrade_tier(&mut self, tier: SubscriptionTier) {
        self.tier = tier;
        self.max_scans_monthly = tier.default_scan_limit();
        self.max_api_calls_monthly = tier.default_api_call_limit();
        self.max_members = tier.default_member_limit();

        // Update features based on tier
        self.features = match tier {
            SubscriptionTier::Free => serde_json::json!({
                "dependency_analysis": true,
                "sast": false,
                "secrets_detection": false,
                "api_security": false,
                "custom_rules": false,
                "priority_support": false,
                "sso": false,
                "compliance_reports": false
            }),
            SubscriptionTier::Starter => serde_json::json!({
                "dependency_analysis": true,
                "sast": true,
                "secrets_detection": true,
                "api_security": true,
                "custom_rules": false,
                "priority_support": false,
                "sso": false,
                "compliance_reports": false
            }),
            SubscriptionTier::Professional => serde_json::json!({
                "dependency_analysis": true,
                "sast": true,
                "secrets_detection": true,
                "api_security": true,
                "custom_rules": true,
                "priority_support": true,
                "sso": false,
                "compliance_reports": true
            }),
            SubscriptionTier::Enterprise => serde_json::json!({
                "dependency_analysis": true,
                "sast": true,
                "secrets_detection": true,
                "api_security": true,
                "custom_rules": true,
                "priority_support": true,
                "sso": true,
                "compliance_reports": true
            }),
        };

        self.updated_at = Utc::now();
    }
}

/// Analysis event for time-series tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisEvent {
    /// Unique identifier
    pub id: Uuid,
    /// Organization this event belongs to
    pub organization_id: Option<OrganizationId>,
    /// User who triggered the event
    pub user_id: Option<UserId>,
    /// Job ID (if applicable)
    pub job_id: Option<Uuid>,
    /// Event type
    pub event_type: super::value_objects::AnalysisEventType,
    /// Event metadata
    pub metadata: serde_json::Value,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
}

impl AnalysisEvent {
    /// Create a new analysis event
    pub fn new(
        organization_id: Option<OrganizationId>,
        user_id: Option<UserId>,
        job_id: Option<Uuid>,
        event_type: super::value_objects::AnalysisEventType,
        metadata: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            organization_id,
            user_id,
            job_id,
            event_type,
            metadata,
            timestamp: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_organization_creation() {
        let owner_id = UserId::generate();
        let name = OrganizationName::new("Acme Corp".to_string()).unwrap();
        let org = Organization::new(owner_id, name);

        assert!(org.is_owner(&owner_id));
        assert!(org.belongs_to(&owner_id));
        assert!(!org.is_member(&owner_id)); // Owner is not in members list
        assert_eq!(org.total_members(), 1);
        assert!(org.can_manage_members(&owner_id));
    }

    #[test]
    fn test_add_member() {
        let owner_id = UserId::generate();
        let member_id = UserId::generate();
        let name = OrganizationName::new("Test Org".to_string()).unwrap();
        let mut org = Organization::new(owner_id, name);

        // Add member
        org.add_member(member_id).unwrap();
        assert!(org.is_member(&member_id));
        assert!(org.belongs_to(&member_id));
        assert_eq!(org.total_members(), 2);

        // Cannot add same member twice
        assert!(org.add_member(member_id).is_err());

        // Cannot add owner as member
        assert!(org.add_member(owner_id).is_err());
    }

    #[test]
    fn test_remove_member() {
        let owner_id = UserId::generate();
        let member_id = UserId::generate();
        let name = OrganizationName::new("Test Org".to_string()).unwrap();
        let mut org = Organization::new(owner_id, name);

        org.add_member(member_id).unwrap();

        // Remove member
        org.remove_member(&member_id).unwrap();
        assert!(!org.is_member(&member_id));
        assert_eq!(org.total_members(), 1);

        // Cannot remove owner
        assert!(org.remove_member(&owner_id).is_err());

        // Cannot remove non-member
        let non_member = UserId::generate();
        assert!(org.remove_member(&non_member).is_err());
    }

    #[test]
    fn test_transfer_ownership() {
        let owner_id = UserId::generate();
        let member_id = UserId::generate();
        let name = OrganizationName::new("Test Org".to_string()).unwrap();
        let mut org = Organization::new(owner_id, name);

        org.add_member(member_id).unwrap();

        // Transfer to member
        org.transfer_ownership(member_id).unwrap();
        assert!(org.is_owner(&member_id));
        assert!(org.is_member(&owner_id)); // Old owner is now member
        assert!(!org.is_member(&member_id)); // New owner is not in members list

        // Cannot transfer to non-member
        let non_member = UserId::generate();
        assert!(org.transfer_ownership(non_member).is_err());
    }

    #[test]
    fn test_subscription_limits() {
        let org_id = OrganizationId::generate();
        let mut limits = SubscriptionLimits::new_free(org_id);

        assert_eq!(limits.tier, SubscriptionTier::Free);
        assert!(limits.has_feature("dependency_analysis"));
        assert!(!limits.has_feature("sast"));

        // Upgrade to starter
        limits.upgrade_tier(SubscriptionTier::Starter);
        assert!(limits.has_feature("sast"));
        assert!(limits.has_feature("secrets_detection"));
        assert!(!limits.has_feature("custom_rules"));
    }

    #[test]
    fn test_user_stats_monthly() {
        let org_id = OrganizationId::generate();
        let mut stats = UserStatsMonthly::new(org_id, "2025-11".to_string());

        stats.increment_scans_completed();
        assert_eq!(stats.scans_completed, 1);

        stats.add_findings(1, 2, 3, 4, 5);
        assert_eq!(stats.findings_count, 15);
        assert_eq!(stats.findings_critical, 1);
        assert_eq!(stats.findings_high, 2);

        stats.increment_api_calls(100);
        assert_eq!(stats.api_calls_used, 100);
    }
}
