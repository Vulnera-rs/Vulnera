//! Organization domain errors

use thiserror::Error;

/// Organization domain errors
#[derive(Error, Debug, Clone, PartialEq)]
pub enum OrganizationError {
    /// Organization not found
    #[error("Organization not found: {id}")]
    NotFound { id: String },

    /// Organization name already exists for this owner
    #[error("Organization name already exists: {name}")]
    NameAlreadyExists { name: String },

    /// Invalid organization name
    #[error("Invalid organization name: {reason}")]
    InvalidName { reason: String },

    /// User is not a member of the organization
    #[error("User {user_id} is not a member of organization {org_id}")]
    NotAMember { user_id: String, org_id: String },

    /// User is already a member of the organization
    #[error("User {user_id} is already a member of organization {org_id}")]
    AlreadyMember { user_id: String, org_id: String },

    /// User does not have permission to perform this action
    #[error("Permission denied: {reason}")]
    PermissionDenied { reason: String },

    /// Cannot remove the owner from the organization
    #[error("Cannot remove the owner from the organization")]
    CannotRemoveOwner,

    /// Owner cannot leave their own organization
    #[error(
        "Owner cannot leave their own organization. Transfer ownership or delete the organization."
    )]
    OwnerCannotLeave,

    /// Member limit exceeded for this tier
    #[error("Member limit exceeded. Current tier allows {limit} members.")]
    MemberLimitExceeded { limit: u32 },

    /// Scan limit exceeded for this tier
    #[error("Monthly scan limit exceeded. Used {used}/{limit} scans.")]
    ScanLimitExceeded { used: u32, limit: u32 },

    /// API call limit exceeded for this tier
    #[error("Monthly API call limit exceeded. Used {used}/{limit} calls.")]
    ApiCallLimitExceeded { used: u32, limit: u32 },

    /// Database operation failed
    #[error("Database error: {message}")]
    DatabaseError { message: String },

    /// Internal error
    #[error("Internal error: {message}")]
    InternalError { message: String },
}

impl OrganizationError {
    /// Check if this error is a "not found" error
    pub fn is_not_found(&self) -> bool {
        matches!(self, OrganizationError::NotFound { .. })
    }

    /// Check if this error is a permission error
    pub fn is_permission_denied(&self) -> bool {
        matches!(self, OrganizationError::PermissionDenied { .. })
    }

    /// Check if this error is a limit exceeded error
    pub fn is_limit_exceeded(&self) -> bool {
        matches!(
            self,
            OrganizationError::MemberLimitExceeded { .. }
                | OrganizationError::ScanLimitExceeded { .. }
                | OrganizationError::ApiCallLimitExceeded { .. }
        )
    }
}
