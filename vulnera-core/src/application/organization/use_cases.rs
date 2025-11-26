//! Organization use cases
//!
//! Application-level use cases for organization management.

use std::sync::Arc;

use tracing::instrument;

use crate::domain::auth::value_objects::UserId;
use crate::domain::organization::{
    entities::{Organization, SubscriptionLimits},
    errors::OrganizationError,
    repositories::{
        IOrganizationMemberRepository, IOrganizationRepository, ISubscriptionLimitsRepository,
    },
    value_objects::{OrganizationId, OrganizationMember, OrganizationName},
};

/// Result of organization creation
#[derive(Debug, Clone)]
pub struct CreateOrganizationResult {
    pub organization: Organization,
    pub subscription_limits: SubscriptionLimits,
}

/// Use case for creating a new organization
pub struct CreateOrganizationUseCase {
    org_repository: Arc<dyn IOrganizationRepository>,
    member_repository: Arc<dyn IOrganizationMemberRepository>,
    limits_repository: Arc<dyn ISubscriptionLimitsRepository>,
}

impl CreateOrganizationUseCase {
    pub fn new(
        org_repository: Arc<dyn IOrganizationRepository>,
        member_repository: Arc<dyn IOrganizationMemberRepository>,
        limits_repository: Arc<dyn ISubscriptionLimitsRepository>,
    ) -> Self {
        Self {
            org_repository,
            member_repository,
            limits_repository,
        }
    }

    /// Create a new organization with the given owner
    ///
    /// The owner is automatically added as a member.
    #[instrument(skip(self), fields(owner_id = %owner_id, name = %name))]
    pub async fn execute(
        &self,
        owner_id: UserId,
        name: String,
    ) -> Result<CreateOrganizationResult, OrganizationError> {
        // Validate name
        let org_name = OrganizationName::new(name)
            .map_err(|e| OrganizationError::InvalidName { reason: e })?;

        // Check if user already has an org with this name
        if self
            .org_repository
            .find_by_owner_and_name(&owner_id, org_name.as_str())
            .await?
            .is_some()
        {
            return Err(OrganizationError::NameAlreadyExists {
                name: org_name.as_str().to_string(),
            });
        }

        // Create organization entity
        let organization = Organization::new(owner_id, org_name);

        // Save organization
        self.org_repository.create(&organization).await?;

        // Add owner as member
        self.member_repository
            .add_member(&organization.id, &owner_id)
            .await?;

        // Create default subscription limits (free tier)
        let limits = SubscriptionLimits::new_free(organization.id);
        self.limits_repository.create(&limits).await?;

        Ok(CreateOrganizationResult {
            organization,
            subscription_limits: limits,
        })
    }
}

/// Use case for inviting a member to an organization
///
/// Only the organization owner can invite members.
pub struct InviteMemberUseCase {
    org_repository: Arc<dyn IOrganizationRepository>,
    member_repository: Arc<dyn IOrganizationMemberRepository>,
}

impl InviteMemberUseCase {
    pub fn new(
        org_repository: Arc<dyn IOrganizationRepository>,
        member_repository: Arc<dyn IOrganizationMemberRepository>,
    ) -> Self {
        Self {
            org_repository,
            member_repository,
        }
    }

    /// Invite a user to an organization
    ///
    /// Only the owner can invite members.
    #[instrument(skip(self), fields(org_id = %org_id, inviter_id = %inviter_id, invitee_id = %invitee_id))]
    pub async fn execute(
        &self,
        org_id: OrganizationId,
        inviter_id: UserId,
        invitee_id: UserId,
    ) -> Result<OrganizationMember, OrganizationError> {
        // Fetch organization
        let organization =
            self.org_repository
                .find_by_id(&org_id)
                .await?
                .ok_or(OrganizationError::NotFound {
                    id: org_id.to_string(),
                })?;

        // Verify inviter is owner
        if !organization.is_owner(&inviter_id) {
            return Err(OrganizationError::PermissionDenied {
                reason: "Only the owner can invite members".to_string(),
            });
        }

        // Check if user is already a member
        if self
            .member_repository
            .is_member(&org_id, &invitee_id)
            .await?
        {
            return Err(OrganizationError::AlreadyMember {
                user_id: invitee_id.to_string(),
                org_id: org_id.to_string(),
            });
        }

        // Add member
        self.member_repository
            .add_member(&org_id, &invitee_id)
            .await?;

        Ok(OrganizationMember::new(invitee_id))
    }
}

/// Use case for removing a member from an organization
///
/// Only the owner can remove members. The owner cannot be removed.
pub struct RemoveMemberUseCase {
    org_repository: Arc<dyn IOrganizationRepository>,
    member_repository: Arc<dyn IOrganizationMemberRepository>,
}

impl RemoveMemberUseCase {
    pub fn new(
        org_repository: Arc<dyn IOrganizationRepository>,
        member_repository: Arc<dyn IOrganizationMemberRepository>,
    ) -> Self {
        Self {
            org_repository,
            member_repository,
        }
    }

    /// Remove a member from an organization
    ///
    /// Only the owner can remove members. The owner cannot remove themselves.
    #[instrument(skip(self), fields(org_id = %org_id, remover_id = %remover_id, member_id = %member_id))]
    pub async fn execute(
        &self,
        org_id: OrganizationId,
        remover_id: UserId,
        member_id: UserId,
    ) -> Result<(), OrganizationError> {
        // Fetch organization
        let organization =
            self.org_repository
                .find_by_id(&org_id)
                .await?
                .ok_or(OrganizationError::NotFound {
                    id: org_id.to_string(),
                })?;

        // Verify remover is owner
        if !organization.is_owner(&remover_id) {
            return Err(OrganizationError::PermissionDenied {
                reason: "Only the owner can remove members".to_string(),
            });
        }

        // Cannot remove owner
        if organization.is_owner(&member_id) {
            return Err(OrganizationError::CannotRemoveOwner);
        }

        // Check if user is a member
        if !self
            .member_repository
            .is_member(&org_id, &member_id)
            .await?
        {
            return Err(OrganizationError::NotAMember {
                user_id: member_id.to_string(),
                org_id: org_id.to_string(),
            });
        }

        // Remove member
        self.member_repository
            .remove_member(&org_id, &member_id)
            .await?;

        Ok(())
    }
}

/// Use case for a member leaving an organization
///
/// Any member can leave. The owner cannot leave (must transfer ownership first).
pub struct LeaveOrganizationUseCase {
    org_repository: Arc<dyn IOrganizationRepository>,
    member_repository: Arc<dyn IOrganizationMemberRepository>,
}

impl LeaveOrganizationUseCase {
    pub fn new(
        org_repository: Arc<dyn IOrganizationRepository>,
        member_repository: Arc<dyn IOrganizationMemberRepository>,
    ) -> Self {
        Self {
            org_repository,
            member_repository,
        }
    }

    /// Leave an organization
    ///
    /// The owner cannot leave (must transfer ownership first or delete org).
    #[instrument(skip(self), fields(org_id = %org_id, user_id = %user_id))]
    pub async fn execute(
        &self,
        org_id: OrganizationId,
        user_id: UserId,
    ) -> Result<(), OrganizationError> {
        // Fetch organization
        let organization =
            self.org_repository
                .find_by_id(&org_id)
                .await?
                .ok_or(OrganizationError::NotFound {
                    id: org_id.to_string(),
                })?;

        // Owner cannot leave
        if organization.is_owner(&user_id) {
            return Err(OrganizationError::OwnerCannotLeave);
        }

        // Check if user is a member
        if !self.member_repository.is_member(&org_id, &user_id).await? {
            return Err(OrganizationError::NotAMember {
                user_id: user_id.to_string(),
                org_id: org_id.to_string(),
            });
        }

        // Remove membership
        self.member_repository
            .remove_member(&org_id, &user_id)
            .await?;

        Ok(())
    }
}

/// Use case for transferring organization ownership
pub struct TransferOwnershipUseCase {
    org_repository: Arc<dyn IOrganizationRepository>,
    member_repository: Arc<dyn IOrganizationMemberRepository>,
}

impl TransferOwnershipUseCase {
    pub fn new(
        org_repository: Arc<dyn IOrganizationRepository>,
        member_repository: Arc<dyn IOrganizationMemberRepository>,
    ) -> Self {
        Self {
            org_repository,
            member_repository,
        }
    }

    /// Transfer ownership to another member
    ///
    /// The new owner must be an existing member.
    #[instrument(skip(self), fields(org_id = %org_id, current_owner_id = %current_owner_id, new_owner_id = %new_owner_id))]
    pub async fn execute(
        &self,
        org_id: OrganizationId,
        current_owner_id: UserId,
        new_owner_id: UserId,
    ) -> Result<Organization, OrganizationError> {
        // Fetch organization
        let mut organization =
            self.org_repository
                .find_by_id(&org_id)
                .await?
                .ok_or(OrganizationError::NotFound {
                    id: org_id.to_string(),
                })?;

        // Verify current user is owner
        if !organization.is_owner(&current_owner_id) {
            return Err(OrganizationError::PermissionDenied {
                reason: "Only the owner can transfer ownership".to_string(),
            });
        }

        // Verify new owner is a member
        if !self
            .member_repository
            .is_member(&org_id, &new_owner_id)
            .await?
        {
            return Err(OrganizationError::NotAMember {
                user_id: new_owner_id.to_string(),
                org_id: org_id.to_string(),
            });
        }

        // Transfer ownership
        organization.transfer_ownership(new_owner_id)?;

        // Save changes
        self.org_repository.update(&organization).await?;

        Ok(organization)
    }
}

/// Use case for getting organization details
pub struct GetOrganizationUseCase {
    org_repository: Arc<dyn IOrganizationRepository>,
    member_repository: Arc<dyn IOrganizationMemberRepository>,
}

impl GetOrganizationUseCase {
    pub fn new(
        org_repository: Arc<dyn IOrganizationRepository>,
        member_repository: Arc<dyn IOrganizationMemberRepository>,
    ) -> Self {
        Self {
            org_repository,
            member_repository,
        }
    }

    /// Get organization details
    ///
    /// Only members can view organization details.
    #[instrument(skip(self), fields(org_id = %org_id, user_id = %user_id))]
    pub async fn execute(
        &self,
        org_id: OrganizationId,
        user_id: UserId,
    ) -> Result<OrganizationDetails, OrganizationError> {
        // Fetch organization
        let organization =
            self.org_repository
                .find_by_id(&org_id)
                .await?
                .ok_or(OrganizationError::NotFound {
                    id: org_id.to_string(),
                })?;

        // Verify user is a member
        if !self.member_repository.is_member(&org_id, &user_id).await? {
            return Err(OrganizationError::NotAMember {
                user_id: user_id.to_string(),
                org_id: org_id.to_string(),
            });
        }

        // Get all members
        let members = self.member_repository.find_by_organization(&org_id).await?;

        let is_owner = organization.is_owner(&user_id);

        Ok(OrganizationDetails {
            organization,
            members,
            is_owner,
        })
    }
}

/// Organization details with members
#[derive(Debug, Clone)]
pub struct OrganizationDetails {
    pub organization: Organization,
    pub members: Vec<OrganizationMember>,
    pub is_owner: bool,
}

/// Use case for listing user's organizations
pub struct ListUserOrganizationsUseCase {
    org_repository: Arc<dyn IOrganizationRepository>,
    member_repository: Arc<dyn IOrganizationMemberRepository>,
}

impl ListUserOrganizationsUseCase {
    pub fn new(
        org_repository: Arc<dyn IOrganizationRepository>,
        member_repository: Arc<dyn IOrganizationMemberRepository>,
    ) -> Self {
        Self {
            org_repository,
            member_repository,
        }
    }

    /// List all organizations the user is a member of (including owned)
    #[instrument(skip(self), fields(user_id = %user_id))]
    pub async fn execute(&self, user_id: UserId) -> Result<Vec<Organization>, OrganizationError> {
        // Get orgs owned by user
        let mut organizations = self.org_repository.find_by_owner_id(&user_id).await?;

        // Get orgs where user is member (not owner)
        let member_org_ids = self
            .member_repository
            .find_organizations_by_user(&user_id)
            .await?;
        for org_id in member_org_ids {
            if let Some(org) = self.org_repository.find_by_id(&org_id).await? {
                // Only add if not already in list (not owner)
                if !org.is_owner(&user_id) {
                    organizations.push(org);
                }
            }
        }

        Ok(organizations)
    }
}

/// Use case for deleting an organization
///
/// Only the owner can delete an organization.
pub struct DeleteOrganizationUseCase {
    org_repository: Arc<dyn IOrganizationRepository>,
    limits_repository: Arc<dyn ISubscriptionLimitsRepository>,
}

impl DeleteOrganizationUseCase {
    pub fn new(
        org_repository: Arc<dyn IOrganizationRepository>,
        limits_repository: Arc<dyn ISubscriptionLimitsRepository>,
    ) -> Self {
        Self {
            org_repository,
            limits_repository,
        }
    }

    /// Delete an organization
    ///
    /// Only the owner can delete. This will cascade delete all members and data.
    #[instrument(skip(self), fields(org_id = %org_id, user_id = %user_id))]
    pub async fn execute(
        &self,
        org_id: OrganizationId,
        user_id: UserId,
    ) -> Result<(), OrganizationError> {
        // Fetch organization
        let organization =
            self.org_repository
                .find_by_id(&org_id)
                .await?
                .ok_or(OrganizationError::NotFound {
                    id: org_id.to_string(),
                })?;

        // Verify user is owner
        if !organization.is_owner(&user_id) {
            return Err(OrganizationError::PermissionDenied {
                reason: "Only the owner can delete the organization".to_string(),
            });
        }

        // Delete subscription limits (cascade)
        self.limits_repository.delete(&org_id).await.ok(); // Ignore if not exists

        // Delete organization (will cascade delete members via FK)
        self.org_repository.delete(&org_id).await?;

        Ok(())
    }
}

/// Use case for updating organization name
pub struct UpdateOrganizationNameUseCase {
    org_repository: Arc<dyn IOrganizationRepository>,
}

impl UpdateOrganizationNameUseCase {
    pub fn new(org_repository: Arc<dyn IOrganizationRepository>) -> Self {
        Self { org_repository }
    }

    /// Update the organization's name
    ///
    /// Only the owner can update the name.
    #[instrument(skip(self), fields(org_id = %org_id, user_id = %user_id, new_name = %new_name))]
    pub async fn execute(
        &self,
        org_id: OrganizationId,
        user_id: UserId,
        new_name: String,
    ) -> Result<Organization, OrganizationError> {
        // Fetch organization
        let mut organization =
            self.org_repository
                .find_by_id(&org_id)
                .await?
                .ok_or(OrganizationError::NotFound {
                    id: org_id.to_string(),
                })?;

        // Verify user is owner
        if !organization.is_owner(&user_id) {
            return Err(OrganizationError::PermissionDenied {
                reason: "Only the owner can update the organization name".to_string(),
            });
        }

        // Validate and update name
        let name = OrganizationName::new(new_name)
            .map_err(|e| OrganizationError::InvalidName { reason: e })?;
        organization.update_name(name);

        // Save changes
        self.org_repository.update(&organization).await?;

        Ok(organization)
    }
}
