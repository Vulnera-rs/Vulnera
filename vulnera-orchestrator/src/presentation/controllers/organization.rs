//! Organization management API controllers

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use tracing::{error, info, instrument};
use uuid::Uuid;

use vulnera_core::domain::auth::value_objects::UserId;
use vulnera_core::domain::organization::value_objects::OrganizationId;

use crate::presentation::auth::Auth;
use crate::presentation::controllers::OrchestratorState;
use crate::presentation::models::{
    CreateOrganizationRequest, ErrorResponse, InviteMemberRequest, OrganizationListResponse,
    OrganizationMemberDto, OrganizationMembersResponse, OrganizationResponse,
    OrganizationStatsResponse, TransferOwnershipRequest, UpdateOrganizationRequest,
};

/// POST /api/v1/organizations - Create a new organization
#[utoipa::path(
    post,
    path = "/api/v1/organizations",
    request_body = CreateOrganizationRequest,
    responses(
        (status = 201, description = "Organization created", body = OrganizationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Organization name already exists"),
        (status = 500, description = "Internal server error")
    ),
    tag = "organizations",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
#[instrument(skip(state, auth, request), fields(user_id = %auth.user_id.as_uuid()))]
pub async fn create_organization(
    State(state): State<OrchestratorState>,
    auth: Auth,
    Json(request): Json<CreateOrganizationRequest>,
) -> Result<(StatusCode, Json<OrganizationResponse>), Response> {
    // Execute use case
    let result = state
        .organization
        .create_organization_use_case
        .execute(auth.user_id, request.name)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to create organization");
            map_organization_error(e)
        })?;

    let organization = result.organization;

    info!(
        org_id = %organization.id,
        "Organization created successfully"
    );

    // Get member count (just the owner at creation)
    let member_count = 1;

    Ok((
        StatusCode::CREATED,
        Json(OrganizationResponse {
            id: organization.id.as_uuid(),
            name: organization.name.as_str().to_string(),
            description: organization.description.clone(),
            owner_id: organization.owner_id.as_uuid(),
            member_count,
            tier: "Free".to_string(),
            created_at: organization.created_at,
            updated_at: organization.updated_at,
        }),
    ))
}

/// GET /api/v1/organizations - List user's organizations
#[utoipa::path(
    get,
    path = "/api/v1/organizations",
    responses(
        (status = 200, description = "Organizations retrieved", body = OrganizationListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "organizations",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
#[instrument(skip(state, auth), fields(user_id = %auth.user_id.as_uuid()))]
pub async fn list_organizations(
    State(state): State<OrchestratorState>,
    auth: Auth,
) -> Result<Json<OrganizationListResponse>, Response> {
    let organizations = state
        .organization
        .list_user_organizations_use_case
        .execute(auth.user_id)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to list organizations");
            map_organization_error(e)
        })?;

    // Map to response DTOs
    let mut org_responses = Vec::with_capacity(organizations.len());
    for org in &organizations {
        // Get member count for each org
        let member_count = state
            .organization
            .organization_member_repository
            .count_members(&org.id)
            .await
            .unwrap_or(0) as usize;

        org_responses.push(OrganizationResponse {
            id: org.id.as_uuid(),
            name: org.name.as_str().to_string(),
            description: org.description.clone(),
            owner_id: org.owner_id.as_uuid(),
            member_count,
            tier: "Free".to_string(),
            created_at: org.created_at,
            updated_at: org.updated_at,
        });
    }

    let total = org_responses.len();

    Ok(Json(OrganizationListResponse {
        organizations: org_responses,
        total,
    }))
}

/// GET /api/v1/organizations/{id} - Get organization details
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{id}",
    params(
        ("id" = Uuid, Path, description = "Organization ID")
    ),
    responses(
        (status = 200, description = "Organization found", body = OrganizationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not a member of this organization"),
        (status = 404, description = "Organization not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "organizations",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
#[instrument(skip(state, auth), fields(user_id = %auth.user_id.as_uuid(), org_id = %id))]
pub async fn get_organization(
    State(state): State<OrchestratorState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> Result<Json<OrganizationResponse>, Response> {
    let org_id = OrganizationId::from(id);

    let details = state
        .organization
        .get_organization_use_case
        .execute(org_id, auth.user_id)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to get organization");
            map_organization_error(e)
        })?;

    let organization = details.organization;
    let member_count = details.members.len();

    Ok(Json(OrganizationResponse {
        id: organization.id.as_uuid(),
        name: organization.name.as_str().to_string(),
        description: organization.description.clone(),
        owner_id: organization.owner_id.as_uuid(),
        member_count,
        tier: "Free".to_string(),
        created_at: organization.created_at,
        updated_at: organization.updated_at,
    }))
}

/// PUT /api/v1/organizations/{id} - Update organization name
#[utoipa::path(
    put,
    path = "/api/v1/organizations/{id}",
    params(
        ("id" = Uuid, Path, description = "Organization ID")
    ),
    request_body = UpdateOrganizationRequest,
    responses(
        (status = 200, description = "Organization updated", body = OrganizationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Only owner can update organization"),
        (status = 404, description = "Organization not found"),
        (status = 409, description = "Organization name already exists"),
        (status = 500, description = "Internal server error")
    ),
    tag = "organizations",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
#[instrument(skip(state, auth, request), fields(user_id = %auth.user_id.as_uuid(), org_id = %id))]
pub async fn update_organization(
    State(state): State<OrchestratorState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateOrganizationRequest>,
) -> Result<Json<OrganizationResponse>, Response> {
    let org_id = OrganizationId::from(id);

    let organization = state
        .organization
        .update_organization_name_use_case
        .execute(org_id, auth.user_id, request.name)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to update organization");
            map_organization_error(e)
        })?;

    let member_count = state
        .organization
        .organization_member_repository
        .count_members(&org_id)
        .await
        .unwrap_or(0) as usize;

    info!(org_id = %id, "Organization updated successfully");

    Ok(Json(OrganizationResponse {
        id: organization.id.as_uuid(),
        name: organization.name.as_str().to_string(),
        description: organization.description.clone(),
        owner_id: organization.owner_id.as_uuid(),
        member_count,
        tier: "Free".to_string(),
        created_at: organization.created_at,
        updated_at: organization.updated_at,
    }))
}

/// DELETE /api/v1/organizations/{id} - Delete organization
#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{id}",
    params(
        ("id" = Uuid, Path, description = "Organization ID")
    ),
    responses(
        (status = 204, description = "Organization deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Only owner can delete organization"),
        (status = 404, description = "Organization not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "organizations",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
#[instrument(skip(state, auth), fields(user_id = %auth.user_id.as_uuid(), org_id = %id))]
pub async fn delete_organization(
    State(state): State<OrchestratorState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, Response> {
    let org_id = OrganizationId::from(id);

    state
        .organization
        .delete_organization_use_case
        .execute(org_id, auth.user_id)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to delete organization");
            map_organization_error(e)
        })?;

    info!(org_id = %id, "Organization deleted successfully");

    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/v1/organizations/{id}/members - List organization members
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{id}/members",
    params(
        ("id" = Uuid, Path, description = "Organization ID")
    ),
    responses(
        (status = 200, description = "Members retrieved", body = OrganizationMembersResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not a member of this organization"),
        (status = 404, description = "Organization not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "organizations",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
#[instrument(skip(state, auth), fields(user_id = %auth.user_id.as_uuid(), org_id = %id))]
pub async fn list_members(
    State(state): State<OrchestratorState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> Result<Json<OrganizationMembersResponse>, Response> {
    let org_id = OrganizationId::from(id);

    // Get organization details (includes members)
    let details = state
        .organization
        .get_organization_use_case
        .execute(org_id, auth.user_id)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to list members");
            map_organization_error(e)
        })?;

    let organization = details.organization;
    let members = details.members;

    // Convert to DTOs - need to fetch user details for each member
    let mut member_dtos = Vec::with_capacity(members.len());
    for member in members {
        // Get user email
        let email = state
            .auth
            .user_repository
            .find_by_id(&member.user_id)
            .await
            .ok()
            .flatten()
            .map(|u| u.email.into_string())
            .unwrap_or_else(|| "unknown@example.com".to_string());

        let role = if member.user_id == organization.owner_id {
            "Owner"
        } else {
            "Member"
        };

        member_dtos.push(OrganizationMemberDto {
            user_id: member.user_id.as_uuid(),
            email,
            role: role.to_string(),
            joined_at: member.joined_at,
        });
    }

    let total = member_dtos.len();

    Ok(Json(OrganizationMembersResponse {
        organization_id: id,
        members: member_dtos,
        total,
    }))
}

/// POST /api/v1/organizations/{id}/members - Invite a member
#[utoipa::path(
    post,
    path = "/api/v1/organizations/{id}/members",
    params(
        ("id" = Uuid, Path, description = "Organization ID")
    ),
    request_body = InviteMemberRequest,
    responses(
        (status = 201, description = "Member invited", body = OrganizationMemberDto),
        (status = 400, description = "Invalid email"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Only owner can invite members"),
        (status = 404, description = "Organization or user not found"),
        (status = 409, description = "User is already a member"),
        (status = 500, description = "Internal server error")
    ),
    tag = "organizations",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
#[instrument(skip(state, auth, request), fields(user_id = %auth.user_id.as_uuid(), org_id = %id))]
pub async fn invite_member(
    State(state): State<OrchestratorState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Json(request): Json<InviteMemberRequest>,
) -> Result<(StatusCode, Json<OrganizationMemberDto>), Response> {
    let org_id = OrganizationId::from(id);

    // Parse email
    let email = vulnera_core::domain::auth::value_objects::Email::new(request.email.clone())
        .map_err(|_| {
            error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_EMAIL",
                "Invalid email format",
            )
        })?;

    // Find user by email
    let invitee = state
        .auth
        .user_repository
        .find_by_email(&email)
        .await
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to look up user",
            )
        })?
        .ok_or_else(|| {
            error_response(
                StatusCode::NOT_FOUND,
                "USER_NOT_FOUND",
                &format!("User with email {} not found", request.email),
            )
        })?;

    let member = state
        .organization
        .invite_member_use_case
        .execute(org_id, auth.user_id, invitee.user_id)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to invite member");
            map_organization_error(e)
        })?;

    info!(email = %request.email, "Member invited successfully");

    Ok((
        StatusCode::CREATED,
        Json(OrganizationMemberDto {
            user_id: member.user_id.as_uuid(),
            email: request.email,
            role: "Member".to_string(),
            joined_at: member.joined_at,
        }),
    ))
}

/// DELETE /api/v1/organizations/{id}/members/{user_id} - Remove a member
#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{id}/members/{user_id}",
    params(
        ("id" = Uuid, Path, description = "Organization ID"),
        ("user_id" = Uuid, Path, description = "User ID to remove")
    ),
    responses(
        (status = 204, description = "Member removed"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Only owner can remove members"),
        (status = 404, description = "Organization or member not found"),
        (status = 409, description = "Cannot remove owner"),
        (status = 500, description = "Internal server error")
    ),
    tag = "organizations",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
#[instrument(skip(state, auth), fields(user_id = %auth.user_id.as_uuid(), org_id = %id, target_user = %user_id))]
pub async fn remove_member(
    State(state): State<OrchestratorState>,
    auth: Auth,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, Response> {
    let org_id = OrganizationId::from(id);
    let target_user_id = UserId::from(user_id);

    state
        .organization
        .remove_member_use_case
        .execute(org_id, auth.user_id, target_user_id)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to remove member");
            map_organization_error(e)
        })?;

    info!(user_id = %user_id, "Member removed successfully");

    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/v1/organizations/{id}/leave - Leave an organization
#[utoipa::path(
    post,
    path = "/api/v1/organizations/{id}/leave",
    params(
        ("id" = Uuid, Path, description = "Organization ID")
    ),
    responses(
        (status = 204, description = "Left organization"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Owner cannot leave without transferring ownership"),
        (status = 404, description = "Organization not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "organizations",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
#[instrument(skip(state, auth), fields(user_id = %auth.user_id.as_uuid(), org_id = %id))]
pub async fn leave_organization(
    State(state): State<OrchestratorState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, Response> {
    let org_id = OrganizationId::from(id);

    state
        .organization
        .leave_organization_use_case
        .execute(org_id, auth.user_id)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to leave organization");
            map_organization_error(e)
        })?;

    info!("Left organization successfully");

    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/v1/organizations/{id}/transfer - Transfer ownership
#[utoipa::path(
    post,
    path = "/api/v1/organizations/{id}/transfer",
    params(
        ("id" = Uuid, Path, description = "Organization ID")
    ),
    request_body = TransferOwnershipRequest,
    responses(
        (status = 200, description = "Ownership transferred", body = OrganizationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Only owner can transfer ownership"),
        (status = 404, description = "Organization or new owner not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "organizations",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
#[instrument(skip(state, auth, request), fields(user_id = %auth.user_id.as_uuid(), org_id = %id))]
pub async fn transfer_ownership(
    State(state): State<OrchestratorState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Json(request): Json<TransferOwnershipRequest>,
) -> Result<Json<OrganizationResponse>, Response> {
    let org_id = OrganizationId::from(id);
    let new_owner_id = UserId::from(request.new_owner_id);

    let organization = state
        .organization
        .transfer_ownership_use_case
        .execute(org_id, auth.user_id, new_owner_id)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to transfer ownership");
            map_organization_error(e)
        })?;

    let member_count = state
        .organization
        .organization_member_repository
        .count_members(&org_id)
        .await
        .unwrap_or(0) as usize;

    info!(new_owner = %request.new_owner_id, "Ownership transferred successfully");

    Ok(Json(OrganizationResponse {
        id: organization.id.as_uuid(),
        name: organization.name.as_str().to_string(),
        description: organization.description.clone(),
        owner_id: organization.owner_id.as_uuid(),
        member_count,
        tier: "Free".to_string(),
        created_at: organization.created_at,
        updated_at: organization.updated_at,
    }))
}

/// GET /api/v1/organizations/{id}/stats - Get organization statistics
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{id}/stats",
    params(
        ("id" = Uuid, Path, description = "Organization ID")
    ),
    responses(
        (status = 200, description = "Statistics retrieved", body = OrganizationStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not a member of this organization"),
        (status = 404, description = "Organization not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "organizations",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
#[instrument(skip(state, auth), fields(user_id = %auth.user_id.as_uuid(), org_id = %id))]
pub async fn get_organization_stats(
    State(state): State<OrchestratorState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> Result<Json<OrganizationStatsResponse>, Response> {
    let org_id = OrganizationId::from(id);

    // First verify user is a member via get_organization
    let details = state
        .organization
        .get_organization_use_case
        .execute(org_id, auth.user_id)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to get organization");
            map_organization_error(e)
        })?;

    // Get dashboard overview which includes stats
    let overview = state
        .analytics
        .get_dashboard_overview_use_case
        .execute(org_id)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to get organization stats");
            map_organization_error(e)
        })?;

    let member_count = details.members.len();

    // Extract stats from current month data
    let stats = overview.current_month_stats.unwrap_or_default();

    Ok(Json(OrganizationStatsResponse {
        organization_id: id,
        total_scans: stats.scans_completed as i64,
        total_findings: stats.findings_count as i64,
        critical_findings: stats.findings_critical as i64,
        high_findings: stats.findings_high as i64,
        medium_findings: stats.findings_medium as i64,
        low_findings: stats.findings_low as i64,
        api_calls_this_month: stats.api_calls_used as i64,
        member_count,
    }))
}

// =============================================================================
// Helper functions
// =============================================================================

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    let body = Json(ErrorResponse {
        code: code.to_string(),
        message: message.to_string(),
        details: None,
        request_id: Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
    });

    (status, body).into_response()
}

fn map_organization_error(
    error: vulnera_core::domain::organization::errors::OrganizationError,
) -> Response {
    use vulnera_core::domain::organization::errors::OrganizationError;

    let (status, code, message) = match &error {
        OrganizationError::NotFound { id } => (
            StatusCode::NOT_FOUND,
            "ORG_NOT_FOUND",
            format!("Organization {} not found", id),
        ),
        OrganizationError::NameAlreadyExists { name } => (
            StatusCode::CONFLICT,
            "NAME_EXISTS",
            format!("Organization name '{}' already exists", name),
        ),
        OrganizationError::InvalidName { reason } => {
            (StatusCode::BAD_REQUEST, "INVALID_NAME", reason.clone())
        }
        OrganizationError::NotAMember { user_id, .. } => (
            StatusCode::FORBIDDEN,
            "NOT_A_MEMBER",
            format!("User {} is not a member of this organization", user_id),
        ),
        OrganizationError::AlreadyMember { user_id, .. } => (
            StatusCode::CONFLICT,
            "ALREADY_MEMBER",
            format!("User {} is already a member", user_id),
        ),
        OrganizationError::PermissionDenied { reason } => (
            StatusCode::FORBIDDEN,
            "PERMISSION_DENIED",
            format!("Permission denied: {}", reason),
        ),
        OrganizationError::CannotRemoveOwner => (
            StatusCode::CONFLICT,
            "CANNOT_REMOVE_OWNER",
            "Cannot remove the organization owner".to_string(),
        ),
        OrganizationError::OwnerCannotLeave => (
            StatusCode::CONFLICT,
            "OWNER_CANNOT_LEAVE",
            "Owner cannot leave without transferring ownership first".to_string(),
        ),
        OrganizationError::MemberLimitExceeded { limit } => (
            StatusCode::PAYMENT_REQUIRED,
            "MEMBER_LIMIT_EXCEEDED",
            format!(
                "Member limit exceeded. Current tier allows {} members.",
                limit
            ),
        ),
        OrganizationError::ScanLimitExceeded { used, limit } => (
            StatusCode::PAYMENT_REQUIRED,
            "SCAN_LIMIT_EXCEEDED",
            format!(
                "Monthly scan limit exceeded. Used {}/{} scans.",
                used, limit
            ),
        ),
        OrganizationError::ApiCallLimitExceeded { used, limit } => (
            StatusCode::PAYMENT_REQUIRED,
            "API_CALL_LIMIT_EXCEEDED",
            format!(
                "Monthly API call limit exceeded. Used {}/{} calls.",
                used, limit
            ),
        ),
        OrganizationError::DatabaseError { message } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "DATABASE_ERROR",
            message.clone(),
        ),
        OrganizationError::InternalError { message } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            message.clone(),
        ),
    };

    error_response(status, code, &message)
}
