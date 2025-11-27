//! Analytics API controllers

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use chrono::{Datelike, Utc};
use serde::Deserialize;
use tracing::{error, instrument};
use uuid::Uuid;

use vulnera_core::domain::organization::value_objects::OrganizationId;

use crate::presentation::auth::Auth;
use crate::presentation::controllers::OrchestratorState;
use crate::presentation::models::{
    DashboardStatsResponse, ErrorResponse, MonthlyUsageDto, OrganizationUsageResponse,
    PersonalDashboardStatsResponse, PersonalUsageResponse, QuotaItemDto, QuotaUsageResponse,
};

/// Query parameters for usage endpoint
#[derive(Debug, Deserialize)]
pub struct UsageQueryParams {
    /// Number of months to include (default: 6, max: 24)
    pub months: Option<u32>,
}

/// GET /api/v1/organizations/{id}/analytics/dashboard - Get dashboard statistics
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{id}/analytics/dashboard",
    params(
        ("id" = Uuid, Path, description = "Organization ID")
    ),
    responses(
        (status = 200, description = "Dashboard stats retrieved", body = DashboardStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not a member of this organization"),
        (status = 404, description = "Organization not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "analytics",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
#[instrument(skip(state, auth), fields(user_id = %auth.user_id.as_uuid(), org_id = %id))]
pub async fn get_dashboard_stats(
    State(state): State<OrchestratorState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> Result<Json<DashboardStatsResponse>, Response> {
    let org_id = OrganizationId::from(id);

    // Verify user is a member
    let _ = state
        .get_organization_use_case
        .execute(org_id, auth.user_id)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to verify membership");
            map_organization_error(e)
        })?;

    let overview = state
        .get_dashboard_overview_use_case
        .execute(org_id)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to get dashboard stats");
            map_organization_error(e)
        })?;

    // Format current month as YYYY-MM
    let now = Utc::now();
    let current_month = format!("{:04}-{:02}", now.year(), now.month());

    // Extract stats from current month data
    let stats = overview.current_month_stats.clone().unwrap_or_default();

    // TODO: Calculate trends from previous month
    // For now, return None for trends
    let scans_trend_percent = None;
    let findings_trend_percent = None;

    Ok(Json(DashboardStatsResponse {
        organization_id: id,
        scans_this_month: stats.scans_completed as i64,
        findings_this_month: stats.findings_count as i64,
        critical_this_month: stats.findings_critical as i64,
        high_this_month: stats.findings_high as i64,
        scans_trend_percent,
        findings_trend_percent,
        current_month,
    }))
}

/// GET /api/v1/organizations/{id}/analytics/usage - Get historical usage data
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{id}/analytics/usage",
    params(
        ("id" = Uuid, Path, description = "Organization ID"),
        ("months" = Option<u32>, Query, description = "Number of months to include (default: 6, max: 24)")
    ),
    responses(
        (status = 200, description = "Usage data retrieved", body = OrganizationUsageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not a member of this organization"),
        (status = 404, description = "Organization not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "analytics",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
#[instrument(skip(state, auth, params), fields(user_id = %auth.user_id.as_uuid(), org_id = %id))]
pub async fn get_usage(
    State(state): State<OrchestratorState>,
    auth: Auth,
    Path(id): Path<Uuid>,
    Query(params): Query<UsageQueryParams>,
) -> Result<Json<OrganizationUsageResponse>, Response> {
    let org_id = OrganizationId::from(id);

    // Verify user is a member
    let _ = state
        .get_organization_use_case
        .execute(org_id, auth.user_id)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to verify membership");
            map_organization_error(e)
        })?;

    // Clamp months to 1-24 range
    let months_count = params.months.unwrap_or(6).clamp(1, 24);

    // Calculate date range
    let now = Utc::now();
    let end_month = format!("{:04}-{:02}", now.year(), now.month());

    // Calculate start month (months_count months ago)
    let start_date = now - chrono::Months::new(months_count);
    let start_month = format!("{:04}-{:02}", start_date.year(), start_date.month());

    let analytics = state
        .get_monthly_analytics_use_case
        .execute(org_id, &start_month, &end_month)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to get usage data");
            map_organization_error(e)
        })?;

    // Convert to DTOs
    let months_data: Vec<MonthlyUsageDto> = analytics
        .into_iter()
        .map(|m| MonthlyUsageDto {
            month: m.year_month,
            scans_completed: m.total_scans as i64,
            scans_failed: 0, // Not tracked separately in current model
            total_findings: m.total_findings as i64,
            critical_findings: m.findings_by_severity.critical as i64,
            high_findings: m.findings_by_severity.high as i64,
            medium_findings: m.findings_by_severity.medium as i64,
            low_findings: m.findings_by_severity.low as i64,
            api_calls: m.total_api_calls as i64,
            reports_generated: m.total_reports as i64,
        })
        .collect();

    Ok(Json(OrganizationUsageResponse {
        organization_id: id,
        months: months_data,
    }))
}

/// GET /api/v1/organizations/{id}/analytics/quota - Get quota usage
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{id}/analytics/quota",
    params(
        ("id" = Uuid, Path, description = "Organization ID")
    ),
    responses(
        (status = 200, description = "Quota usage retrieved", body = QuotaUsageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not a member of this organization"),
        (status = 404, description = "Organization not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "analytics",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
#[instrument(skip(state, auth), fields(user_id = %auth.user_id.as_uuid(), org_id = %id))]
pub async fn get_quota(
    State(state): State<OrchestratorState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> Result<Json<QuotaUsageResponse>, Response> {
    let org_id = OrganizationId::from(id);

    // Verify user is a member
    let details = state
        .get_organization_use_case
        .execute(org_id, auth.user_id)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to verify membership");
            map_organization_error(e)
        })?;

    let quota = state
        .check_quota_use_case
        .get_quota_status(org_id)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to get quota");
            map_organization_error(e)
        })?;

    // Format current month as YYYY-MM
    let now = Utc::now();
    let current_month = format!("{:04}-{:02}", now.year(), now.month());

    // Build quota items
    let scans = build_quota_item(quota.scans_used as i64, quota.scans_limit.map(|l| l as i64));
    let api_calls = build_quota_item(
        quota.api_calls_used as i64,
        quota.api_calls_limit.map(|l| l as i64),
    );
    let members = build_quota_item(details.members.len() as i64, None); // Member limit not tracked yet

    let is_over_limit = scans.is_exceeded || api_calls.is_exceeded || members.is_exceeded;

    // Determine tier (default to Free for now)
    let tier = "Free".to_string();

    Ok(Json(QuotaUsageResponse {
        organization_id: id,
        tier,
        current_month,
        scans,
        api_calls,
        members,
        is_over_limit,
    }))
}

// =============================================================================
// Personal Analytics Endpoints (for users without organizations)
// =============================================================================

/// GET /api/v1/me/analytics/dashboard - Get personal dashboard statistics
#[utoipa::path(
    get,
    path = "/api/v1/me/analytics/dashboard",
    responses(
        (status = 200, description = "Personal dashboard stats retrieved", body = PersonalDashboardStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "personal-analytics",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
#[instrument(skip(state, auth), fields(user_id = %auth.user_id.as_uuid()))]
pub async fn get_personal_dashboard_stats(
    State(state): State<OrchestratorState>,
    auth: Auth,
) -> Result<Json<PersonalDashboardStatsResponse>, Response> {
    let now = Utc::now();
    let current_month = format!("{:04}-{:02}", now.year(), now.month());
    let prev_month_date = now - chrono::Months::new(1);
    let prev_month = format!("{:04}-{:02}", prev_month_date.year(), prev_month_date.month());

    // Get current month stats
    let current_stats = state
        .analytics_service
        .get_personal_stats_for_range(auth.user_id, &current_month, &current_month)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to get personal dashboard stats");
            map_organization_error(e)
        })?;

    // Get previous month for trend calculation
    let prev_stats = state
        .analytics_service
        .get_personal_stats_for_range(auth.user_id, &prev_month, &prev_month)
        .await
        .ok()
        .and_then(|v| v.into_iter().next());

    let stats = current_stats.into_iter().next();

    let (scans_this_month, findings_this_month, critical, high, medium, low) = stats
        .as_ref()
        .map(|s| {
            (
                s.scans_completed as i64,
                s.findings_count as i64,
                s.findings_critical as i64,
                s.findings_high as i64,
                s.findings_medium as i64,
                s.findings_low as i64,
            )
        })
        .unwrap_or((0, 0, 0, 0, 0, 0));

    // Calculate trends
    let scans_trend_percent = prev_stats.as_ref().and_then(|prev| {
        if prev.scans_completed > 0 {
            Some(((scans_this_month - prev.scans_completed as i64) as f64 / prev.scans_completed as f64) * 100.0)
        } else if scans_this_month > 0 {
            Some(100.0)
        } else {
            None
        }
    });

    let findings_trend_percent = prev_stats.as_ref().and_then(|prev| {
        if prev.findings_count > 0 {
            Some(((findings_this_month - prev.findings_count as i64) as f64 / prev.findings_count as f64) * 100.0)
        } else if findings_this_month > 0 {
            Some(100.0)
        } else {
            None
        }
    });

    Ok(Json(PersonalDashboardStatsResponse {
        user_id: auth.user_id.as_uuid(),
        scans_this_month,
        findings_this_month,
        critical_this_month: critical,
        high_this_month: high,
        medium_this_month: medium,
        low_this_month: low,
        scans_trend_percent,
        findings_trend_percent,
        current_month,
    }))
}

/// GET /api/v1/me/analytics/usage - Get personal historical usage data
#[utoipa::path(
    get,
    path = "/api/v1/me/analytics/usage",
    params(
        ("months" = Option<u32>, Query, description = "Number of months to include (default: 6, max: 24)")
    ),
    responses(
        (status = 200, description = "Personal usage data retrieved", body = PersonalUsageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "personal-analytics",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
#[instrument(skip(state, auth, params), fields(user_id = %auth.user_id.as_uuid()))]
pub async fn get_personal_usage(
    State(state): State<OrchestratorState>,
    auth: Auth,
    Query(params): Query<UsageQueryParams>,
) -> Result<Json<PersonalUsageResponse>, Response> {
    // Clamp months to 1-24 range
    let months_count = params.months.unwrap_or(6).clamp(1, 24);

    // Calculate date range
    let now = Utc::now();
    let end_month = format!("{:04}-{:02}", now.year(), now.month());
    let start_date = now - chrono::Months::new(months_count);
    let start_month = format!("{:04}-{:02}", start_date.year(), start_date.month());

    let stats = state
        .analytics_service
        .get_personal_stats_for_range(auth.user_id, &start_month, &end_month)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to get personal usage data");
            map_organization_error(e)
        })?;

    // Convert to DTOs
    let months_data: Vec<MonthlyUsageDto> = stats
        .into_iter()
        .map(|s| MonthlyUsageDto {
            month: s.year_month,
            scans_completed: s.scans_completed as i64,
            scans_failed: s.scans_failed as i64,
            total_findings: s.findings_count as i64,
            critical_findings: s.findings_critical as i64,
            high_findings: s.findings_high as i64,
            medium_findings: s.findings_medium as i64,
            low_findings: s.findings_low as i64,
            api_calls: s.api_calls_used as i64,
            reports_generated: s.reports_generated as i64,
        })
        .collect();

    Ok(Json(PersonalUsageResponse {
        user_id: auth.user_id.as_uuid(),
        months: months_data,
    }))
}

// =============================================================================
// Helper functions
// =============================================================================

fn build_quota_item(used: i64, limit: Option<i64>) -> QuotaItemDto {
    let (usage_percent, is_exceeded) = match limit {
        Some(l) if l > 0 => {
            let percent = (used as f64 / l as f64) * 100.0;
            (percent, used > l)
        }
        Some(_) => (0.0, false), // Zero limit means unlimited
        None => (0.0, false),    // No limit means unlimited
    };

    QuotaItemDto {
        used,
        limit,
        usage_percent: (usage_percent * 10.0).round() / 10.0, // Round to 1 decimal
        is_exceeded,
    }
}

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
        OrganizationError::NotAMember { user_id, .. } => (
            StatusCode::FORBIDDEN,
            "NOT_A_MEMBER",
            format!("User {} is not a member of this organization", user_id),
        ),
        OrganizationError::PermissionDenied { reason } => (
            StatusCode::FORBIDDEN,
            "PERMISSION_DENIED",
            format!("Permission denied: {}", reason),
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
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            error.to_string(),
        ),
    };

    error_response(status, code, &message)
}
