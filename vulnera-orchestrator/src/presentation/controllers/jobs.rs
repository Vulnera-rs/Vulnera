use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use tracing::{error, warn};
use uuid::Uuid;

use crate::presentation::auth::extractors::Auth;
use crate::presentation::controllers::OrchestratorState;
use crate::presentation::models::JobStatusResponse;

/// GET /api/v1/jobs/{id} - Retrieve job by ID
///
/// Only the user who created the job can retrieve it.
#[utoipa::path(
    get,
    path = "/api/v1/jobs/{id}",
    params(
        ("id" = Uuid, Path, description = "Job ID")
    ),
    responses(
        (status = 200, description = "Job found", body = JobStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - not job owner"),
        (status = 404, description = "Job not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "jobs",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn get_job(
    State(state): State<OrchestratorState>,
    auth: Auth,
    Path(id): Path<Uuid>,
) -> Result<Json<JobStatusResponse>, StatusCode> {
    match state.orchestrator.job_store.get_snapshot(id).await {
        Ok(Some(snapshot)) => {
            // Validate job ownership: only the user who created the job can access it
            // Master key bypass: allow master key authentication to access any job
            if !auth.is_master_key
                && let Some(ref ctx) = snapshot.invocation_context
                && let Some(ref job_user_id) = ctx.user_id
                && job_user_id != &auth.user_id
            {
                warn!(
                    job_id = %id,
                    requesting_user = %auth.user_id.as_str(),
                    job_owner = %job_user_id.as_str(),
                    "Unauthorized job access attempt"
                );
                return Err(StatusCode::FORBIDDEN);
            }

            Ok(Json(JobStatusResponse::from(snapshot)))
        }
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!(job_id = %id, error = %e, "Failed to retrieve job");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
