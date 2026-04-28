use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use tracing::error;
use uuid::Uuid;

use crate::presentation::controllers::OrchestratorState;
use crate::presentation::models::JobStatusResponse;

/// GET /api/v1/jobs/{id} - Retrieve job by ID
#[utoipa::path(
    get,
    path = "/api/v1/jobs/{id}",
    params(
        ("id" = Uuid, Path, description = "Job ID")
    ),
    responses(
        (status = 200, description = "Job found"),
        (status = 404, description = "Job not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "jobs"
)]
pub async fn get_job(
    State(state): State<OrchestratorState>,
    Path(id): Path<Uuid>,
) -> Result<Json<JobStatusResponse>, StatusCode> {
    match state.orchestrator.job_store.get_snapshot(id).await {
        Ok(Some(snapshot)) => Ok(Json(JobStatusResponse::from(snapshot))),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!(job_id = %id, error = %e, "Failed to retrieve job");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
