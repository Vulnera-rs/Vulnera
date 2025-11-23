use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use tracing::error;
use uuid::Uuid;

use crate::presentation::controllers::OrchestratorState;
use crate::presentation::models::{JobInvocationContextDto, JobStatusResponse};

/// GET /api/v1/jobs/{id} - Retrieve job by ID
#[utoipa::path(
    get,
    path = "/api/v1/jobs/{id}",
    params(
        ("id" = Uuid, Path, description = "Job ID")
    ),
    responses(
        (status = 200, description = "Job found", body = JobStatusResponse),
        (status = 404, description = "Job not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "jobs"
)]
pub async fn get_job(
    State(state): State<OrchestratorState>,
    Path(id): Path<Uuid>,
) -> Result<Json<JobStatusResponse>, StatusCode> {
    match state.job_store.get_snapshot(id).await {
        Ok(Some(snapshot)) => {
            let modules_completed = snapshot
                .module_results
                .iter()
                .filter(|r| r.error.is_none())
                .count();
            let modules_failed = snapshot
                .module_results
                .iter()
                .filter(|r| r.error.is_some())
                .count();

            let response = JobStatusResponse {
                job_id: snapshot.job_id,
                project_id: snapshot.project_id,
                status: format!("{:?}", snapshot.status),
                modules_completed,
                modules_failed,
                created_at: snapshot.created_at,
                started_at: snapshot.started_at,
                completed_at: snapshot.completed_at,
                error: snapshot.error,
                callback_url: snapshot.callback_url,
                invocation_context: snapshot
                    .invocation_context
                    .map(JobInvocationContextDto::from),
                summary: snapshot.summary,
                findings: snapshot.findings,
            };
            Ok(Json(response))
        }
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!(job_id = %id, error = %e, "Failed to retrieve job");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
