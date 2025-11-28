use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use tracing::{error, warn};
use uuid::Uuid;

use crate::presentation::auth::extractors::Auth;
use crate::presentation::controllers::OrchestratorState;
use crate::presentation::models::{JobInvocationContextDto, JobStatusResponse};

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
    match state.job_store.get_snapshot(id).await {
        Ok(Some(snapshot)) => {
            // Validate job ownership: only the user who created the job can access it
            // Master key bypass: allow master key authentication to access any job
            if !auth.is_master_key {
                if let Some(ref ctx) = snapshot.invocation_context {
                    if let Some(ref job_user_id) = ctx.user_id {
                        if job_user_id != &auth.user_id {
                            warn!(
                                job_id = %id,
                                requesting_user = %auth.user_id.as_str(),
                                job_owner = %job_user_id.as_str(),
                                "Unauthorized job access attempt"
                            );
                            return Err(StatusCode::FORBIDDEN);
                        }
                    }
                }
            }

            let modules = snapshot
                .module_results
                .iter()
                .map(|r| crate::presentation::models::ModuleResultDto {
                    module_type: format!("{:?}", r.module_type),
                    status: if r.error.is_none() {
                        "Completed".to_string()
                    } else {
                        "Failed".to_string()
                    },
                    files_scanned: r.metadata.files_scanned,
                    duration_ms: r.metadata.duration_ms,
                    findings_count: r.findings.len(),
                    metadata: Some(serde_json::to_value(&r.metadata).unwrap_or_default()),
                    error: r.error.clone(),
                })
                .collect();

            let response = JobStatusResponse {
                job_id: snapshot.job_id,
                project_id: snapshot.project_id,
                status: format!("{:?}", snapshot.status),
                created_at: snapshot.created_at,
                started_at: snapshot.started_at,
                completed_at: snapshot.completed_at,
                error: snapshot.error,
                callback_url: snapshot.callback_url,
                invocation_context: snapshot
                    .invocation_context
                    .map(JobInvocationContextDto::from),
                summary: snapshot
                    .summary
                    .unwrap_or_else(|| crate::domain::entities::Summary {
                        total_findings: 0,
                        by_severity: Default::default(),
                        by_type: crate::domain::entities::TypeBreakdown {
                            sast: 0,
                            secrets: 0,
                            dependencies: 0,
                            api: 0,
                        },
                        modules_completed: 0,
                        modules_failed: 0,
                    }),
                modules,
                findings_by_type: snapshot.findings_by_type.unwrap_or_else(|| {
                    crate::domain::entities::FindingsByType {
                        sast: vec![],
                        secrets: vec![],
                        dependencies: std::collections::HashMap::new(),
                        api: vec![],
                    }
                }),
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
