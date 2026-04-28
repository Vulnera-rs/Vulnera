//! Orchestrator API controllers

pub mod health;
pub mod jobs;

use std::sync::Arc;
use std::time::Instant;

use axum::{extract::State, response::Json};

use vulnera_infrastructure::infrastructure::cache::dragonfly_cache::DragonflyCache;

use crate::application::use_cases::{
    AggregateResultsUseCase, CreateAnalysisJobUseCase, ExecuteAnalysisJobUseCase,
};
use crate::application::workflow::JobWorkflow;
use crate::domain::entities::JobInvocationContext;
use crate::infrastructure::git::GitService;
use crate::infrastructure::job_queue::{JobQueueHandle, QueuedAnalysisJob};
use crate::infrastructure::job_store::JobStore;
use crate::presentation::models::{AnalysisRequest, JobAcceptedResponse};
use axum::http::StatusCode;
use tracing::error;

/// Application state for orchestrator
#[derive(Clone)]
pub struct OrchestratorServices {
    pub create_job_use_case: Arc<CreateAnalysisJobUseCase>,
    pub execute_job_use_case: Arc<ExecuteAnalysisJobUseCase>,
    pub aggregate_results_use_case: Arc<AggregateResultsUseCase>,
    pub git_service: Arc<GitService>,
    pub job_store: Arc<dyn JobStore>,
    pub job_queue: JobQueueHandle,
    pub workflow: Arc<JobWorkflow>,
    pub db_pool: Arc<sqlx::PgPool>,
    pub cache_service: Arc<DragonflyCache>,
}

#[derive(Clone)]
pub struct OrchestratorState {
    pub orchestrator: Arc<OrchestratorServices>,
    pub config: Arc<vulnera_infrastructure::Config>,
    pub startup_time: Instant,
}

/// POST /api/v1/analyze/job - Create and execute analysis job
#[utoipa::path(
    post,
    path = "/api/v1/analyze/job",
    request_body = AnalysisRequest,
    responses(
        (status = 202, description = "Analysis job accepted for asynchronous execution", body = JobAcceptedResponse),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error")
    ),
    tag = "analysis"
)]
pub async fn analyze(
    State(state): State<OrchestratorState>,
    Json(request): Json<AnalysisRequest>,
) -> Result<(StatusCode, Json<JobAcceptedResponse>), String> {
    // Parse request
    let source_type = request.parse_source_type()?;
    let analysis_depth = request.parse_analysis_depth()?;

    // Create job
    let (job, project) = state
        .orchestrator
        .create_job_use_case
        .execute(
            source_type,
            request.source_uri.clone(),
            analysis_depth,
            None,
        )
        .await
        .map_err(|e| format!("Failed to create job: {}", e))?;

    let job_id = job.job_id;

    let invocation_context = JobInvocationContext {
        is_master_key: false,
    };
    let callback_url = request.callback_url.clone();
    let webhook_secret = request.webhook_secret.clone();

    // Transition Pending -> Queued via workflow (persists snapshot + audit trail)
    let mut job = job;
    if let Err(e) = state
        .orchestrator
        .workflow
        .enqueue_job(
            &mut job,
            &project,
            callback_url.clone(),
            Some(invocation_context.clone()),
        )
        .await
    {
        error!(%job_id, error = %e, "Failed to enqueue job");
        return Err(format!("Failed to enqueue job: {}", e));
    }

    // Push onto the background worker queue
    state
        .orchestrator
        .job_queue
        .enqueue(QueuedAnalysisJob {
            job,
            project,
            callback_url: callback_url.clone(),
            webhook_secret,
            invocation_context: Some(invocation_context),
        })
        .await
        .map_err(|e| format!("Failed to enqueue job: {}", e))?;

    Ok((
        StatusCode::ACCEPTED,
        Json(JobAcceptedResponse {
            job_id,
            status: "queued".to_string(),
            callback_url,
            message: "Analysis job accepted for asynchronous execution".to_string(),
        }),
    ))
}

// Re-export health controllers
pub use health::*;
