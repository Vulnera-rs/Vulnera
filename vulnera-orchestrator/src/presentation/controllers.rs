//! Orchestrator API controllers

use axum::{extract::State, response::Json};
use std::sync::Arc;

use crate::application::use_cases::{
    AggregateResultsUseCase, CreateAnalysisJobUseCase, ExecuteAnalysisJobUseCase,
};
use crate::presentation::models::{AnalysisRequest, FinalReportResponse};

/// Application state for orchestrator
#[derive(Clone)]
pub struct OrchestratorState {
    pub create_job_use_case: Arc<CreateAnalysisJobUseCase>,
    pub execute_job_use_case: Arc<ExecuteAnalysisJobUseCase>,
    pub aggregate_results_use_case: Arc<AggregateResultsUseCase>,
}

/// POST /api/v1/analyze - Create and execute analysis job
#[utoipa::path(
    post,
    path = "/api/v1/analyze",
    request_body = AnalysisRequest,
    responses(
        (status = 200, description = "Analysis job created and executed", body = FinalReportResponse),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error")
    ),
    tag = "analysis"
)]
pub async fn analyze(
    State(state): State<OrchestratorState>,
    Json(request): Json<AnalysisRequest>,
) -> Result<Json<FinalReportResponse>, String> {
    // Parse request
    let source_type = request.parse_source_type()?;
    let analysis_depth = request.parse_analysis_depth()?;

    // Create job
    let mut job = state
        .create_job_use_case
        .execute(source_type, request.source_uri.clone(), analysis_depth)
        .await
        .map_err(|e| format!("Failed to create job: {}", e))?;

    // Execute job
    let module_results = state
        .execute_job_use_case
        .execute(&mut job, request.source_uri)
        .await
        .map_err(|e| format!("Failed to execute job: {}", e))?;

    // Aggregate results
    let report = state
        .aggregate_results_use_case
        .execute(&job, module_results);

    Ok(Json(FinalReportResponse {
        job_id: report.job_id,
        status: format!("{:?}", report.status),
        summary: report.summary,
        findings: report.findings,
    }))
}
