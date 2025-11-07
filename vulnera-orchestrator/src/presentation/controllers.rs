//! Orchestrator API controllers

pub mod health;

use std::sync::Arc;
use std::time::Instant;

use axum::{extract::State, response::Json};
use vulnera_core::application::auth::use_cases::{
    LoginUseCase, RefreshTokenUseCase, RegisterUserUseCase, ValidateApiKeyUseCase,
    ValidateTokenUseCase,
};
use vulnera_core::application::reporting::ReportServiceImpl;
use vulnera_core::domain::vulnerability::repositories::IVulnerabilityRepository;
use vulnera_core::infrastructure::auth::{ApiKeyGenerator, JwtService, PasswordHasher};
use vulnera_core::infrastructure::cache::CacheServiceImpl;

use crate::application::use_cases::{
    AggregateResultsUseCase, CreateAnalysisJobUseCase, ExecuteAnalysisJobUseCase,
};
use crate::presentation::auth::extractors::AuthState;
use crate::presentation::models::{AnalysisRequest, FinalReportResponse};

/// Application state for orchestrator
#[derive(Clone)]
pub struct OrchestratorState {
    // Orchestrator use cases
    pub create_job_use_case: Arc<CreateAnalysisJobUseCase>,
    pub execute_job_use_case: Arc<ExecuteAnalysisJobUseCase>,
    pub aggregate_results_use_case: Arc<AggregateResultsUseCase>,
    
    // Services
    pub cache_service: Arc<CacheServiceImpl>,
    pub report_service: Arc<ReportServiceImpl>,
    pub vulnerability_repository: Arc<dyn IVulnerabilityRepository>,
    
    // Auth-related state
    pub db_pool: Arc<sqlx::PgPool>,
    pub user_repository: Arc<dyn vulnera_core::domain::auth::repositories::IUserRepository>,
    pub api_key_repository: Arc<dyn vulnera_core::domain::auth::repositories::IApiKeyRepository>,
    pub jwt_service: Arc<JwtService>,
    pub password_hasher: Arc<PasswordHasher>,
    pub api_key_generator: Arc<ApiKeyGenerator>,
    pub login_use_case: Arc<LoginUseCase>,
    pub register_use_case: Arc<RegisterUserUseCase>,
    pub validate_token_use_case: Arc<ValidateTokenUseCase>,
    pub refresh_token_use_case: Arc<RefreshTokenUseCase>,
    pub validate_api_key_use_case: Arc<ValidateApiKeyUseCase>,
    
    // Auth state (for extractors)
    pub auth_state: AuthState,
    
    // Config and metadata
    pub config: Arc<vulnera_core::Config>,
    pub startup_time: Instant,
}

/// POST /api/v1/analyze/job - Create and execute analysis job
#[utoipa::path(
    post,
    path = "/api/v1/analyze/job",
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

// Re-export health controllers
pub use health::*;
