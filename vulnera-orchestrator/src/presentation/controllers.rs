//! Orchestrator API controllers

pub mod analytics;
pub mod health;
pub mod jobs;
pub mod llm;
pub mod organization;
pub mod repository;

use std::sync::Arc;
use std::time::Instant;

use axum::{extract::State, response::Json};
use vulnera_core::application::analytics::use_cases::{
    CheckQuotaUseCase, GetDashboardOverviewUseCase, GetMonthlyAnalyticsUseCase,
};
use vulnera_core::application::auth::use_cases::{
    LoginUseCase, RefreshTokenUseCase, RegisterUserUseCase, ValidateApiKeyUseCase,
    ValidateTokenUseCase,
};
use vulnera_core::application::organization::use_cases::{
    CreateOrganizationUseCase, DeleteOrganizationUseCase, GetOrganizationUseCase,
    InviteMemberUseCase, LeaveOrganizationUseCase, ListUserOrganizationsUseCase,
    RemoveMemberUseCase, TransferOwnershipUseCase, UpdateOrganizationNameUseCase,
};
use vulnera_core::application::reporting::ReportServiceImpl;
use vulnera_core::domain::organization::repositories::IOrganizationMemberRepository;
use vulnera_core::domain::vulnerability::repositories::IVulnerabilityRepository;
use vulnera_core::infrastructure::auth::{ApiKeyGenerator, JwtService, PasswordHasher};
use vulnera_core::infrastructure::cache::CacheServiceImpl;
use vulnera_core::infrastructure::rate_limiter::RateLimiterService;
use vulnera_deps::types::VersionResolutionService;

use crate::application::use_cases::{
    AggregateResultsUseCase, CreateAnalysisJobUseCase, ExecuteAnalysisJobUseCase,
};
use crate::domain::entities::{JobAuthStrategy, JobInvocationContext};
use crate::infrastructure::git::GitService;
use crate::infrastructure::job_queue::{JobQueueHandle, QueuedAnalysisJob};
use crate::infrastructure::job_store::{JobSnapshot, JobStore};
use crate::presentation::auth::extractors::{Auth, AuthState, OptionalApiKeyAuth, OptionalAwsCredentials};
use crate::presentation::models::{
    AffectedPackageDto, AnalysisMetadataDto, AnalysisRequest, BatchAnalysisMetadata,
    BatchDependencyAnalysisRequest, BatchDependencyAnalysisResponse, DependencyGraphDto,
    DependencyGraphEdgeDto, DependencyGraphNodeDto, FileAnalysisResult, JobAcceptedResponse,
    PackageDto, SeverityBreakdownDto, VersionRecommendationDto, VulnerabilityDto,
};
use axum::extract::Query;
use axum::http::StatusCode;
use serde::Deserialize;
use tokio::task::JoinSet;
use tracing::{error, info};
use vulnera_core::domain::vulnerability::{
    entities::{AnalysisReport, Package, Vulnerability},
    value_objects::Ecosystem,
};
use vulnera_deps::{
    AnalyzeDependenciesUseCase, DependencyGraph,
    services::repository_analysis::RepositoryAnalysisService,
};

/// Application state for orchestrator
#[derive(Clone)]
pub struct OrchestratorState {
    // Orchestrator use cases
    pub create_job_use_case: Arc<CreateAnalysisJobUseCase>,
    pub execute_job_use_case: Arc<ExecuteAnalysisJobUseCase>,
    pub aggregate_results_use_case: Arc<AggregateResultsUseCase>,
    pub git_service: Arc<GitService>,
    pub job_store: Arc<dyn JobStore>,
    pub job_queue: JobQueueHandle,

    // Services
    pub cache_service: Arc<CacheServiceImpl>,
    pub report_service: Arc<ReportServiceImpl>,
    pub vulnerability_repository: Arc<dyn IVulnerabilityRepository>,

    // Dependency analysis use case
    pub dependency_analysis_use_case: Arc<AnalyzeDependenciesUseCase<CacheServiceImpl>>,

    // Repository analysis service
    pub repository_analysis_service: Arc<dyn RepositoryAnalysisService>,

    // Version resolution service
    pub version_resolution_service: Arc<dyn VersionResolutionService>,

    // LLM use cases
    pub generate_code_fix_use_case:
        Arc<vulnera_llm::application::use_cases::GenerateCodeFixUseCase>,
    pub explain_vulnerability_use_case:
        Arc<vulnera_llm::application::use_cases::ExplainVulnerabilityUseCase>,
    pub natural_language_query_use_case:
        Arc<vulnera_llm::application::use_cases::NaturalLanguageQueryUseCase>,
    pub enrich_findings_use_case: Arc<vulnera_llm::application::use_cases::EnrichFindingsUseCase>,

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

    // Organization-related repositories
    pub organization_member_repository: Arc<dyn IOrganizationMemberRepository>,

    // Organization use cases
    pub create_organization_use_case: Arc<CreateOrganizationUseCase>,
    pub get_organization_use_case: Arc<GetOrganizationUseCase>,
    pub list_user_organizations_use_case: Arc<ListUserOrganizationsUseCase>,
    pub invite_member_use_case: Arc<InviteMemberUseCase>,
    pub remove_member_use_case: Arc<RemoveMemberUseCase>,
    pub leave_organization_use_case: Arc<LeaveOrganizationUseCase>,
    pub transfer_ownership_use_case: Arc<TransferOwnershipUseCase>,
    pub delete_organization_use_case: Arc<DeleteOrganizationUseCase>,
    pub update_organization_name_use_case: Arc<UpdateOrganizationNameUseCase>,

    // Analytics use cases
    pub get_dashboard_overview_use_case: Arc<GetDashboardOverviewUseCase>,
    pub get_monthly_analytics_use_case: Arc<GetMonthlyAnalyticsUseCase>,
    pub check_quota_use_case: Arc<CheckQuotaUseCase>,

    // Analytics service (for personal analytics)
    pub analytics_service: Arc<vulnera_core::application::analytics::AnalyticsAggregationService>,

    // Rate limiting service
    pub rate_limiter_service: Option<Arc<RateLimiterService>>,

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
        (status = 202, description = "Analysis job accepted for asynchronous execution", body = JobAcceptedResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "analysis",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn analyze(
    State(state): State<OrchestratorState>,
    auth: Auth,
    aws_credentials: OptionalAwsCredentials,
    Json(request): Json<AnalysisRequest>,
) -> Result<(StatusCode, Json<JobAcceptedResponse>), String> {
    use crate::presentation::auth::extractors::AuthMethod;

    // Parse request
    let source_type = request.parse_source_type()?;
    let analysis_depth = request.parse_analysis_depth()?;

    // Validate S3 bucket requests have credentials
    if source_type == crate::domain::value_objects::SourceType::S3Bucket
        && aws_credentials.0.is_none()
    {
        return Err(
            "S3 bucket source requires X-AWS-Credentials header with Base64-encoded JSON credentials"
                .to_string(),
        );
    }

    // Create job
    let (job, project) = state
        .create_job_use_case
        .execute(
            source_type,
            request.source_uri.clone(),
            analysis_depth,
            aws_credentials.0.as_ref(),
        )
        .await
        .map_err(|e| format!("Failed to create job: {}", e))?;

    let job_id = job.job_id;

    // Set auth strategy based on how the user authenticated
    let (auth_strategy, api_key_id) = match auth.auth_method {
        AuthMethod::Cookie => (JobAuthStrategy::Jwt, None),
        AuthMethod::ApiKey => (JobAuthStrategy::ApiKey, auth.api_key_id),
    };

    // Fetch user's organization for analytics tracking
    let organization_id = if !auth.is_master_key {
        state
            .list_user_organizations_use_case
            .execute(auth.user_id.clone())
            .await
            .ok()
            .and_then(|orgs| orgs.first().map(|org| org.id.clone()))
    } else {
        None
    };

    let invocation_context = JobInvocationContext {
        user_id: Some(auth.user_id),
        email: Some(auth.email.clone()),
        auth_strategy: Some(auth_strategy),
        api_key_id,
        organization_id,
        is_master_key: auth.is_master_key,
    };
    let callback_url = request.callback_url.clone();
    let webhook_secret = request.webhook_secret.clone();

    let snapshot = JobSnapshot {
        job_id,
        project_id: job.project_id.clone(),
        status: job.status.clone(),
        module_results: Vec::new(),
        project_metadata: project.metadata.clone(),
        created_at: job.created_at.to_rfc3339(),
        started_at: job.started_at.map(|t| t.to_rfc3339()),
        completed_at: job.completed_at.map(|t| t.to_rfc3339()),
        error: job.error.clone(),
        module_configs: std::collections::HashMap::new(),
        callback_url: callback_url.clone(),
        webhook_secret: None, // Don't persist secret
        invocation_context: Some(invocation_context.clone()),
        summary: None,
        findings_by_type: None,
    };
    if let Err(e) = state.job_store.save_snapshot(snapshot).await {
        error!(job_id = %job_id, error = %e, "Failed to persist pending job snapshot");
    }

    state
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

/// Query parameters for dependency analysis endpoint
#[derive(Deserialize)]
pub struct DependencyAnalysisQuery {
    /// Detail level: "minimal", "standard", or "full"
    #[serde(default = "default_detail_level")]
    pub detail_level: String,
}

fn default_detail_level() -> String {
    "standard".to_string()
}

/// Detail level enum for filtering response data
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DetailLevel {
    Minimal,
    Standard,
    Full,
}

impl DetailLevel {
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "minimal" => Ok(DetailLevel::Minimal),
            "standard" => Ok(DetailLevel::Standard),
            "full" => Ok(DetailLevel::Full),
            _ => Err(format!(
                "Invalid detail_level: {}. Must be 'minimal', 'standard', or 'full'",
                s
            )),
        }
    }
}

/// Convert Vulnerability entity to VulnerabilityDto
pub(super) fn vulnerability_to_dto(vuln: &Vulnerability) -> VulnerabilityDto {
    VulnerabilityDto {
        id: vuln.id.as_str().to_string(),
        summary: vuln.summary.clone(),
        description: vuln.description.clone(),
        severity: format!("{:?}", vuln.severity),
        affected_packages: vuln
            .affected_packages
            .iter()
            .map(|ap| AffectedPackageDto {
                name: ap.package.name.clone(),
                version: ap.package.version.to_string(),
                ecosystem: ap.package.ecosystem.canonical_name().to_string(),
                vulnerable_ranges: ap
                    .vulnerable_ranges
                    .iter()
                    .map(|vr| vr.to_string())
                    .collect(),
                fixed_versions: ap.fixed_versions.iter().map(|v| v.to_string()).collect(),
            })
            .collect(),
        references: vuln.references.clone(),
        published_at: vuln.published_at,
        sources: vuln.sources.iter().map(|s| format!("{:?}", s)).collect(),
    }
}

/// Convert Package entity to PackageDto
fn package_to_dto(pkg: &Package) -> PackageDto {
    PackageDto {
        name: pkg.name.clone(),
        version: pkg.version.to_string(),
        ecosystem: pkg.ecosystem.canonical_name().to_string(),
    }
}

/// Convert AnalysisMetadata to AnalysisMetadataDto
fn metadata_to_dto(
    metadata: &vulnera_core::domain::vulnerability::entities::AnalysisMetadata,
) -> AnalysisMetadataDto {
    AnalysisMetadataDto {
        total_packages: metadata.total_packages,
        vulnerable_packages: metadata.vulnerable_packages,
        total_vulnerabilities: metadata.total_vulnerabilities,
        severity_breakdown: SeverityBreakdownDto {
            critical: metadata.severity_breakdown.critical,
            high: metadata.severity_breakdown.high,
            medium: metadata.severity_breakdown.medium,
            low: metadata.severity_breakdown.low,
        },
        analysis_duration_ms: metadata.analysis_duration.as_millis() as u64,
        sources_queried: metadata.sources_queried.clone(),
    }
}

/// Convert DependencyGraph to DependencyGraphDto
fn dependency_graph_to_dto(graph: &DependencyGraph) -> DependencyGraphDto {
    let nodes: Vec<DependencyGraphNodeDto> = graph
        .nodes
        .values()
        .map(|node| DependencyGraphNodeDto {
            package: package_to_dto(&node.package),
            dependencies: node
                .direct_dependencies
                .iter()
                .map(|id| id.to_string())
                .collect(),
            is_direct: node.metadata.is_direct,
        })
        .collect();

    let edges: Vec<DependencyGraphEdgeDto> = graph
        .edges
        .iter()
        .map(|edge| DependencyGraphEdgeDto {
            from: edge.from.to_string(),
            to: edge.to.to_string(),
            is_transitive: edge.is_transitive,
        })
        .collect();

    DependencyGraphDto {
        nodes,
        edges,
        package_count: graph.package_count(),
        dependency_count: graph.dependency_count(),
    }
}

/// Convert VersionRecommendation to VersionRecommendationDto
pub(super) fn version_recommendation_to_dto(
    package: &Package,
    recommendation: &vulnera_deps::types::VersionRecommendation,
) -> VersionRecommendationDto {
    use vulnera_deps::types::UpgradeImpact;

    VersionRecommendationDto {
        package: package.name.clone(),
        ecosystem: package.ecosystem.canonical_name().to_string(),
        current_version: Some(package.version.to_string()),
        nearest_safe_above_current: recommendation
            .nearest_safe_above_current
            .as_ref()
            .map(|v| v.to_string()),
        most_up_to_date_safe: recommendation
            .most_up_to_date_safe
            .as_ref()
            .map(|v| v.to_string()),
        next_safe_minor_within_current_major: recommendation
            .next_safe_minor_within_current_major
            .as_ref()
            .map(|v| v.to_string()),
        nearest_impact: recommendation.nearest_impact.map(|impact| match impact {
            UpgradeImpact::Major => "major".to_string(),
            UpgradeImpact::Minor => "minor".to_string(),
            UpgradeImpact::Patch => "patch".to_string(),
            UpgradeImpact::Unknown => "unknown".to_string(),
        }),
        most_up_to_date_impact: recommendation
            .most_up_to_date_impact
            .map(|impact| match impact {
                UpgradeImpact::Major => "major".to_string(),
                UpgradeImpact::Minor => "minor".to_string(),
                UpgradeImpact::Patch => "patch".to_string(),
                UpgradeImpact::Unknown => "unknown".to_string(),
            }),
        prerelease_exclusion_applied: Some(recommendation.prerelease_exclusion_applied),
        notes: if recommendation.notes.is_empty() {
            None
        } else {
            Some(recommendation.notes.clone())
        },
    }
}

/// Convert AnalysisReport to FileAnalysisResult based on detail level
async fn convert_analysis_report_to_response(
    report: &AnalysisReport,
    filename: Option<String>,
    ecosystem: Ecosystem,
    detail_level: DetailLevel,
    dependency_graph: Option<&DependencyGraph>,
    version_resolution_service: Arc<dyn VersionResolutionService>,
) -> FileAnalysisResult {
    let vulnerabilities: Vec<VulnerabilityDto> = report
        .vulnerabilities
        .iter()
        .map(vulnerability_to_dto)
        .collect();

    let packages = if detail_level >= DetailLevel::Standard {
        Some(report.packages.iter().map(package_to_dto).collect())
    } else {
        None
    };

    let dependency_graph_dto = if detail_level == DetailLevel::Full {
        dependency_graph.map(dependency_graph_to_dto)
    } else {
        None
    };

    // Compute version recommendations for vulnerable packages
    let version_recommendations = if detail_level >= DetailLevel::Standard {
        // Collect unique vulnerable packages (deduplicate by identifier)
        let mut vulnerable_packages: std::collections::HashMap<String, &Package> =
            std::collections::HashMap::new();
        for vuln in &report.vulnerabilities {
            for affected_pkg in &vuln.affected_packages {
                let identifier = affected_pkg.package.identifier();
                vulnerable_packages
                    .entry(identifier)
                    .or_insert(&affected_pkg.package);
            }
        }

        if !vulnerable_packages.is_empty() {
            // Collect vulnerabilities per package for recommendation computation
            // We need to collect references to vulnerabilities for each package
            let mut package_vulnerability_indices: std::collections::HashMap<String, Vec<usize>> =
                std::collections::HashMap::new();
            for (vuln_idx, vuln) in report.vulnerabilities.iter().enumerate() {
                for affected_pkg in &vuln.affected_packages {
                    let identifier = affected_pkg.package.identifier();
                    package_vulnerability_indices
                        .entry(identifier)
                        .or_default()
                        .push(vuln_idx);
                }
            }

            // Compute recommendations for each vulnerable package
            let mut recommendations = Vec::new();
            for (identifier, package) in &vulnerable_packages {
                if let Some(vuln_indices) = package_vulnerability_indices.get(identifier) {
                    // Collect vulnerabilities for this package
                    // The recommend function expects &[Vulnerability], so we need to work with indices
                    // and create a slice from the report's vulnerabilities
                    let vulns: Vec<&Vulnerability> = vuln_indices
                        .iter()
                        .map(|&idx| &report.vulnerabilities[idx])
                        .collect();

                    // Since we can't convert &[&Vulnerability] to &[Vulnerability] without cloning,
                    // and the trait expects &[Vulnerability], we need to work around this.
                    // The trait signature requires owned values, but we have references.
                    // We'll need to clone the vulnerabilities for the recommendation call.
                    let vulns_owned: Vec<Vulnerability> =
                        vulns.iter().map(|v| (*v).clone()).collect();

                    match version_resolution_service
                        .recommend(
                            package.ecosystem.clone(),
                            &package.name,
                            Some(package.version.clone()),
                            &vulns_owned,
                        )
                        .await
                    {
                        Ok(recommendation) => {
                            recommendations
                                .push(version_recommendation_to_dto(package, &recommendation));
                        }
                        Err(e) => {
                            error!(
                                "Failed to compute version recommendation for {}: {}",
                                identifier, e
                            );
                            // Continue with other packages
                        }
                    }
                }
            }

            if recommendations.is_empty() {
                None
            } else {
                Some(recommendations)
            }
        } else {
            None
        }
    } else {
        None
    };

    FileAnalysisResult {
        filename,
        ecosystem: ecosystem.canonical_name().to_string(),
        vulnerabilities,
        packages,
        dependency_graph: dependency_graph_dto,
        version_recommendations,
        metadata: metadata_to_dto(&report.metadata),
        error: None,
        cache_hit: None,
        workspace_path: None,
    }
}

/// POST /api/v1/dependencies/analyze - Analyze dependency files (synchronous, batch support)
///
/// This endpoint accepts optional API key authentication via the `X-API-Key` header or `Authorization: ApiKey <key>` header.
/// Authenticated requests have higher rate limits and batch size limits.
/// Unauthenticated requests are limited to 10 analyzes per day and 10 files per batch.
///
/// **Extension Optimization Features:**
/// - Batch processing for multiple files in one request
/// - Configurable detail levels (minimal/standard/full)
/// - Optional caching for faster repeated analysis
/// - Compact mode for reduced payload size
/// - Workspace path tracking for better context
#[utoipa::path(
    post,
    path = "/api/v1/dependencies/analyze",
    params(
        ("detail_level" = Option<String>, Query, description = "Detail level: 'minimal', 'standard', or 'full' (default: 'standard')")
    ),
    request_body = BatchDependencyAnalysisRequest,
    responses(
        (status = 200, description = "Analysis completed", body = BatchDependencyAnalysisResponse),
        (status = 400, description = "Invalid request"),
        (status = 429, description = "Rate limit exceeded"),
        (status = 500, description = "Internal server error")
    ),
    tag = "dependencies",
    security(
        ()  // Empty security requirement - API key authentication is optional
    )
)]
pub async fn analyze_dependencies(
    State(state): State<OrchestratorState>,
    Query(query): Query<DependencyAnalysisQuery>,
    OptionalApiKeyAuth(maybe_api_key): OptionalApiKeyAuth,
    Json(request): Json<BatchDependencyAnalysisRequest>,
) -> Result<Json<BatchDependencyAnalysisResponse>, (StatusCode, String)> {
    let start_time = std::time::Instant::now();
    let is_authenticated = maybe_api_key.is_some();

    info!(
        authenticated = is_authenticated,
        file_count = request.files.len(),
        "Starting batch dependency analysis"
    );

    // Parse detail level
    let detail_level =
        DetailLevel::from_str(&query.detail_level).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // Validate batch size limits
    let max_files = if is_authenticated {
        state.config.analysis.max_concurrent_packages * 2 // More lenient for authenticated
    } else {
        10 // Stricter for unauthenticated
    };

    if request.files.len() > max_files {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Batch size exceeds limit: {} files (max: {} for {}, {} for authenticated)",
                request.files.len(),
                max_files,
                if is_authenticated {
                    "authenticated"
                } else {
                    "unauthenticated"
                },
                state.config.analysis.max_concurrent_packages * 2
            ),
        ));
    }

    // Process files in parallel
    let mut join_set: JoinSet<Result<FileAnalysisResult, String>> = JoinSet::new();
    let use_case = state.dependency_analysis_use_case.clone();
    let total_files = request.files.len();

    let version_resolution_service = state.version_resolution_service.clone();

    for file_request in request.files {
        let use_case_clone = use_case.clone();
        let detail_level_clone = detail_level;
        let version_resolution_service_clone = version_resolution_service.clone();
        let workspace_path = file_request.workspace_path.clone();

        join_set.spawn(async move {
            // Parse ecosystem
            let ecosystem = match file_request.ecosystem.to_lowercase().as_str() {
                "npm" => Ecosystem::Npm,
                "pypi" | "pip" | "python" => Ecosystem::PyPI,
                "maven" => Ecosystem::Maven,
                "cargo" | "rust" => Ecosystem::Cargo,
                "go" => Ecosystem::Go,
                "packagist" | "composer" | "php" => Ecosystem::Packagist,
                _ => {
                    return Err(format!("Invalid ecosystem: {}", file_request.ecosystem));
                }
            };

            let ecosystem_for_response = ecosystem.clone();
            let filename_for_response = file_request.filename.clone();

            // Execute analysis
            match use_case_clone
                .execute(
                    &file_request.file_content,
                    ecosystem.clone(),
                    file_request.filename.as_deref(),
                )
                .await
            {
                Ok((report, dependency_graph)) => {
                    let mut result = convert_analysis_report_to_response(
                        &report,
                        filename_for_response,
                        ecosystem_for_response,
                        detail_level_clone,
                        Some(&dependency_graph),
                        version_resolution_service_clone,
                    )
                    .await;
                    result.workspace_path = workspace_path;
                    result.cache_hit = Some(false); // TODO: Implement actual cache tracking
                    Ok(result)
                }
                Err(e) => {
                    error!("Analysis failed: {}", e);
                    Err(format!("Analysis failed: {}", e))
                }
            }
        });
    }

    // Collect results
    let mut results = Vec::new();
    let mut successful = 0;
    let mut failed = 0;
    let mut total_vulnerabilities = 0;
    let mut total_packages = 0;
    let mut critical_count = 0;
    let mut high_count = 0;

    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(Ok(file_result)) => {
                successful += 1;
                total_vulnerabilities += file_result.vulnerabilities.len();

                // Count critical and high vulnerabilities for quick extension reference
                for vuln in &file_result.vulnerabilities {
                    match vuln.severity.as_str() {
                        "Critical" => critical_count += 1,
                        "High" => high_count += 1,
                        _ => {}
                    }
                }

                if let Some(ref packages) = file_result.packages {
                    total_packages += packages.len();
                } else {
                    // If packages not included, we can't count them
                    // This is fine for minimal detail level
                }
                results.push(file_result);
            }
            Ok(Err(error_msg)) => {
                failed += 1;
                results.push(FileAnalysisResult {
                    filename: None,
                    ecosystem: "unknown".to_string(),
                    vulnerabilities: vec![],
                    packages: None,
                    dependency_graph: None,
                    version_recommendations: None,
                    metadata: AnalysisMetadataDto {
                        total_packages: 0,
                        vulnerable_packages: 0,
                        total_vulnerabilities: 0,
                        severity_breakdown: SeverityBreakdownDto {
                            critical: 0,
                            high: 0,
                            medium: 0,
                            low: 0,
                        },
                        analysis_duration_ms: 0,
                        sources_queried: vec![],
                    },
                    error: Some(error_msg),
                    cache_hit: None,
                    workspace_path: None,
                });
            }
            Err(e) => {
                failed += 1;
                error!("Join error: {}", e);
                results.push(FileAnalysisResult {
                    filename: None,
                    ecosystem: "unknown".to_string(),
                    vulnerabilities: vec![],
                    packages: None,
                    dependency_graph: None,
                    version_recommendations: None,
                    metadata: AnalysisMetadataDto {
                        total_packages: 0,
                        vulnerable_packages: 0,
                        total_vulnerabilities: 0,
                        severity_breakdown: SeverityBreakdownDto {
                            critical: 0,
                            high: 0,
                            medium: 0,
                            low: 0,
                        },
                        analysis_duration_ms: 0,
                        sources_queried: vec![],
                    },
                    error: Some(format!("Internal error: {}", e)),
                    cache_hit: None,
                    workspace_path: None,
                });
            }
        }
    }

    let duration = start_time.elapsed();

    info!(
        authenticated = is_authenticated,
        successful,
        failed,
        duration_ms = duration.as_millis(),
        "Batch dependency analysis completed"
    );

    Ok(Json(BatchDependencyAnalysisResponse {
        results,
        metadata: BatchAnalysisMetadata {
            total_files,
            successful,
            failed,
            duration_ms: duration.as_millis() as u64,
            total_vulnerabilities,
            total_packages,
            cache_hits: None, // TODO: Implement cache hit tracking
            critical_count,
            high_count,
        },
    }))
}

// Re-export health controllers
pub use health::*;

// Re-export repository controller(s)
pub use repository::analyze_repository;
