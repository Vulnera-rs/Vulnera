//! Repository analysis controller

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use tracing::{info, warn};
use url::Url;
use uuid::Uuid;

use crate::presentation::auth::extractors::Auth;
use crate::presentation::controllers::{
    OrchestratorState, version_recommendation_to_dto, vulnerability_to_dto,
};
use crate::presentation::middleware::application_error_to_response;
use crate::presentation::models::{
    ErrorResponse, RepositoryAnalysisMetadataDto, RepositoryAnalysisRequest,
    RepositoryAnalysisResponse, RepositoryConfigCapsDto, RepositoryDescriptorDto,
    RepositoryFileResultDto, RepositoryPackageDto, SeverityBreakdownDto,
};
use vulnera_core::domain::vulnerability::entities::{Package, SeverityBreakdown, Vulnerability};
use vulnera_deps::services::repository_analysis::{
    RepositoryAnalysisInput, RepositoryAnalysisInternalResult, RepositoryFileResultInternal,
};
use vulnera_deps::types::VersionResolutionService;

/// POST /api/v1/analyze/repository - Analyze an entire repository's manifests
#[utoipa::path(
    post,
    path = "/api/v1/analyze/repository",
    request_body = RepositoryAnalysisRequest,
    responses(
        (status = 200, description = "Repository analysis completed", body = RepositoryAnalysisResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Repository not found", body = ErrorResponse),
        (status = 429, description = "Upstream rate limited", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "analysis",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn analyze_repository(
    State(state): State<OrchestratorState>,
    _auth: Auth,
    Json(request): Json<RepositoryAnalysisRequest>,
) -> Result<Json<RepositoryAnalysisResponse>, Response> {
    let RepositoryAnalysisRequest {
        repository_url,
        owner,
        repo,
        r#ref,
        include_paths,
        exclude_paths,
        max_files,
        include_lockfiles,
        return_packages,
    } = request;

    let coordinates = resolve_repository_coordinates(
        repository_url.as_deref(),
        owner.as_deref(),
        repo.as_deref(),
    )?;

    let requested_ref = r#ref.or_else(|| coordinates.derived_ref.clone());
    let include_packages_in_response = return_packages.unwrap_or(false);
    let should_collect_packages = include_packages_in_response
        || state.config.recommendations.max_version_queries_per_request > 0;

    let requested_max_files =
        max_files.unwrap_or(state.config.apis.github.max_files_scanned as u32);
    let safe_max_files =
        requested_max_files.clamp(1, state.config.apis.github.max_files_scanned as u32);

    info!(
        owner = %coordinates.owner,
        repo = %coordinates.repo,
        ?requested_ref,
        max_files = safe_max_files,
        include_packages = include_packages_in_response,
        "Repository analysis requested"
    );

    let input = RepositoryAnalysisInput {
        owner: coordinates.owner.clone(),
        repo: coordinates.repo.clone(),
        requested_ref: requested_ref.clone(),
        include_paths: sanitize_paths(include_paths),
        exclude_paths: sanitize_paths(exclude_paths),
        max_files: safe_max_files,
        include_lockfiles: include_lockfiles.unwrap_or(true),
        return_packages: should_collect_packages,
    };

    let analysis_result = state
        .dependencies
        .repository_analysis_service
        .analyze_repository(input)
        .await
        .map_err(application_error_to_response)?;

    let config_caps = RepositoryConfigCapsDto {
        max_files_scanned: state.config.apis.github.max_files_scanned as u32,
        max_total_bytes: state.config.apis.github.max_total_bytes,
    };

    let response = transform_repository_result(
        analysis_result,
        &coordinates,
        requested_ref,
        include_packages_in_response,
        coordinates.source_url.clone().or_else(|| {
            Some(format!(
                "https://github.com/{}/{}",
                coordinates.owner, coordinates.repo
            ))
        }),
        state.dependencies.version_resolution_service.clone(),
        state.config.recommendations.max_version_queries_per_request,
        config_caps,
    )
    .await;

    Ok(Json(response))
}

#[derive(Debug, Clone)]
struct RepositoryCoordinates {
    owner: String,
    repo: String,
    derived_ref: Option<String>,
    source_url: Option<String>,
}

fn resolve_repository_coordinates(
    repository_url: Option<&str>,
    owner: Option<&str>,
    repo: Option<&str>,
) -> Result<RepositoryCoordinates, Response> {
    if let Some(url) = repository_url {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            return Err(validation_error_response("repository_url cannot be empty"));
        }
        let (owner, repo, derived_ref) =
            parse_repository_identifier(trimmed).map_err(validation_error_response)?;
        return Ok(RepositoryCoordinates {
            owner,
            repo,
            derived_ref,
            source_url: Some(trimmed.to_string()),
        });
    }

    let owner_val = owner
        .and_then(|value| {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
        .ok_or_else(|| {
            validation_error_response("owner is required when repository_url is not provided")
        })?;

    let repo_val = repo
        .and_then(|value| {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
        .ok_or_else(|| {
            validation_error_response("repo is required when repository_url is not provided")
        })?;

    Ok(RepositoryCoordinates {
        owner: owner_val.clone(),
        repo: repo_val.trim_end_matches(".git").to_string(),
        derived_ref: None,
        source_url: Some(format!("https://github.com/{}/{}", owner_val, repo_val)),
    })
}

fn parse_repository_identifier(input: &str) -> Result<(String, String, Option<String>), String> {
    if let Ok(parsed) = Url::parse(input) {
        return parse_owner_repo_from_path(parsed.path());
    }

    // Handle common scp-like syntax: git@github.com:owner/repo.git
    if input.contains('@') && input.contains(':') && !input.contains("//") {
        let mut parts = input.splitn(2, ':');
        let user_host = parts.next().unwrap_or_default();
        let path_part = parts.next().unwrap_or_default();
        let ssh_url = format!("ssh://{}/{}", user_host, path_part.trim_start_matches('/'));
        if let Ok(parsed) = Url::parse(&ssh_url) {
            return parse_owner_repo_from_path(parsed.path());
        }
    }

    parse_owner_repo_from_path(input)
}

fn parse_owner_repo_from_path(path: &str) -> Result<(String, String, Option<String>), String> {
    let cleaned = path
        .trim()
        .trim_start_matches('/')
        .trim_end_matches('/')
        .trim_end_matches(".git");
    if cleaned.is_empty() {
        return Err("Repository identifier must include owner and repo".to_string());
    }

    let (without_ref, ref_suffix) = if let Some(idx) = cleaned.rfind('@') {
        let (left, right) = cleaned.split_at(idx);
        if left.contains('/') {
            (left, Some(right.trim_start_matches('@').to_string()))
        } else {
            (cleaned, None)
        }
    } else {
        (cleaned, None)
    };

    let mut parts: Vec<&str> = without_ref
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if parts.len() >= 3 && parts[0].contains('.') {
        parts.remove(0);
    }
    if parts.len() < 2 {
        return Err("Repository identifier must include both owner and repo".to_string());
    }

    let owner = parts[0].trim().to_string();
    let repo = parts[1].trim().trim_end_matches(".git").to_string();
    if owner.is_empty() || repo.is_empty() {
        return Err("Repository owner and repo cannot be empty".to_string());
    }

    let mut remaining: Vec<&str> = parts[2..].to_vec();
    let mut derived_ref = ref_suffix;
    if derived_ref.is_none() && !remaining.is_empty() {
        if matches!(remaining[0], "tree" | "blob" | "commit") {
            remaining.remove(0);
        }
        if !remaining.is_empty() {
            derived_ref = Some(remaining.join("/"));
        }
    }

    Ok((owner, repo, derived_ref))
}

fn sanitize_paths(paths: Option<Vec<String>>) -> Option<Vec<String>> {
    paths
        .map(|values| {
            values
                .into_iter()
                .map(|p| {
                    p.trim()
                        .trim_start_matches("./")
                        .trim_start_matches('/')
                        .to_string()
                })
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
        })
        .filter(|values| !values.is_empty())
}

fn validation_error_response(message: impl Into<String>) -> Response {
    let error_response = ErrorResponse {
        code: "VALIDATION_ERROR".to_string(),
        message: message.into(),
        details: None,
        request_id: Uuid::new_v4(),
        timestamp: Utc::now(),
    };
    (StatusCode::BAD_REQUEST, Json(error_response)).into_response()
}

async fn transform_repository_result(
    result: RepositoryAnalysisInternalResult,
    coordinates: &RepositoryCoordinates,
    requested_ref: Option<String>,
    include_packages_in_response: bool,
    source_url: Option<String>,
    version_resolution_service: Arc<dyn VersionResolutionService>,
    max_version_queries: usize,
    config_caps: RepositoryConfigCapsDto,
) -> RepositoryAnalysisResponse {
    let repository_descriptor = RepositoryDescriptorDto {
        owner: coordinates.owner.clone(),
        repo: coordinates.repo.clone(),
        requested_ref: requested_ref.or(result.requested_ref.clone()),
        commit_sha: result.commit_sha.clone(),
        source_url,
    };

    let files = map_file_results(&result.files, include_packages_in_response);
    let vulnerabilities: Vec<_> = result
        .vulnerabilities
        .iter()
        .map(vulnerability_to_dto)
        .collect();
    let metadata = build_metadata(&result, config_caps);

    let version_recommendations =
        if max_version_queries == 0 || result.files.iter().all(|file| file.packages.is_empty()) {
            None
        } else {
            compute_repository_version_recommendations(
                &result.files,
                &result.vulnerabilities,
                version_resolution_service,
                max_version_queries,
            )
            .await
        };

    RepositoryAnalysisResponse {
        id: result.id,
        repository: repository_descriptor,
        files,
        vulnerabilities,
        metadata,
        version_recommendations,
    }
}

fn map_file_results(
    files: &[RepositoryFileResultInternal],
    include_packages_in_response: bool,
) -> Vec<RepositoryFileResultDto> {
    files
        .iter()
        .map(|file| RepositoryFileResultDto {
            path: file.path.clone(),
            ecosystem: file
                .ecosystem
                .as_ref()
                .map(|ecosystem| ecosystem.canonical_name().to_string()),
            packages_count: file.packages.len() as u32,
            packages: if include_packages_in_response && !file.packages.is_empty() {
                Some(
                    file.packages
                        .iter()
                        .map(package_to_repository_package_dto)
                        .collect(),
                )
            } else {
                None
            },
            error: file.error.clone(),
        })
        .collect()
}

fn package_to_repository_package_dto(package: &Package) -> RepositoryPackageDto {
    RepositoryPackageDto {
        name: package.name.clone(),
        version: package.version.to_string(),
        ecosystem: package.ecosystem.canonical_name().to_string(),
    }
}

fn build_metadata(
    result: &RepositoryAnalysisInternalResult,
    config_caps: RepositoryConfigCapsDto,
) -> RepositoryAnalysisMetadataDto {
    RepositoryAnalysisMetadataDto {
        total_files_scanned: result.total_files_scanned,
        analyzed_files: result.analyzed_files,
        skipped_files: result.skipped_files,
        unique_packages: result.unique_packages,
        total_vulnerabilities: result.vulnerabilities.len() as u32,
        severity_breakdown: severity_breakdown_to_dto(&result.severity_breakdown),
        duration_ms: result.duration.as_millis() as u64,
        file_errors: result.file_errors,
        rate_limit_remaining: result.rate_limit_remaining,
        truncated: result.truncated,
        config_caps,
    }
}

fn severity_breakdown_to_dto(breakdown: &SeverityBreakdown) -> SeverityBreakdownDto {
    SeverityBreakdownDto {
        critical: breakdown.critical,
        high: breakdown.high,
        medium: breakdown.medium,
        low: breakdown.low,
    }
}

async fn compute_repository_version_recommendations(
    files: &[RepositoryFileResultInternal],
    vulnerabilities: &[Vulnerability],
    version_resolution_service: Arc<dyn VersionResolutionService>,
    max_queries: usize,
) -> Option<Vec<crate::presentation::models::VersionRecommendationDto>> {
    if max_queries == 0 {
        return None;
    }

    let mut packages: HashMap<String, Package> = HashMap::new();
    for file in files {
        for package in &file.packages {
            packages
                .entry(package.identifier())
                .or_insert_with(|| package.clone());
        }
    }

    if packages.is_empty() {
        return None;
    }

    let mut unique_packages: Vec<Package> = packages.into_values().collect();
    unique_packages.sort_by_key(|a| a.identifier());

    let limit = max_queries.min(unique_packages.len());
    let mut recommendations = Vec::new();

    for package in unique_packages.into_iter().take(limit) {
        let mut package_vulnerabilities: Vec<Vulnerability> = Vec::new();
        for vuln in vulnerabilities {
            if vuln.affects_package(&package) {
                package_vulnerabilities.push(vuln.clone());
            }
        }

        if package_vulnerabilities.is_empty() {
            continue;
        }

        match version_resolution_service
            .recommend(
                package.ecosystem.clone(),
                &package.name,
                Some(package.version.clone()),
                &package_vulnerabilities,
            )
            .await
        {
            Ok(recommendation) => {
                recommendations.push(version_recommendation_to_dto(&package, &recommendation));
            }
            Err(error) => {
                warn!(
                    package = %package.identifier(),
                    error = %error,
                    "Failed to compute version recommendation for repository package"
                );
            }
        }
    }

    if recommendations.is_empty() {
        None
    } else {
        Some(recommendations)
    }
}
