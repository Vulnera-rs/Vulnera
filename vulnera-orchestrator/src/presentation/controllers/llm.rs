//! LLM API controllers

use axum::{
    Json,
    extract::{Path, State},
    response::{Sse, sse::Event},
};
use futures::stream::{Stream, StreamExt};
use std::collections::HashMap;
use std::convert::Infallible;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use crate::presentation::auth::extractors::Auth;
use crate::presentation::controllers::OrchestratorState;
use crate::presentation::models::{
    CodeFixResponse, EnrichFindingsRequest, EnrichFindingsResponse, EnrichedFindingDto,
    ExplainVulnerabilityRequest, GenerateCodeFixRequest, NaturalLanguageQueryRequest,
    NaturalLanguageQueryResponse,
};

/// POST /api/v1/llm/fix - Generate code fix
#[utoipa::path(
    post,
    path = "/api/v1/llm/fix",
    request_body = GenerateCodeFixRequest,
    responses(
        (status = 200, description = "Code fix generated", body = CodeFixResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "llm",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn generate_code_fix(
    State(state): State<OrchestratorState>,
    _auth: Auth,
    Json(request): Json<GenerateCodeFixRequest>,
) -> Result<Json<CodeFixResponse>, String> {
    // Build vulnerability description from available fields
    let description = format!(
        "Vulnerability {} in {} code{}",
        request.vulnerability_id,
        request.language,
        request
            .context
            .as_ref()
            .map(|c| format!(" (context: {})", c))
            .unwrap_or_default()
    );

    let fix = state
        .generate_code_fix_use_case
        .execute(
            &request.vulnerability_id,
            &request.vulnerable_code,
            &description,
        )
        .await
        .map_err(|e| format!("Failed to generate code fix: {}", e))?;

    Ok(Json(CodeFixResponse {
        fixed_code: fix.suggested_code,
        explanation: fix.explanation,
        confidence: 0.85, // Default confidence, not provided by current LLM
    }))
}

/// POST /api/v1/llm/explain - Explain vulnerability (streaming)
#[utoipa::path(
    post,
    path = "/api/v1/llm/explain",
    request_body = ExplainVulnerabilityRequest,
    responses(
        (status = 200, description = "Explanation stream", body = String, content_type = "text/event-stream"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "llm",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn explain_vulnerability(
    State(state): State<OrchestratorState>,
    _auth: Auth,
    Json(request): Json<ExplainVulnerabilityRequest>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream_result = state
        .explain_vulnerability_use_case
        .execute_stream(
            &request.vulnerability_id,
            "unknown", // Severity not provided in request
            &request.description,
        )
        .await;

    let stream = match stream_result {
        Ok(rx) => ReceiverStream::new(rx)
            .map(|result| -> Result<Event, Infallible> {
                match result {
                    Ok(response) => {
                        // Extract content from streaming response - use content_str() to handle Option<String>
                        let content = response
                            .choices
                            .first()
                            .and_then(|c| c.delta.as_ref().or(c.message.as_ref()))
                            .map(|m| m.content_str())
                            .unwrap_or_default();
                        Ok(Event::default().data(content))
                    }
                    Err(e) => Ok(Event::default().event("error").data(e.to_string())),
                }
            })
            .boxed(),
        Err(e) => {
            let error_msg = format!("Failed to start explanation stream: {}", e);
            futures::stream::once(async move {
                Ok::<Event, Infallible>(Event::default().event("error").data(error_msg))
            })
            .boxed()
        }
    };

    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

/// POST /api/v1/llm/query - Natural language query
#[utoipa::path(
    post,
    path = "/api/v1/llm/query",
    request_body = NaturalLanguageQueryRequest,
    responses(
        (status = 200, description = "Query answered", body = NaturalLanguageQueryResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "llm",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn natural_language_query(
    State(state): State<OrchestratorState>,
    _auth: Auth,
    Json(request): Json<NaturalLanguageQueryRequest>,
) -> Result<Json<NaturalLanguageQueryResponse>, String> {
    let context_str = request
        .context
        .map(|c| serde_json::to_string(&c).unwrap_or_default())
        .unwrap_or_default();

    let answer = state
        .natural_language_query_use_case
        .execute(&request.query, &context_str)
        .await
        .map_err(|e| format!("Failed to execute query: {}", e))?;

    Ok(Json(NaturalLanguageQueryResponse {
        answer,
        references: vec![], // Not supported by current LLM provider
    }))
}

/// POST /api/v1/jobs/{job_id}/enrich - Enrich job findings with LLM insights
///
/// Enriches the top N findings (prioritized by severity: Critical > High > Medium > Low > Info)
/// with LLM-generated explanations, remediation suggestions, and risk summaries.
///
/// This is an on-demand operation typically triggered by a user action (e.g., clicking an
/// "Enrich with AI" button in the UI).
#[utoipa::path(
    post,
    path = "/api/v1/jobs/{job_id}/enrich",
    params(
        ("job_id" = Uuid, Path, description = "Job ID to enrich findings for")
    ),
    request_body = EnrichFindingsRequest,
    responses(
        (status = 200, description = "Findings enriched successfully", body = EnrichFindingsResponse),
        (status = 404, description = "Job not found"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "llm",
    security(
        ("cookie_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn enrich_job_findings(
    State(state): State<OrchestratorState>,
    _auth: Auth,
    Path(job_id): Path<Uuid>,
    Json(request): Json<EnrichFindingsRequest>,
) -> Result<Json<EnrichFindingsResponse>, (axum::http::StatusCode, String)> {
    use axum::http::StatusCode;

    // Fetch job snapshot
    let snapshot = state
        .job_store
        .get_snapshot(job_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch job: {}", e),
            )
        })?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("Job {} not found", job_id)))?;

    // Extract findings from module results
    let mut all_findings: Vec<vulnera_core::domain::module::Finding> = snapshot
        .module_results
        .iter()
        .flat_map(|result| result.findings.clone())
        .collect();

    if all_findings.is_empty() {
        return Ok(Json(EnrichFindingsResponse {
            job_id,
            enriched_count: 0,
            failed_count: 0,
            findings: vec![],
        }));
    }

    // Filter to specific finding IDs if provided
    if let Some(ref finding_ids) = request.finding_ids {
        if !finding_ids.is_empty() {
            all_findings.retain(|f| finding_ids.contains(&f.id));
        }
    }

    // Build code contexts map
    let code_contexts: HashMap<String, String> = request.code_contexts.unwrap_or_default();

    // Create enrichment request
    let enrich_request = vulnera_llm::EnrichFindingsRequest {
        findings: all_findings,
        code_contexts,
    };

    // Execute enrichment
    let enrich_response = state
        .enrich_findings_use_case
        .execute(enrich_request)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to enrich findings: {}", e),
            )
        })?;

    // Convert to response DTOs
    let enriched_findings: Vec<EnrichedFindingDto> = enrich_response
        .findings
        .into_iter()
        .filter(|f| f.enrichment.is_some())
        .map(|f| {
            let enrichment = f.enrichment.unwrap();
            EnrichedFindingDto {
                id: f.id,
                severity: format!("{:?}", f.severity),
                description: f.description,
                location: format!(
                    "{}:{}:{}",
                    f.location.path,
                    f.location.line.unwrap_or(0),
                    f.location.column.unwrap_or(0)
                ),
                explanation: enrichment.explanation,
                remediation_suggestion: enrichment.remediation_suggestion,
                risk_summary: enrichment.risk_summary,
                enrichment_successful: enrichment.enrichment_successful,
                enrichment_error: enrichment.error,
            }
        })
        .collect();

    Ok(Json(EnrichFindingsResponse {
        job_id,
        enriched_count: enrich_response.enriched_count,
        failed_count: enrich_response.failed_count,
        findings: enriched_findings,
    }))
}
