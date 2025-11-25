//! LLM API controllers

use axum::{
    Json,
    extract::State,
    response::{Sse, sse::Event},
};
use futures::stream::{Stream, StreamExt};
use std::convert::Infallible;
use tokio_stream::wrappers::ReceiverStream;

use crate::presentation::controllers::OrchestratorState;
use crate::presentation::models::{
    CodeFixResponse, ExplainVulnerabilityRequest, GenerateCodeFixRequest,
    NaturalLanguageQueryRequest, NaturalLanguageQueryResponse,
};

/// POST /api/v1/llm/fix - Generate code fix
#[utoipa::path(
    post,
    path = "/api/v1/llm/fix",
    request_body = GenerateCodeFixRequest,
    responses(
        (status = 200, description = "Code fix generated", body = CodeFixResponse),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error")
    ),
    tag = "llm"
)]
pub async fn generate_code_fix(
    State(state): State<OrchestratorState>,
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
        (status = 500, description = "Internal server error")
    ),
    tag = "llm"
)]
pub async fn explain_vulnerability(
    State(state): State<OrchestratorState>,
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
                        // Extract content from streaming response
                        let content = response
                            .choices
                            .first()
                            .and_then(|c| c.delta.as_ref().or(c.message.as_ref()))
                            .map(|m| m.content.clone())
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
        (status = 500, description = "Internal server error")
    ),
    tag = "llm"
)]
pub async fn natural_language_query(
    State(state): State<OrchestratorState>,
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
