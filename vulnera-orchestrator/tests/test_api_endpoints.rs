//! Integration tests for API endpoint models

use chrono::{DateTime, Utc};
use uuid::Uuid;
use vulnera_orchestrator::domain::value_objects::{AnalysisDepth, SourceType};
use vulnera_orchestrator::presentation::models::{
    AnalysisRequest, ErrorResponse, HealthResponse, JobAcceptedResponse,
};

#[test]
fn test_analysis_request_parsing_git() {
    let raw = serde_json::json!({
        "source_type": "git",
        "source_uri": "https://github.com/owner/repo.git",
        "analysis_depth": "full",
    });

    let request: AnalysisRequest =
        serde_json::from_value(raw).expect("deserialization should succeed");

    assert_eq!(request.parse_source_type(), Ok(SourceType::Git));
    assert_eq!(request.parse_analysis_depth(), Ok(AnalysisDepth::Full));
}

#[test]
fn test_analysis_request_parsing_invalid_source_type() {
    let raw = serde_json::json!({
        "source_type": "invalid",
        "source_uri": "https://example.com",
        "analysis_depth": "full",
    });

    let request: AnalysisRequest =
        serde_json::from_value(raw).expect("deserialization should succeed");
    assert!(request.parse_source_type().is_err());
}

#[test]
fn test_job_accepted_response_serialization() {
    let response = JobAcceptedResponse {
        job_id: Uuid::nil(),
        status: "Accepted".to_string(),
        callback_url: None,
        message: "Job queued".to_string(),
    };

    let value = serde_json::to_value(&response).expect("serialization should succeed");
    assert_eq!(value["job_id"], "00000000-0000-0000-0000-000000000000");
    assert_eq!(value["status"], "Accepted");
    assert_eq!(value["message"], "Job queued");
}

#[test]
fn test_error_response_serialization() {
    let response = ErrorResponse {
        code: "PARSE_ERROR".to_string(),
        message: "Invalid input".to_string(),
        details: None,
        request_id: Uuid::nil(),
        timestamp: DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
            .unwrap()
            .with_timezone(&Utc),
    };

    let value = serde_json::to_value(&response).expect("serialization should succeed");
    assert_eq!(value["code"], "PARSE_ERROR");
    assert_eq!(value["message"], "Invalid input");
}

#[test]
fn test_health_response_serialization() {
    let response = HealthResponse {
        status: "healthy".to_string(),
        version: "1.0.0".to_string(),
        timestamp: DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
            .unwrap()
            .with_timezone(&Utc),
        details: Some(serde_json::json!({"db": "healthy"})),
    };

    let value = serde_json::to_value(&response).expect("serialization should succeed");
    assert_eq!(value["status"], "healthy");
    assert_eq!(value["version"], "1.0.0");
}
