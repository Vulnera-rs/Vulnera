//! Integration tests for API endpoints

use vulnera_orchestrator::presentation::models::{
    BatchAnalysisMetadata, BatchDependencyAnalysisRequest, BatchDependencyAnalysisResponse,
    FileAnalysisResult, SeverityBreakdownDto,
};

#[tokio::test]
async fn test_health_endpoint() {
    // Placeholder until full router harness is added.
}

#[tokio::test]
async fn test_metrics_endpoint() {
    // Placeholder until full router harness is added.
}

#[test]
fn test_batch_request_supports_file_id_contract() {
    let raw = serde_json::json!({
        "files": [
            {
                "file_id": "file:///workspace/frontend/package.json",
                "file_content": "{\"dependencies\":{\"lodash\":\"4.17.20\"}}",
                "ecosystem": "npm",
                "filename": "package.json",
                "workspace_path": "/workspace/frontend/package.json"
            }
        ],
        "enable_cache": true,
        "compact_mode": false
    });

    let request: BatchDependencyAnalysisRequest =
        serde_json::from_value(raw).expect("request deserialization should succeed");

    assert_eq!(request.files.len(), 1);
    assert_eq!(
        request.files[0].file_id.as_deref(),
        Some("file:///workspace/frontend/package.json")
    );
}

#[test]
fn test_batch_response_supports_request_id_and_file_id_contract() {
    let response = BatchDependencyAnalysisResponse {
        results: vec![FileAnalysisResult {
            file_id: Some("file:///workspace/frontend/package.json".to_string()),
            filename: Some("package.json".to_string()),
            ecosystem: "npm".to_string(),
            vulnerabilities: vec![],
            packages: None,
            dependency_graph: None,
            version_recommendations: None,
            metadata: vulnera_orchestrator::presentation::models::AnalysisMetadataDto {
                total_packages: 1,
                vulnerable_packages: 0,
                total_vulnerabilities: 0,
                severity_breakdown: SeverityBreakdownDto {
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0,
                },
                analysis_duration_ms: 3,
                sources_queried: vec![],
            },
            error: None,
            cache_hit: Some(false),
            workspace_path: Some("/workspace/frontend/package.json".to_string()),
        }],
        metadata: BatchAnalysisMetadata {
            request_id: Some("3dd8a6d0-a6f6-4622-9f9c-53d84fd0c7ad".to_string()),
            total_files: 1,
            successful: 1,
            failed: 0,
            duration_ms: 3,
            total_vulnerabilities: 0,
            total_packages: 1,
            cache_hits: Some(0),
            critical_count: 0,
            high_count: 0,
        },
    };

    let value = serde_json::to_value(&response).expect("response serialization should succeed");

    let request_id = value
        .get("metadata")
        .and_then(|metadata| metadata.get("request_id"))
        .and_then(|id| id.as_str());
    let file_id = value
        .get("results")
        .and_then(|results| results.get(0))
        .and_then(|result| result.get("file_id"))
        .and_then(|id| id.as_str());

    assert_eq!(request_id, Some("3dd8a6d0-a6f6-4622-9f9c-53d84fd0c7ad"));
    assert_eq!(file_id, Some("file:///workspace/frontend/package.json"));
}
