//! Snapshot tests for API responses

#[test]
fn test_health_response_snapshot() {
    let response = serde_json::json!({
        "status": "healthy",
        "version": "0.3.0",
        "timestamp": "2024-01-01T00:00:00Z"
    });
    
    insta::assert_json_snapshot!("health_response", response);
}

#[test]
fn test_error_response_snapshot() {
    let response = serde_json::json!({
        "error": "Invalid request",
        "code": 400
    });
    
    insta::assert_json_snapshot!("error_response", response);
}

