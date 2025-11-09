//! Snapshot tests for OpenAPI analysis findings

#[test]
fn test_openapi_findings_snapshot() {
    let findings = serde_json::json!({
        "vulnerabilities": [
            {
                "type": "missing_authentication",
                "severity": "high",
                "path": "/users"
            }
        ]
    });

    insta::assert_json_snapshot!("openapi_findings", findings);
}

#[test]
fn test_oauth_findings_snapshot() {
    let findings = serde_json::json!({
        "oauth": {
            "flows": ["authorizationCode"],
            "security_issues": []
        }
    });

    insta::assert_json_snapshot!("oauth_findings", findings);
}
