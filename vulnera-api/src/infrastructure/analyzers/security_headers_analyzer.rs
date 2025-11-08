//! Security headers analyzer

use crate::domain::entities::{ApiFinding, ApiLocation, FindingSeverity};
use crate::domain::value_objects::{ApiVulnerabilityType, OpenApiSpec};

/// Analyzer for security headers
pub struct SecurityHeadersAnalyzer;

impl SecurityHeadersAnalyzer {
    pub fn analyze(spec: &OpenApiSpec) -> Vec<ApiFinding> {
        let mut findings = Vec::new();

        // Security headers that should be present in API responses
        let required_security_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Content-Security-Policy",
        ];

        // Check each endpoint's responses for security headers
        for path in &spec.paths {
            for operation in &path.operations {
                // Check all responses for security headers
                for response in &operation.responses {
                    let found_headers: Vec<String> = response.headers.iter()
                        .map(|h| h.name.clone())
                        .collect();

                    // Check for missing security headers
                    for required_header in &required_security_headers {
                        if !found_headers.iter().any(|h| h.eq_ignore_ascii_case(required_header)) {
                            findings.push(ApiFinding {
                                id: format!("security-header-missing-{}-{}-{}", 
                                    path.path, operation.method, required_header),
                                vulnerability_type: ApiVulnerabilityType::MissingSecurityHeaders,
                                location: ApiLocation {
                                    file_path: "openapi.yaml".to_string(),
                                    line: None,
                                    path: Some(path.path.clone()),
                                    operation: Some(operation.method.clone()),
                                },
                                severity: FindingSeverity::Medium,
                                description: format!(
                                    "Response for {} {} is missing security header: {}",
                                    operation.method, path.path, required_header
                                ),
                                recommendation: format!(
                                    "Add {} header to response headers for better security",
                                    required_header
                                ),
                                path: Some(path.path.clone()),
                                method: Some(operation.method.clone()),
                            });
                        }
                    }

                    // Check for CORS headers and validate configuration
                    // Note: CORS header values are in the header schema, not the header name
                    // This is a simplified check - in a full implementation, we'd parse the header schema
                    if found_headers.iter().any(|h| h.eq_ignore_ascii_case("Access-Control-Allow-Origin")) {
                        // Flag CORS header presence for review (can't check value from spec alone)
                        findings.push(ApiFinding {
                            id: format!("cors-review-{}-{}", path.path, operation.method),
                            vulnerability_type: ApiVulnerabilityType::InsecureCors,
                            location: ApiLocation {
                                file_path: "openapi.yaml".to_string(),
                                line: None,
                                path: Some(path.path.clone()),
                                operation: Some(operation.method.clone()),
                            },
                            severity: FindingSeverity::Low,
                            description: format!(
                                "Endpoint {} {} has CORS header - verify it's not allowing all origins (*)",
                                operation.method, path.path
                            ),
                            recommendation: "Ensure CORS is restricted to specific trusted origins, not '*'".to_string(),
                            path: Some(path.path.clone()),
                            method: Some(operation.method.clone()),
                        });
                    }
                }
            }
        }

        findings
    }
}

