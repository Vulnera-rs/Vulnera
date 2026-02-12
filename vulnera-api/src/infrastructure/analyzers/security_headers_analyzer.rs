//! Security headers analyzer

use crate::domain::entities::{ApiFinding, ApiLocation, FindingSeverity};
use crate::domain::value_objects::{ApiVulnerabilityType, OpenApiSpec};

/// Analyzer for security headers
pub struct SecurityHeadersAnalyzer;

impl SecurityHeadersAnalyzer {
    fn schema_has_wildcard_origin(schema: &crate::domain::value_objects::ApiSchema) -> bool {
        if schema
            .default
            .as_ref()
            .and_then(|v| v.as_str())
            .is_some_and(|v| v.trim() == "*")
        {
            return true;
        }

        if schema
            .example
            .as_ref()
            .and_then(|v| v.as_str())
            .is_some_and(|v| v.trim() == "*")
        {
            return true;
        }

        schema
            .enum_values
            .as_ref()
            .is_some_and(|vals| vals.iter().any(|v| v.trim() == "*"))
    }

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
                    let found_headers: Vec<String> =
                        response.headers.iter().map(|h| h.name.clone()).collect();

                    // Check for missing security headers
                    for required_header in &required_security_headers {
                        if !found_headers
                            .iter()
                            .any(|h| h.eq_ignore_ascii_case(required_header))
                        {
                            findings.push(ApiFinding {
                                id: format!(
                                    "security-header-missing-{}-{}-{}",
                                    path.path, operation.method, required_header
                                ),
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

                    if let Some(cors_header) = response
                        .headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case("Access-Control-Allow-Origin"))
                    {
                        let (severity, description) = if cors_header
                            .schema
                            .as_ref()
                            .is_some_and(Self::schema_has_wildcard_origin)
                        {
                            (
                                FindingSeverity::High,
                                format!(
                                    "Endpoint {} {} allows wildcard CORS origin '*'",
                                    operation.method, path.path
                                ),
                            )
                        } else {
                            (
                                FindingSeverity::Low,
                                format!(
                                    "Endpoint {} {} defines CORS origin header; verify allowed origins are restricted",
                                    operation.method, path.path
                                ),
                            )
                        };

                        findings.push(ApiFinding {
                            id: format!("cors-review-{}-{}", path.path, operation.method),
                            vulnerability_type: ApiVulnerabilityType::InsecureCors,
                            location: ApiLocation {
                                file_path: "openapi.yaml".to_string(),
                                line: None,
                                path: Some(path.path.clone()),
                                operation: Some(operation.method.clone()),
                            },
                            severity,
                            description,
                            recommendation:
                                "Ensure CORS is restricted to specific trusted origins, not '*'"
                                    .to_string(),
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
