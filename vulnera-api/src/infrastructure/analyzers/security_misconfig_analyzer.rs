//! Security Misconfiguration Analyzer
//! Checks for common misconfigurations (CORS, Verb Tampering, etc.)

use crate::domain::entities::{ApiFinding, ApiLocation, FindingSeverity};
use crate::domain::value_objects::{ApiVulnerabilityType, OpenApiSpec};

/// Analyzer for security misconfigurations
pub struct SecurityMisconfigAnalyzer;

impl SecurityMisconfigAnalyzer {
    pub fn analyze(spec: &OpenApiSpec) -> Vec<ApiFinding> {
        let mut findings = Vec::new();

        // Check for CORS wildcards
        // Note: OpenAPI spec usually doesn't define CORS explicitly unless in headers or OPTIONS method
        // We scan for Access-Control-Allow-Origin header in responses

        for path in &spec.paths {
            for operation in &path.operations {
                for response in &operation.responses {
                    if response.headers.iter().any(|h| {
                        h.name.to_lowercase() == "access-control-allow-origin"
                            && h.schema
                                .as_ref()
                                .and_then(|s| s.default.as_ref())
                                .map(|v| v.as_str() == Some("*"))
                                .unwrap_or(false)
                    }) {
                        findings.push(ApiFinding {
                            id: format!("cors-wildcard-{}-{}", path.path, operation.method),
                            vulnerability_type: ApiVulnerabilityType::CorsWildcard,
                            location: ApiLocation {
                                file_path: "openapi.yaml".to_string(),
                                line: None,
                                path: Some(path.path.clone()),
                                operation: Some(operation.method.clone()),
                            },
                            severity: FindingSeverity::High,
                            description: format!(
                                "CORS wildcard '*' detected in response for {} {}",
                                operation.method, path.path
                            ),
                            recommendation:
                                "Avoid using '*' for CORS origin; explicitly allow specific domains"
                                    .to_string(),
                            path: Some(path.path.clone()),
                            method: Some(operation.method.clone()),
                        });
                    }
                }

                // Verb Tampering / Dangerous Methods
                // Check if TRACE or TRACK methods are defined (rare in OpenAPI but if present, it's bad)
                if operation.method == "TRACE" || operation.method == "TRACK" {
                    findings.push(ApiFinding {
                        id: format!("dangerous-method-{}-{}", path.path, operation.method),
                        vulnerability_type: ApiVulnerabilityType::VerbTampering,
                        location: ApiLocation {
                            file_path: "openapi.yaml".to_string(),
                            line: None,
                            path: Some(path.path.clone()),
                            operation: Some(operation.method.clone()),
                        },
                        severity: FindingSeverity::Medium,
                        description: format!(
                            "Dangerous HTTP method '{}' defined for {}",
                            operation.method, path.path
                        ),
                        recommendation: "Disable TRACE/TRACK methods to prevent XST attacks"
                            .to_string(),
                        path: Some(path.path.clone()),
                        method: Some(operation.method.clone()),
                    });
                }
            }
        }

        findings
    }
}
