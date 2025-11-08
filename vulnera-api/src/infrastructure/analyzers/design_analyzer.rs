//! API design analyzer

use crate::domain::entities::{ApiFinding, ApiLocation, FindingSeverity};
use crate::domain::value_objects::{ApiVulnerabilityType, OpenApiSpec};

/// Analyzer for API design issues
pub struct DesignAnalyzer;

impl DesignAnalyzer {
    pub fn analyze(spec: &OpenApiSpec) -> Vec<ApiFinding> {
        let mut findings = Vec::new();

        for path in &spec.paths {
            for operation in &path.operations {
                // Check for missing pagination on list endpoints
                if operation.method == "GET" && path.path.contains("list") || path.path.contains("search") {
                    let has_pagination = operation.parameters.iter()
                        .any(|p| p.name.to_lowercase().contains("page") || p.name.to_lowercase().contains("limit"));

                    if !has_pagination {
                        findings.push(ApiFinding {
                            id: format!("pagination-missing-{}-{}", path.path, operation.method),
                            vulnerability_type: ApiVulnerabilityType::MissingPagination,
                            location: ApiLocation {
                                file_path: "openapi.yaml".to_string(),
                                line: None,
                                path: Some(path.path.clone()),
                                operation: Some(operation.method.clone()),
                            },
                            severity: FindingSeverity::Low,
                            description: format!(
                                "List endpoint {} {} is missing pagination parameters",
                                operation.method, path.path
                            ),
                            recommendation: "Add pagination parameters (page, limit) to prevent large responses".to_string(),
                            path: Some(path.path.clone()),
                            method: Some(operation.method.clone()),
                        });
                    }
                }

                // Check for missing error handling
                let has_error_responses = operation.responses.iter()
                    .any(|r| r.status_code.starts_with("4") || r.status_code.starts_with("5"));

                if !has_error_responses {
                    findings.push(ApiFinding {
                        id: format!("error-handling-{}-{}", path.path, operation.method),
                        vulnerability_type: ApiVulnerabilityType::MissingErrorHandling,
                        location: ApiLocation {
                            file_path: "openapi.yaml".to_string(),
                            line: None,
                            path: Some(path.path.clone()),
                            operation: Some(operation.method.clone()),
                        },
                        severity: FindingSeverity::Medium,
                        description: format!(
                            "Endpoint {} {} is missing error response definitions",
                            operation.method, path.path
                        ),
                        recommendation: "Define error responses (4xx, 5xx) in the specification".to_string(),
                        path: Some(path.path.clone()),
                        method: Some(operation.method.clone()),
                    });
                }
            }
        }

        findings
    }
}

