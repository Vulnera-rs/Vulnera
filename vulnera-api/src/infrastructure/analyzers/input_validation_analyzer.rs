//! Input validation security analyzer

use crate::domain::entities::{ApiFinding, ApiLocation, FindingSeverity};
use crate::domain::value_objects::{ApiVulnerabilityType, OpenApiSpec, ParameterLocation};

/// Analyzer for input validation issues
pub struct InputValidationAnalyzer;

impl InputValidationAnalyzer {
    pub fn analyze(spec: &OpenApiSpec) -> Vec<ApiFinding> {
        let mut findings = Vec::new();

        for path in &spec.paths {
            for operation in &path.operations {
                // Check for missing request validation
                if operation.request_body.is_none() && (operation.method == "POST" || operation.method == "PUT" || operation.method == "PATCH") {
                    findings.push(ApiFinding {
                        id: format!("validation-missing-{}-{}", path.path, operation.method),
                        vulnerability_type: ApiVulnerabilityType::MissingRequestValidation,
                        location: ApiLocation {
                            file_path: "openapi.yaml".to_string(),
                            line: None,
                            path: Some(path.path.clone()),
                            operation: Some(operation.method.clone()),
                        },
                        severity: FindingSeverity::Medium,
                        description: format!(
                            "Endpoint {} {} is missing request body validation",
                            operation.method, path.path
                        ),
                        recommendation: "Define request body schema with validation rules".to_string(),
                        path: Some(path.path.clone()),
                        method: Some(operation.method.clone()),
                    });
                }

                // Check for SQL injection risks in query parameters
                for param in &operation.parameters {
                    if param.location == ParameterLocation::Query && param.schema.is_none() {
                        findings.push(ApiFinding {
                            id: format!("sqli-risk-{}-{}-{}", path.path, operation.method, param.name),
                            vulnerability_type: ApiVulnerabilityType::SqlInjectionRisk,
                            location: ApiLocation {
                                file_path: "openapi.yaml".to_string(),
                                line: None,
                                path: Some(path.path.clone()),
                                operation: Some(operation.method.clone()),
                            },
                            severity: FindingSeverity::High,
                            description: format!(
                                "Query parameter '{}' in {} {} lacks schema validation",
                                param.name, operation.method, path.path
                            ),
                            recommendation: "Add schema validation to prevent SQL injection".to_string(),
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

