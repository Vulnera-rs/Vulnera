//! Sensitive data exposure analyzer

use crate::domain::entities::{ApiFinding, ApiLocation, FindingSeverity};
use crate::domain::value_objects::{ApiVulnerabilityType, OpenApiSpec, ParameterLocation};

/// Analyzer for sensitive data exposure
pub struct DataExposureAnalyzer;

impl DataExposureAnalyzer {
    pub fn analyze(spec: &OpenApiSpec) -> Vec<ApiFinding> {
        let mut findings = Vec::new();

        let sensitive_param_names = [
            "password",
            "token",
            "secret",
            "key",
            "api_key",
            "access_token",
            "refresh_token",
        ];

        for path in &spec.paths {
            for operation in &path.operations {
                // Check for sensitive data in query parameters
                for param in &operation.parameters {
                    if param.location == ParameterLocation::Query {
                        let param_lower = param.name.to_lowercase();
                        if sensitive_param_names
                            .iter()
                            .any(|&sensitive| param_lower.contains(sensitive))
                        {
                            findings.push(ApiFinding {
                                id: format!("sensitive-query-{}-{}-{}", path.path, operation.method, param.name),
                                vulnerability_type: ApiVulnerabilityType::SensitiveDataInUrl,
                                location: ApiLocation {
                                    file_path: "openapi.yaml".to_string(),
                                    line: None,
                                    path: Some(path.path.clone()),
                                    operation: Some(operation.method.clone()),
                                },
                                severity: FindingSeverity::High,
                                description: format!(
                                    "Sensitive parameter '{}' is exposed in URL query string for {} {}",
                                    param.name, operation.method, path.path
                                ),
                                recommendation: "Move sensitive parameters to request body or headers".to_string(),
                                path: Some(path.path.clone()),
                                method: Some(operation.method.clone()),
                            });
                        }
                    }
                }
            }
        }

        findings
    }
}
