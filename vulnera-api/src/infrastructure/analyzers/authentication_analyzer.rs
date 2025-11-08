//! Authentication security analyzer

use crate::domain::entities::{ApiFinding, ApiLocation, FindingSeverity};
use crate::domain::value_objects::{ApiVulnerabilityType, OpenApiSpec, SecuritySchemeType};

/// Analyzer for authentication issues
pub struct AuthenticationAnalyzer;

impl AuthenticationAnalyzer {
    pub fn analyze(spec: &OpenApiSpec) -> Vec<ApiFinding> {
        let mut findings = Vec::new();

        // Check for missing authentication on endpoints
        for path in &spec.paths {
            for operation in &path.operations {
                // Check if operation has security requirements
                let has_security = !operation.security.is_empty() || !spec.global_security.is_empty();

                if !has_security {
                    findings.push(ApiFinding {
                        id: format!("auth-missing-{}-{}", path.path, operation.method),
                        vulnerability_type: ApiVulnerabilityType::MissingAuthentication,
                        location: ApiLocation {
                            file_path: "openapi.yaml".to_string(),
                            line: None,
                            path: Some(path.path.clone()),
                            operation: Some(operation.method.clone()),
                        },
                        severity: FindingSeverity::High,
                        description: format!(
                            "Endpoint {} {} is missing authentication",
                            operation.method, path.path
                        ),
                        recommendation: "Add authentication requirements to this endpoint".to_string(),
                        path: Some(path.path.clone()),
                        method: Some(operation.method.clone()),
                    });
                }

                // Check for weak authentication schemes
                for security_req in &operation.security {
                    if let Some(scheme) = spec.security_schemes.iter()
                        .find(|s| s.name == security_req.scheme_name) {
                        match &scheme.scheme_type {
                            SecuritySchemeType::Http { scheme: http_scheme, .. } => {
                                if http_scheme == "basic" {
                                    findings.push(ApiFinding {
                                        id: format!("auth-weak-{}-{}", path.path, operation.method),
                                        vulnerability_type: ApiVulnerabilityType::WeakAuthentication,
                                        location: ApiLocation {
                                            file_path: "openapi.yaml".to_string(),
                                            line: None,
                                            path: Some(path.path.clone()),
                                            operation: Some(operation.method.clone()),
                                        },
                                        severity: FindingSeverity::Medium,
                                        description: format!(
                                            "Endpoint {} {} uses HTTP Basic authentication which is weak",
                                            operation.method, path.path
                                        ),
                                        recommendation: "Use OAuth2 or JWT Bearer tokens instead".to_string(),
                                        path: Some(path.path.clone()),
                                        method: Some(operation.method.clone()),
                                    });
                                }
                            }
                            SecuritySchemeType::ApiKey { .. } => {
                                findings.push(ApiFinding {
                                    id: format!("auth-apikey-{}-{}", path.path, operation.method),
                                    vulnerability_type: ApiVulnerabilityType::WeakAuthentication,
                                    location: ApiLocation {
                                        file_path: "openapi.yaml".to_string(),
                                        line: None,
                                        path: Some(path.path.clone()),
                                        operation: Some(operation.method.clone()),
                                    },
                                    severity: FindingSeverity::Medium,
                                    description: format!(
                                        "Endpoint {} {} uses API key only authentication",
                                        operation.method, path.path
                                    ),
                                    recommendation: "Consider using OAuth2 or JWT for better security".to_string(),
                                    path: Some(path.path.clone()),
                                    method: Some(operation.method.clone()),
                                });
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        findings
    }
}

