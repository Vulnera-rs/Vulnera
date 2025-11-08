//! Authorization security analyzer

use crate::domain::entities::{ApiFinding, ApiLocation, FindingSeverity};
use crate::domain::value_objects::{ApiVulnerabilityType, OpenApiSpec};

/// Analyzer for authorization issues
pub struct AuthorizationAnalyzer;

impl AuthorizationAnalyzer {
    pub fn analyze(spec: &OpenApiSpec) -> Vec<ApiFinding> {
        let mut findings = Vec::new();

        // Check for missing authorization (all endpoints have same access)
        for path in &spec.paths {
            for operation in &path.operations {
                // Check if operation has scopes defined (OAuth2 authorization)
                let has_scopes = operation.security.iter().any(|req| !req.scopes.is_empty());

                if !has_scopes
                    && (operation.method == "POST"
                        || operation.method == "PUT"
                        || operation.method == "DELETE")
                {
                    findings.push(ApiFinding {
                        id: format!("authz-missing-{}-{}", path.path, operation.method),
                        vulnerability_type: ApiVulnerabilityType::MissingAuthorization,
                        location: ApiLocation {
                            file_path: "openapi.yaml".to_string(),
                            line: None,
                            path: Some(path.path.clone()),
                            operation: Some(operation.method.clone()),
                        },
                        severity: FindingSeverity::High,
                        description: format!(
                            "Endpoint {} {} may be missing authorization checks",
                            operation.method, path.path
                        ),
                        recommendation: "Add OAuth2 scopes or RBAC requirements to restrict access"
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
