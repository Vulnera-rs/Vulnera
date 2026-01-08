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
                        || operation.method == "DELETE"
                        || operation.method == "PATCH")
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

                // BOLA Detection: ID in path but generic or missing scopes
                let id_pattern = regex::Regex::new(r"\{[a-zA-Z]*[Ii]d\}").unwrap();
                if id_pattern.is_match(&path.path) {
                    let is_bola_prone = if !has_scopes {
                        true
                    } else {
                        // Check if scopes are generic
                        let generic_scopes = ["read", "write", "user", "access"];
                        operation.security.iter().any(|req| {
                            req.scopes
                                .iter()
                                .any(|s| generic_scopes.contains(&s.as_str()))
                        })
                    };

                    if is_bola_prone {
                        findings.push(ApiFinding {
                            id: format!("bola-risk-{}-{}", path.path, operation.method),
                            vulnerability_type: ApiVulnerabilityType::BolaRisk,
                            location: ApiLocation {
                                file_path: "openapi.yaml".to_string(),
                                line: None,
                                path: Some(path.path.clone()),
                                operation: Some(operation.method.clone()),
                            },
                            severity: FindingSeverity::High,
                            description: format!(
                                "Endpoint {} {} contains ID in path but uses generic/no scopes, indicating BOLA risk",
                                operation.method, path.path
                            ),
                            recommendation: "Use resource-specific scopes (e.g., 'read:orders') or implement fine-grained owner checks".to_string(),
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
