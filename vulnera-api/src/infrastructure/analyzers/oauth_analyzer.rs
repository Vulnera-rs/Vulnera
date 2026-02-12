//! OAuth/OIDC security analyzer

use crate::domain::entities::{ApiFinding, ApiLocation, FindingSeverity};
use crate::domain::value_objects::{
    ApiVulnerabilityType, OAuthFlowType, OpenApiSpec, SecuritySchemeType,
};

/// Analyzer for OAuth/OIDC issues
pub struct OAuthAnalyzer;

impl OAuthAnalyzer {
    pub fn analyze(spec: &OpenApiSpec) -> Vec<ApiFinding> {
        let mut findings = Vec::new();

        for scheme in &spec.security_schemes {
            if let SecuritySchemeType::OAuth2 { flows } = &scheme.scheme_type {
                for flow in flows {
                    // Check for insecure OAuth flows
                    if flow.flow_type == OAuthFlowType::Implicit {
                        findings.push(ApiFinding {
                            id: format!("oauth-implicit-{}", scheme.name),
                            vulnerability_type: ApiVulnerabilityType::InsecureOAuthFlow,
                            location: ApiLocation {
                                file_path: "openapi.yaml".to_string(),
                                line: None,
                                path: None,
                                operation: None,
                            },
                            severity: FindingSeverity::High,
                            description: format!(
                                "OAuth2 scheme '{}' uses implicit flow which is insecure",
                                scheme.name
                            ),
                            recommendation: "Use authorization code flow instead".to_string(),
                            path: None,
                            method: None,
                        });
                    }

                    // Check for missing token URL in authorization code flow
                    if flow.flow_type == OAuthFlowType::AuthorizationCode
                        && flow.token_url.is_none()
                    {
                        findings.push(ApiFinding {
                            id: format!("oauth-token-url-{}", scheme.name),
                            vulnerability_type: ApiVulnerabilityType::InsecureOAuthFlow,
                            location: ApiLocation {
                                file_path: "openapi.yaml".to_string(),
                                line: None,
                                path: None,
                                operation: None,
                            },
                            severity: FindingSeverity::High,
                            description: format!(
                                "OAuth2 authorization code flow for '{}' is missing token URL",
                                scheme.name
                            ),
                            recommendation: "Add token URL to the OAuth2 flow configuration"
                                .to_string(),
                            path: None,
                            method: None,
                        });
                    }
                }
            }
        }

        // Check scope granularity
        let mut all_scopes = std::collections::HashSet::new();
        let mut endpoint_count = 0;

        for path in &spec.paths {
            for operation in &path.operations {
                endpoint_count += 1;
                for req in &operation.security {
                    for scope in &req.scopes {
                        all_scopes.insert(scope.clone());

                        // Check for admin scope leakage (admin scope on non-admin path)
                        if scope.contains("admin")
                            && !path.path.contains("admin")
                            && !path.path.contains("internal")
                        {
                            findings.push(ApiFinding {
                                id: format!("admin-scope-leak-{}-{}", path.path, operation.method),
                                vulnerability_type: ApiVulnerabilityType::BolaRisk,
                                location: ApiLocation {
                                    file_path: "openapi.yaml".to_string(),
                                    line: None,
                                    path: Some(path.path.clone()),
                                    operation: Some(operation.method.clone()),
                                },
                                severity: FindingSeverity::Medium,
                                description: format!(
                                    "Administrative scope '{}' used on apparent non-admin endpoint {} {}",
                                    scope, operation.method, path.path
                                ),
                                recommendation: "Ensure administrative scopes are only used on privileged endpoints".to_string(),
                                path: Some(path.path.clone()),
                                method: Some(operation.method.clone()),
                            });
                        }
                    }
                }
            }
        }

        // Single Scope Anti-Pattern
        // If API has > 5 endpoints but uses only 1 scope, it likely has poor granularity
        if endpoint_count > 5 && all_scopes.len() == 1 {
            let scope_label = all_scopes
                .iter()
                .next()
                .map(String::as_str)
                .unwrap_or("<unknown>");
            findings.push(ApiFinding {
                id: "single-scope-anti-pattern".to_string(),
                vulnerability_type: ApiVulnerabilityType::IneffectiveScopeHierarchy, // Need to ensure this enum variant exists or use similar
                location: ApiLocation {
                    file_path: "openapi.yaml".to_string(),
                    line: None,
                    path: None,
                    operation: None,
                },
                severity: FindingSeverity::Medium,
                description: format!(
                    "API contains {} endpoints but uses only 1 OAuth scope ('{}'). This indicates ineffective authorization granularity.",
                    endpoint_count, scope_label
                ),
                recommendation: "Define granular scopes (e.g., read:users, write:orders) to follow Least Privilege principle".to_string(),
                path: None,
                method: None,
            });
        }

        findings
    }
}
