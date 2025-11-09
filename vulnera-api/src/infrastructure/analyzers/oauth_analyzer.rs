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

        findings
    }
}
