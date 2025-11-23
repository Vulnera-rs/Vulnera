//! Unit tests for OAuthAnalyzer

use vulnera_api::domain::entities::FindingSeverity;
use vulnera_api::domain::value_objects::{
    ApiOperation, ApiPath, ApiVulnerabilityType, OAuthFlow, OAuthFlowType, OAuthScope, OpenApiSpec,
    SecurityScheme, SecuritySchemeType,
};
use vulnera_api::infrastructure::analyzers::OAuthAnalyzer;

fn create_spec_with_implicit_flow() -> OpenApiSpec {
    OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![],
        security_schemes: vec![SecurityScheme {
            name: "oauth2".to_string(),
            scheme_type: SecuritySchemeType::OAuth2 {
                flows: vec![OAuthFlow {
                    flow_type: OAuthFlowType::Implicit,
                    authorization_url: Some("https://example.com/oauth/authorize".to_string()),
                    token_url: None,
                    scopes: vec![],
                }],
            },
        }],
        global_security: vec![],
    }
}

fn create_spec_with_auth_code_flow() -> OpenApiSpec {
    OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![],
        security_schemes: vec![SecurityScheme {
            name: "oauth2".to_string(),
            scheme_type: SecuritySchemeType::OAuth2 {
                flows: vec![OAuthFlow {
                    flow_type: OAuthFlowType::AuthorizationCode,
                    authorization_url: Some("https://example.com/oauth/authorize".to_string()),
                    token_url: Some("https://example.com/oauth/token".to_string()),
                    scopes: vec![],
                }],
            },
        }],
        global_security: vec![],
    }
}

fn create_spec_with_missing_token_url() -> OpenApiSpec {
    OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![],
        security_schemes: vec![SecurityScheme {
            name: "oauth2".to_string(),
            scheme_type: SecuritySchemeType::OAuth2 {
                flows: vec![OAuthFlow {
                    flow_type: OAuthFlowType::AuthorizationCode,
                    authorization_url: Some("https://example.com/oauth/authorize".to_string()),
                    token_url: None, // Missing token URL
                    scopes: vec![],
                }],
            },
        }],
        global_security: vec![],
    }
}

#[test]
fn test_detects_implicit_flow() {
    let spec = create_spec_with_implicit_flow();
    let findings = OAuthAnalyzer::analyze(&spec);

    assert!(!findings.is_empty());
    let implicit_finding = findings
        .iter()
        .find(|f| f.vulnerability_type == ApiVulnerabilityType::InsecureOAuthFlow);
    assert!(implicit_finding.is_some());

    let finding = implicit_finding.unwrap();
    assert_eq!(finding.severity, FindingSeverity::High);
    assert!(finding.description.contains("implicit flow"));
}

#[test]
fn test_accepts_authorization_code_flow() {
    let spec = create_spec_with_auth_code_flow();
    let findings = OAuthAnalyzer::analyze(&spec);

    // Authorization code flow with token URL should not trigger findings
    assert!(findings.is_empty());
}

#[test]
fn test_detects_missing_token_url() {
    let spec = create_spec_with_missing_token_url();
    let findings = OAuthAnalyzer::analyze(&spec);

    assert!(!findings.is_empty());
    let missing_url_finding = findings
        .iter()
        .find(|f| f.vulnerability_type == ApiVulnerabilityType::InsecureOAuthFlow);
    assert!(missing_url_finding.is_some());

    let finding = missing_url_finding.unwrap();
    assert_eq!(finding.severity, FindingSeverity::High);
    assert!(finding.description.contains("missing token URL"));
}

#[test]
fn test_multiple_flows_multiple_findings() {
    let spec = OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![],
        security_schemes: vec![SecurityScheme {
            name: "oauth2".to_string(),
            scheme_type: SecuritySchemeType::OAuth2 {
                flows: vec![
                    OAuthFlow {
                        flow_type: OAuthFlowType::Implicit,
                        authorization_url: Some("https://example.com/oauth/authorize".to_string()),
                        token_url: None,
                        scopes: vec![],
                    },
                    OAuthFlow {
                        flow_type: OAuthFlowType::AuthorizationCode,
                        authorization_url: Some("https://example.com/oauth/authorize".to_string()),
                        token_url: None, // Missing
                        scopes: vec![],
                    },
                ],
            },
        }],
        global_security: vec![],
    };

    let findings = OAuthAnalyzer::analyze(&spec);

    // Should find 2 issues: implicit flow + missing token URL
    assert_eq!(findings.len(), 2);
}

#[test]
fn test_client_credentials_flow() {
    let spec = OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![],
        security_schemes: vec![SecurityScheme {
            name: "oauth2".to_string(),
            scheme_type: SecuritySchemeType::OAuth2 {
                flows: vec![OAuthFlow {
                    flow_type: OAuthFlowType::ClientCredentials,
                    authorization_url: None,
                    token_url: Some("https://example.com/oauth/token".to_string()),
                    scopes: vec![],
                }],
            },
        }],
        global_security: vec![],
    };

    let findings = OAuthAnalyzer::analyze(&spec);

    // Client credentials flow is acceptable
    assert!(findings.is_empty());
}

#[test]
fn test_password_flow() {
    let spec = OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![],
        security_schemes: vec![SecurityScheme {
            name: "oauth2".to_string(),
            scheme_type: SecuritySchemeType::OAuth2 {
                flows: vec![OAuthFlow {
                    flow_type: OAuthFlowType::Password,
                    authorization_url: None,
                    token_url: Some("https://example.com/oauth/token".to_string()),
                    scopes: vec![],
                }],
            },
        }],
        global_security: vec![],
    };

    let findings = OAuthAnalyzer::analyze(&spec);

    // Password flow with token URL is acceptable
    assert!(findings.is_empty());
}

#[test]
fn test_non_oauth_schemes_ignored() {
    let spec = OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![],
        security_schemes: vec![
            SecurityScheme {
                name: "apiKey".to_string(),
                scheme_type: SecuritySchemeType::ApiKey {
                    location: "header".to_string(),
                    name: "X-API-Key".to_string(),
                },
            },
            SecurityScheme {
                name: "bearer".to_string(),
                scheme_type: SecuritySchemeType::Http {
                    scheme: "bearer".to_string(),
                    bearer_format: Some("JWT".to_string()),
                },
            },
        ],
        global_security: vec![],
    };

    let findings = OAuthAnalyzer::analyze(&spec);

    // Non-OAuth schemes should be ignored
    assert!(findings.is_empty());
}
