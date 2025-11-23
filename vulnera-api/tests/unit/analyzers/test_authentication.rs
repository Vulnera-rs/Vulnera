//! Unit tests for AuthenticationAnalyzer

use vulnera_api::domain::entities::FindingSeverity;
use vulnera_api::domain::value_objects::{
    ApiOperation, ApiPath, ApiVulnerabilityType, OpenApiSpec, ParameterLocation,
    SecurityRequirement, SecurityScheme, SecuritySchemeType,
};
use vulnera_api::infrastructure::analyzers::AuthenticationAnalyzer;

fn create_test_spec_no_auth() -> OpenApiSpec {
    OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![ApiPath {
            path: "/users".to_string(),
            operations: vec![ApiOperation {
                method: "GET".to_string(),
                security: vec![],
                parameters: vec![],
                request_body: None,
                responses: vec![],
            }],
        }],
        security_schemes: vec![],
        global_security: vec![],
    }
}

fn create_test_spec_with_http_basic() -> OpenApiSpec {
    OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![ApiPath {
            path: "/users".to_string(),
            operations: vec![ApiOperation {
                method: "GET".to_string(),
                security: vec![SecurityRequirement {
                    scheme_name: "basicAuth".to_string(),
                    scopes: vec![],
                }],
                parameters: vec![],
                request_body: None,
                responses: vec![],
            }],
        }],
        security_schemes: vec![SecurityScheme {
            name: "basicAuth".to_string(),
            scheme_type: SecuritySchemeType::Http {
                scheme: "basic".to_string(),
                bearer_format: None,
            },
        }],
        global_security: vec![],
    }
}

fn create_test_spec_with_api_key() -> OpenApiSpec {
    OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![ApiPath {
            path: "/users".to_string(),
            operations: vec![ApiOperation {
                method: "GET".to_string(),
                security: vec![SecurityRequirement {
                    scheme_name: "apiKey".to_string(),
                    scopes: vec![],
                }],
                parameters: vec![],
                request_body: None,
                responses: vec![],
            }],
        }],
        security_schemes: vec![SecurityScheme {
            name: "apiKey".to_string(),
            scheme_type: SecuritySchemeType::ApiKey {
                location: "header".to_string(),
                name: "X-API-Key".to_string(),
            },
        }],
        global_security: vec![],
    }
}

fn create_test_spec_with_bearer() -> OpenApiSpec {
    OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![ApiPath {
            path: "/users".to_string(),
            operations: vec![ApiOperation {
                method: "GET".to_string(),
                security: vec![SecurityRequirement {
                    scheme_name: "bearerAuth".to_string(),
                    scopes: vec![],
                }],
                parameters: vec![],
                request_body: None,
                responses: vec![],
            }],
        }],
        security_schemes: vec![SecurityScheme {
            name: "bearerAuth".to_string(),
            scheme_type: SecuritySchemeType::Http {
                scheme: "bearer".to_string(),
                bearer_format: Some("JWT".to_string()),
            },
        }],
        global_security: vec![],
    }
}

#[test]
fn test_detects_missing_authentication() {
    let spec = create_test_spec_no_auth();
    let findings = AuthenticationAnalyzer::analyze(&spec);

    assert!(!findings.is_empty());
    let missing_auth_finding = findings
        .iter()
        .find(|f| f.vulnerability_type == ApiVulnerabilityType::MissingAuthentication);
    assert!(missing_auth_finding.is_some());

    let finding = missing_auth_finding.unwrap();
    assert_eq!(finding.severity, FindingSeverity::High);
    assert!(finding.description.contains("/users"));
    assert!(finding.description.contains("GET"));
}

#[test]
fn test_detects_weak_http_basic() {
    let spec = create_test_spec_with_http_basic();
    let findings = AuthenticationAnalyzer::analyze(&spec);

    let weak_auth_finding = findings
        .iter()
        .find(|f| f.vulnerability_type == ApiVulnerabilityType::WeakAuthentication);
    assert!(weak_auth_finding.is_some());

    let finding = weak_auth_finding.unwrap();
    assert_eq!(finding.severity, FindingSeverity::Medium);
    assert!(finding.description.contains("HTTP Basic"));
}

#[test]
fn test_detects_api_key_only() {
    let spec = create_test_spec_with_api_key();
    let findings = AuthenticationAnalyzer::analyze(&spec);

    let weak_auth_finding = findings
        .iter()
        .find(|f| f.vulnerability_type == ApiVulnerabilityType::WeakAuthentication);
    assert!(weak_auth_finding.is_some());

    let finding = weak_auth_finding.unwrap();
    assert!(finding.description.contains("API key"));
}

#[test]
fn test_accepts_bearer_jwt() {
    let spec = create_test_spec_with_bearer();
    let findings = AuthenticationAnalyzer::analyze(&spec);

    // Bearer JWT should not trigger missing or weak auth
    assert!(findings.is_empty());
}

#[test]
fn test_global_security_applies() {
    let mut spec = create_test_spec_no_auth();
    spec.global_security = vec![SecurityRequirement {
        scheme_name: "bearerAuth".to_string(),
        scopes: vec![],
    }];
    spec.security_schemes = vec![SecurityScheme {
        name: "bearerAuth".to_string(),
        scheme_type: SecuritySchemeType::Http {
            scheme: "bearer".to_string(),
            bearer_format: Some("JWT".to_string()),
        },
    }];

    let findings = AuthenticationAnalyzer::analyze(&spec);

    // Should not find missing authentication
    let missing_auth = findings
        .iter()
        .find(|f| f.vulnerability_type == ApiVulnerabilityType::MissingAuthentication);
    assert!(missing_auth.is_none());
}

#[test]
fn test_operation_security_overrides_global() {
    let mut spec = create_test_spec_with_http_basic();
    spec.global_security = vec![SecurityRequirement {
        scheme_name: "bearerAuth".to_string(),
        scopes: vec![],
    }];

    let findings = AuthenticationAnalyzer::analyze(&spec);

    // Should still detect weak HTTP Basic, even with global bearer
    let weak_auth = findings
        .iter()
        .find(|f| f.vulnerability_type == ApiVulnerabilityType::WeakAuthentication);
    assert!(weak_auth.is_some());
}

#[test]
fn test_multiple_paths_multiple_findings() {
    let spec = OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![
            ApiPath {
                path: "/users".to_string(),
                operations: vec![ApiOperation {
                    method: "GET".to_string(),
                    security: vec![],
                    parameters: vec![],
                    request_body: None,
                    responses: vec![],
                }],
            },
            ApiPath {
                path: "/posts".to_string(),
                operations: vec![ApiOperation {
                    method: "GET".to_string(),
                    security: vec![],
                    parameters: vec![],
                    request_body: None,
                    responses: vec![],
                }],
            },
        ],
        security_schemes: vec![],
        global_security: vec![],
    };

    let findings = AuthenticationAnalyzer::analyze(&spec);

    // Should find 2 missing authentication findings
    let missing_auth_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.vulnerability_type == ApiVulnerabilityType::MissingAuthentication)
        .collect();
    assert_eq!(missing_auth_findings.len(), 2);
}
