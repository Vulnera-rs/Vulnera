//! Unit tests for Enhanced Analyzers (Input Validation, Data Exposure, etc.)

use vulnera_api::domain::value_objects::{
    AdditionalProperties, ApiContent, ApiHeader, ApiOperation, ApiPath, ApiProperty,
    ApiRequestBody, ApiResponse, ApiSchema, ApiVulnerabilityType, OpenApiSpec, SecurityRequirement,
};
use vulnera_api::infrastructure::analyzers::{
    AuthorizationAnalyzer, DataExposureAnalyzer, InputValidationAnalyzer,
    ResourceRestrictionAnalyzer, SecurityHeadersAnalyzer, SecurityMisconfigAnalyzer,
};

// --- Helpers ---

fn create_schema_string_unbounded() -> ApiSchema {
    ApiSchema {
        schema_type: Some("string".to_string()),
        min_length: None,
        max_length: None,
        ..Default::default()
    }
}

fn create_schema_int_unbounded() -> ApiSchema {
    ApiSchema {
        schema_type: Some("integer".to_string()),
        minimum: None,
        maximum: None,
        ..Default::default()
    }
}

fn create_schema_object_additional_props() -> ApiSchema {
    ApiSchema {
        schema_type: Some("object".to_string()),
        additional_properties: AdditionalProperties::Allowed,
        ..Default::default()
    }
}

// --- Input Validation Tests ---

#[test]
fn test_detects_unbounded_input() {
    let spec = OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![ApiPath {
            path: "/test".to_string(),
            operations: vec![ApiOperation {
                method: "POST".to_string(),
                security: vec![],
                parameters: vec![],
                request_body: Some(ApiRequestBody {
                    required: true,
                    content: vec![ApiContent {
                        media_type: "application/json".to_string(),
                        schema: Some(ApiSchema {
                            schema_type: Some("object".to_string()),
                            properties: vec![
                                ApiProperty {
                                    name: "name".to_string(),
                                    schema: create_schema_string_unbounded(),
                                },
                                ApiProperty {
                                    name: "age".to_string(),
                                    schema: create_schema_int_unbounded(),
                                },
                            ],
                            ..Default::default()
                        }),
                    }],
                }),
                responses: vec![],
            }],
        }],
        security_schemes: vec![],
        global_security: vec![],
    };

    let findings = InputValidationAnalyzer::analyze(&spec);

    // Should find UnboundedInput for name and age
    let unbounded = findings
        .iter()
        .filter(|f| f.vulnerability_type == ApiVulnerabilityType::UnboundedInput)
        .count();
    assert!(
        unbounded >= 2,
        "Expected at least 2 unbounded input findings, found {}",
        unbounded
    );
}

#[test]
fn test_detects_mass_assignment() {
    let spec = OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![ApiPath {
            path: "/test".to_string(),
            operations: vec![ApiOperation {
                method: "POST".to_string(),
                security: vec![],
                parameters: vec![],
                request_body: Some(ApiRequestBody {
                    required: true,
                    content: vec![ApiContent {
                        media_type: "application/json".to_string(),
                        schema: Some(create_schema_object_additional_props()),
                    }],
                }),
                responses: vec![],
            }],
        }],
        security_schemes: vec![],
        global_security: vec![],
    };

    let findings = InputValidationAnalyzer::analyze(&spec);
    assert!(
        findings
            .iter()
            .any(|f| f.vulnerability_type == ApiVulnerabilityType::MassAssignmentRisk)
    );
}

#[test]
fn test_input_validation_recurses_into_array_item_schemas() {
    let spec = OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![ApiPath {
            path: "/bulk-users".to_string(),
            operations: vec![ApiOperation {
                method: "POST".to_string(),
                security: vec![],
                parameters: vec![],
                request_body: Some(ApiRequestBody {
                    required: true,
                    content: vec![ApiContent {
                        media_type: "application/json".to_string(),
                        schema: Some(ApiSchema {
                            schema_type: Some("array".to_string()),
                            max_items: Some(100),
                            items: Some(Box::new(ApiSchema {
                                schema_type: Some("object".to_string()),
                                properties: vec![ApiProperty {
                                    name: "username".to_string(),
                                    schema: ApiSchema {
                                        schema_type: Some("string".to_string()),
                                        ..Default::default()
                                    },
                                }],
                                ..Default::default()
                            })),
                            ..Default::default()
                        }),
                    }],
                }),
                responses: vec![],
            }],
        }],
        security_schemes: vec![],
        global_security: vec![],
    };

    let findings = InputValidationAnalyzer::analyze(&spec);
    assert!(findings.iter().any(|f| {
        f.vulnerability_type == ApiVulnerabilityType::UnboundedInput
            && f.description.contains("body[].username")
    }));
}

// --- Authorization Tests ---

#[test]
fn test_detects_bola_risk() {
    let spec = OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![ApiPath {
            path: "/users/{userId}".to_string(),
            operations: vec![ApiOperation {
                method: "GET".to_string(),
                security: vec![SecurityRequirement {
                    scheme_name: "oauth".to_string(),
                    scopes: vec!["read".to_string()], // Generic scope
                }],
                parameters: vec![],
                request_body: None,
                responses: vec![],
            }],
        }],
        security_schemes: vec![],
        global_security: vec![],
    };

    let findings = AuthorizationAnalyzer::analyze(&spec);
    assert!(
        findings
            .iter()
            .any(|f| f.vulnerability_type == ApiVulnerabilityType::BolaRisk)
    );
}

// --- Data Exposure Tests ---

#[test]
fn test_detects_exposed_secrets() {
    let jwt_example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    let spec = OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![ApiPath {
            path: "/test".to_string(),
            operations: vec![ApiOperation {
                method: "GET".to_string(),
                security: vec![],
                parameters: vec![],
                request_body: None,
                responses: vec![ApiResponse {
                    status_code: "200".to_string(),
                    content: vec![ApiContent {
                        media_type: "application/json".to_string(),
                        schema: Some(ApiSchema {
                            schema_type: Some("string".to_string()),
                            example: Some(serde_json::Value::String(jwt_example.to_string())),
                            ..Default::default()
                        }),
                    }],
                    headers: vec![],
                }],
            }],
        }],
        security_schemes: vec![],
        global_security: vec![],
    };

    let findings = DataExposureAnalyzer::analyze(&spec);
    assert!(
        findings
            .iter()
            .any(|f| f.vulnerability_type == ApiVulnerabilityType::ExposedSecretInSpec)
    );
}

// --- Resource Restriction Tests ---

#[test]
fn test_detects_missing_pagination() {
    let spec = OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![ApiPath {
            path: "/items".to_string(),
            operations: vec![ApiOperation {
                method: "GET".to_string(),
                security: vec![],
                parameters: vec![], // No limit/offset
                request_body: None,
                responses: vec![ApiResponse {
                    status_code: "200".to_string(),
                    content: vec![ApiContent {
                        media_type: "application/json".to_string(),
                        schema: Some(ApiSchema {
                            schema_type: Some("array".to_string()), // Returns array
                            ..Default::default()
                        }),
                    }],
                    headers: vec![], // No ratelimit header
                }],
            }],
        }],
        security_schemes: vec![],
        global_security: vec![],
    };

    let findings = ResourceRestrictionAnalyzer::analyze(&spec);
    assert!(
        findings
            .iter()
            .any(|f| f.vulnerability_type == ApiVulnerabilityType::ResourceExhaustion)
    );
}

#[test]
fn test_detects_missing_pagination_for_wrapped_array_response() {
    let spec = OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![ApiPath {
            path: "/wrapped-items".to_string(),
            operations: vec![ApiOperation {
                method: "GET".to_string(),
                security: vec![],
                parameters: vec![],
                request_body: None,
                responses: vec![ApiResponse {
                    status_code: "200".to_string(),
                    content: vec![ApiContent {
                        media_type: "application/json".to_string(),
                        schema: Some(ApiSchema {
                            schema_type: Some("object".to_string()),
                            properties: vec![ApiProperty {
                                name: "data".to_string(),
                                schema: ApiSchema {
                                    schema_type: Some("array".to_string()),
                                    ..Default::default()
                                },
                            }],
                            ..Default::default()
                        }),
                    }],
                    headers: vec![],
                }],
            }],
        }],
        security_schemes: vec![],
        global_security: vec![],
    };

    let findings = ResourceRestrictionAnalyzer::analyze(&spec);
    assert!(
        findings
            .iter()
            .any(|f| f.id.contains("missing-pagination")
                && f.vulnerability_type == ApiVulnerabilityType::ResourceExhaustion)
    );
}

// --- Security Misconfig Tests ---

#[test]
fn test_detects_cors_wildcard() {
    let spec = OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![ApiPath {
            path: "/test".to_string(),
            operations: vec![ApiOperation {
                method: "GET".to_string(),
                security: vec![],
                parameters: vec![],
                request_body: None,
                responses: vec![ApiResponse {
                    status_code: "200".to_string(),
                    content: vec![],
                    headers: vec![ApiHeader {
                        name: "Access-Control-Allow-Origin".to_string(),
                        schema: Some(ApiSchema {
                            schema_type: Some("string".to_string()),
                            default: Some(serde_json::Value::String("*".to_string())),
                            ..Default::default()
                        }),
                    }],
                }],
            }],
        }],
        security_schemes: vec![],
        global_security: vec![],
    };

    let findings = SecurityMisconfigAnalyzer::analyze(&spec);
    assert!(
        findings
            .iter()
            .any(|f| f.vulnerability_type == ApiVulnerabilityType::CorsWildcard)
    );
}

#[test]
fn test_security_headers_detects_insecure_cors_wildcard_from_schema() {
    let spec = OpenApiSpec {
        version: "3.0.0".to_string(),
        paths: vec![ApiPath {
            path: "/cors".to_string(),
            operations: vec![ApiOperation {
                method: "GET".to_string(),
                security: vec![],
                parameters: vec![],
                request_body: None,
                responses: vec![ApiResponse {
                    status_code: "200".to_string(),
                    content: vec![],
                    headers: vec![ApiHeader {
                        name: "Access-Control-Allow-Origin".to_string(),
                        schema: Some(ApiSchema {
                            schema_type: Some("string".to_string()),
                            default: Some(serde_json::Value::String("*".to_string())),
                            ..Default::default()
                        }),
                    }],
                }],
            }],
        }],
        security_schemes: vec![],
        global_security: vec![],
    };

    let findings = SecurityHeadersAnalyzer::analyze(&spec);
    assert!(findings.iter().any(|f| {
        f.vulnerability_type == ApiVulnerabilityType::InsecureCors
            && f.severity == vulnera_api::domain::entities::FindingSeverity::High
    }));
}
