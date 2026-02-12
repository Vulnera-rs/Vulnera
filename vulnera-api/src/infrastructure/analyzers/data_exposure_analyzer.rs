//! Sensitive data exposure analyzer

use crate::domain::entities::{ApiFinding, ApiLocation, FindingSeverity};
use crate::domain::value_objects::{ApiVulnerabilityType, OpenApiSpec, ParameterLocation};
use regex::Regex;
use std::sync::OnceLock;

/// Analyzer for sensitive data exposure
pub struct DataExposureAnalyzer;

fn jwt_pattern() -> &'static Regex {
    static JWT_PATTERN: OnceLock<Regex> = OnceLock::new();
    JWT_PATTERN.get_or_init(|| {
        Regex::new(r"eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+")
            .expect("JWT regex pattern must be valid")
    })
}

fn private_key_pattern() -> &'static Regex {
    static PRIVATE_KEY_PATTERN: OnceLock<Regex> = OnceLock::new();
    PRIVATE_KEY_PATTERN.get_or_init(|| {
        Regex::new(r"-----BEGIN [A-Z]+ PRIVATE KEY-----")
            .expect("private key regex pattern must be valid")
    })
}

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

        let jwt_pattern = jwt_pattern();
        let private_key_pattern = private_key_pattern();

        for path in &spec.paths {
            for operation in &path.operations {
                // Check for sensitive data in query parameters
                for param in &operation.parameters {
                    if param.location == ParameterLocation::Query {
                        let param_lower = param.name.to_lowercase();

                        // Existing sensitive data check
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

                        // BOLA Precursor check: user_id in query params
                        if (param_lower == "user_id"
                            || param_lower == "userid"
                            || param_lower == "account_id")
                            && operation.method == "GET"
                        {
                            findings.push(ApiFinding {
                                id: format!("bola-precursor-{}-{}-{}", path.path, operation.method, param.name),
                                vulnerability_type: ApiVulnerabilityType::SensitiveDataInUrl, // Similar category
                                location: ApiLocation {
                                    file_path: "openapi.yaml".to_string(),
                                    line: None,
                                    path: Some(path.path.clone()),
                                    operation: Some(operation.method.clone()),
                                },
                                severity: FindingSeverity::Medium,
                                description: format!(
                                    "Parameter '{}' in query string often indicates BOLA risk (ID Enumeration) in {} {}",
                                    param.name, operation.method, path.path
                                ),
                                recommendation: "Avoid exposing direct object references (ID) in query parameters; use session/token validation".to_string(),
                                path: Some(path.path.clone()),
                                method: Some(operation.method.clone()),
                            });
                        }
                    }

                    // Check schema of parameter
                    if let Some(schema) = &param.schema {
                        Self::analyze_schema(
                            schema,
                            &path.path,
                            &operation.method,
                            &format!("param:{}", param.name),
                            &mut findings,
                            jwt_pattern,
                            private_key_pattern,
                        );
                    }
                }

                // Check request body
                if let Some(rb) = &operation.request_body {
                    for content in &rb.content {
                        if let Some(schema) = &content.schema {
                            Self::analyze_schema(
                                schema,
                                &path.path,
                                &operation.method,
                                "request_body",
                                &mut findings,
                                jwt_pattern,
                                private_key_pattern,
                            );
                        }
                    }
                }

                // Check responses
                for response in &operation.responses {
                    for content in &response.content {
                        if let Some(schema) = &content.schema {
                            Self::analyze_schema(
                                schema,
                                &path.path,
                                &operation.method,
                                &format!("response:{}", response.status_code),
                                &mut findings,
                                jwt_pattern,
                                private_key_pattern,
                            );
                        }
                    }
                }
            }
        }

        findings
    }

    fn analyze_schema(
        schema: &crate::domain::value_objects::ApiSchema,
        path: &str,
        method: &str,
        context: &str,
        findings: &mut Vec<ApiFinding>,
        jwt_pattern: &regex::Regex,
        private_key_pattern: &regex::Regex,
    ) {
        // Check example/default values for secrets
        let check_value =
            |value: &serde_json::Value, field_type: &str, findings: &mut Vec<ApiFinding>| {
                if let Some(s) = value.as_str() {
                    if jwt_pattern.is_match(s) {
                        findings.push(ApiFinding {
                            id: format!("exposed-jwt-{}-{}-{}", path, method, context),
                            vulnerability_type: ApiVulnerabilityType::ExposedSecretInSpec,
                            location: ApiLocation {
                                file_path: "openapi.yaml".to_string(),
                                line: None,
                                path: Some(path.to_string()),
                                operation: Some(method.to_string()),
                            },
                            severity: FindingSeverity::Critical,
                            description: format!(
                                "Leaked JWT detected in {} {} for {} {}",
                                field_type, s, method, context
                            ),
                            recommendation: "Remove real secrets from examples and defaults"
                                .to_string(),
                            path: Some(path.to_string()),
                            method: Some(method.to_string()),
                        });
                    }
                    if private_key_pattern.is_match(s) {
                        findings.push(ApiFinding {
                            id: format!("exposed-key-{}-{}-{}", path, method, context),
                            vulnerability_type: ApiVulnerabilityType::ExposedSecretInSpec,
                            location: ApiLocation {
                                file_path: "openapi.yaml".to_string(),
                                line: None,
                                path: Some(path.to_string()),
                                operation: Some(method.to_string()),
                            },
                            severity: FindingSeverity::Critical,
                            description: format!(
                                "Leaked Private Key detected in {} {} for {} {}",
                                field_type, s, method, context
                            ),
                            recommendation: "Remove real secrets from examples and defaults"
                                .to_string(),
                            path: Some(path.to_string()),
                            method: Some(method.to_string()),
                        });
                    }
                }
            };

        if let Some(example) = &schema.example {
            check_value(example, "example", findings);
        }
        if let Some(default) = &schema.default {
            check_value(default, "default", findings);
        }

        // Recurse
        for prop in &schema.properties {
            Self::analyze_schema(
                &prop.schema,
                path,
                method,
                &format!("{}.{}", context, prop.name),
                findings,
                jwt_pattern,
                private_key_pattern,
            );
        }
    }
}
