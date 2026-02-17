//! Resource Restriction Analyzer
//! Checks for lack of resources restriction (Rate Limiting, Pagination, etc.)

use crate::domain::entities::{ApiFinding, ApiLocation, FindingSeverity};
use crate::domain::value_objects::{ApiVulnerabilityType, OpenApiSpec};

/// Analyzer for resource restriction issues
pub struct ResourceRestrictionAnalyzer;

impl ResourceRestrictionAnalyzer {
    fn schema_contains_array(schema: &crate::domain::value_objects::ApiSchema) -> bool {
        if schema.schema_type.as_deref() == Some("array") {
            return true;
        }

        if schema
            .properties
            .iter()
            .any(|prop| Self::schema_contains_array(&prop.schema))
        {
            return true;
        }

        if schema.one_of.iter().any(Self::schema_contains_array)
            || schema.any_of.iter().any(Self::schema_contains_array)
            || schema.all_of.iter().any(Self::schema_contains_array)
        {
            return true;
        }

        match &schema.additional_properties {
            crate::domain::value_objects::AdditionalProperties::Schema(nested) => {
                Self::schema_contains_array(nested)
            }
            _ => false,
        }
    }

    pub fn analyze(spec: &OpenApiSpec) -> Vec<ApiFinding> {
        let mut findings = Vec::new();

        // Check for Rate Limiting headers in responses
        let mut rate_limit_header_found = false;

        // Also check pagination
        for path in &spec.paths {
            for operation in &path.operations {
                // Pagination check for List operations (GET returning Array)
                if operation.method == "GET" {
                    let mut returns_array = false;
                    for response in &operation.responses {
                        if response.status_code.starts_with('2') {
                            for content in &response.content {
                                if let Some(schema) = &content.schema
                                    && Self::schema_contains_array(schema)
                                {
                                    returns_array = true;
                                }
                            }
                            // Check for rate limit headers in 2xx or 429 response
                            if response
                                .headers
                                .iter()
                                .any(|h| h.name.to_lowercase().contains("ratelimit"))
                            {
                                rate_limit_header_found = true;
                            }
                        }
                        if response.status_code == "429" {
                            rate_limit_header_found = true;
                        }
                    }

                    if returns_array {
                        // Check for pagination parameters
                        let has_pagination = operation.parameters.iter().any(|p| {
                            let name = p.name.to_lowercase();
                            matches!(
                                name.as_str(),
                                "limit" | "offset" | "page" | "cursor" | "size" | "per_page"
                            )
                        });

                        if !has_pagination {
                            findings.push(ApiFinding {
                                id: format!("missing-pagination-{}-{}", path.path, operation.method),
                                vulnerability_type: ApiVulnerabilityType::ResourceExhaustion, // Use appropriate type
                                location: ApiLocation {
                                    file_path: "openapi.yaml".to_string(),
                                    line: None,
                                    path: Some(path.path.clone()),
                                    operation: Some(operation.method.clone()),
                                },
                                severity: FindingSeverity::Medium,
                                description: format!(
                                    "Endpoint {} {} returns a list but missing pagination parameters",
                                    operation.method, path.path
                                ),
                                recommendation: "Implement pagination (limit/offset, page, cursor) to prevent DoS".to_string(),
                                path: Some(path.path.clone()),
                                method: Some(operation.method.clone()),
                            });
                        }
                    }
                }
            }
        }

        if !rate_limit_header_found {
            // This might be a false positive if they use other means, but good to warn
            // Only warning if API is large enough?
            if spec.paths.len() > 3 {
                findings.push(ApiFinding {
                    id: "missing-rate-limiting".to_string(),
                    vulnerability_type: ApiVulnerabilityType::ResourceExhaustion,
                    location: ApiLocation {
                        file_path: "openapi.yaml".to_string(),
                        line: None,
                        path: None,
                        operation: None,
                    },
                    severity: FindingSeverity::Low, // Global finding
                    description: "No Rate Limiting headers (X-RateLimit-*) or 429 responses detected in spec. Verify global rate limiting is applied.".to_string(),
                    recommendation: "Ensure Rate Limiting is enforced to prevent abuse".to_string(),
                    path: None,
                    method: None,
                });
            }
        }

        findings
    }
}
