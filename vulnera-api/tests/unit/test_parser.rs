//! Unit tests for OpenAPI parser

use std::path::Path;
use vulnera_api::infrastructure::parser::OpenApiParser;

#[test]
fn test_parse_valid_minimal_spec() {
    let content = include_str!("../fixtures/valid_minimal.yaml");
    let result = OpenApiParser::parse(content, Path::new("test.yaml"));

    assert!(result.is_ok());
    let spec = result.unwrap();
    assert_eq!(spec.version, "3.0.0");
    assert_eq!(spec.paths.len(), 1);
    assert_eq!(spec.paths[0].path, "/health");
}

#[test]
fn test_parse_missing_security_spec() {
    let content = include_str!("../fixtures/missing_security.yaml");
    let result = OpenApiParser::parse(content, Path::new("test.yaml"));

    assert!(result.is_ok());
    let spec = result.unwrap();
    assert_eq!(spec.paths.len(), 2);
    // Verify no global security
    assert!(spec.global_security.is_empty());
    // Verify operations have no security
    for path in &spec.paths {
        for operation in &path.operations {
            assert!(operation.security.is_empty());
        }
    }
}

#[test]
fn test_parse_oauth2_all_flows() {
    let content = include_str!("../fixtures/oauth2_all_flows.yaml");
    let result = OpenApiParser::parse(content, Path::new("test.yaml"));

    assert!(result.is_ok());
    let spec = result.unwrap();

    // Should have 4 OAuth2 security schemes
    assert_eq!(spec.security_schemes.len(), 4);

    // Verify scheme names
    let scheme_names: Vec<String> = spec
        .security_schemes
        .iter()
        .map(|s| s.name.clone())
        .collect();
    assert!(scheme_names.contains(&"oauth2Implicit".to_string()));
    assert!(scheme_names.contains(&"oauth2AuthCode".to_string()));
    assert!(scheme_names.contains(&"oauth2ClientCreds".to_string()));
    assert!(scheme_names.contains(&"oauth2Password".to_string()));
}

#[test]
fn test_parse_empty_content_fails() {
    let result = OpenApiParser::parse("", Path::new("empty.yaml"));
    assert!(result.is_err());
}

#[test]
fn test_parse_invalid_yaml_fails() {
    let invalid = "invalid: yaml: content:\n  broken - structure";
    let result = OpenApiParser::parse(invalid, Path::new("bad.yaml"));
    assert!(result.is_err());
}

#[test]
fn test_parse_invalid_openapi_version() {
    let content = r#"
openapi: 2.0.0
info:
  title: Old Spec
  version: 1.0.0
paths: {}
"#;
    let result = OpenApiParser::parse(content, Path::new("old.yaml"));
    assert!(result.is_err());
}

#[test]
fn test_parse_json_format() {
    let content = r#"{
  "openapi": "3.0.0",
  "info": {
    "title": "JSON API",
    "version": "1.0.0"
  },
  "paths": {
    "/test": {
      "get": {
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      }
    }
  }
}"#;
    let result = OpenApiParser::parse(content, Path::new("test.json"));
    assert!(result.is_ok());
    let spec = result.unwrap();
    assert_eq!(spec.version, "3.0.0");
}

#[test]
fn test_parse_file_not_found() {
    let result = OpenApiParser::parse_file(Path::new("/nonexistent/file.yaml"));
    assert!(result.is_err());
}

#[test]
fn test_parse_all_http_methods() {
    let content = r#"
openapi: 3.0.0
info:
  title: Methods API
  version: 1.0.0
paths:
  /resource:
    get:
      responses:
        '200':
          description: OK
    post:
      responses:
        '201':
          description: Created
    put:
      responses:
        '200':
          description: Updated
    delete:
      responses:
        '204':
          description: Deleted
    patch:
      responses:
        '200':
          description: Patched
    head:
      responses:
        '200':
          description: Headers
    options:
      responses:
        '200':
          description: Options
"#;
    let result = OpenApiParser::parse(content, Path::new("methods.yaml"));
    assert!(result.is_ok());
    let spec = result.unwrap();
    assert_eq!(spec.paths.len(), 1);
    assert_eq!(spec.paths[0].operations.len(), 7);

    let methods: Vec<String> = spec.paths[0]
        .operations
        .iter()
        .map(|op| op.method.clone())
        .collect();
    assert!(methods.contains(&"GET".to_string()));
    assert!(methods.contains(&"POST".to_string()));
    assert!(methods.contains(&"PUT".to_string()));
    assert!(methods.contains(&"DELETE".to_string()));
    assert!(methods.contains(&"PATCH".to_string()));
    assert!(methods.contains(&"HEAD".to_string()));
    assert!(methods.contains(&"OPTIONS".to_string()));
}

#[test]
fn test_parse_api_key_security() {
    let content = r#"
openapi: 3.0.0
info:
  title: API Key API
  version: 1.0.0
components:
  securitySchemes:
    apiKeyHeader:
      type: apiKey
      in: header
      name: X-API-Key
    apiKeyQuery:
      type: apiKey
      in: query
      name: api_key
paths:
  /data:
    get:
      security:
        - apiKeyHeader: []
      responses:
        '200':
          description: OK
"#;
    let result = OpenApiParser::parse(content, Path::new("apikey.yaml"));
    assert!(result.is_ok());
    let spec = result.unwrap();

    assert_eq!(spec.security_schemes.len(), 2);
    assert_eq!(spec.paths[0].operations[0].security.len(), 1);
    assert_eq!(
        spec.paths[0].operations[0].security[0].scheme_name,
        "apiKeyHeader"
    );
}

#[test]
fn test_parse_http_bearer_security() {
    let content = r#"
openapi: 3.0.0
info:
  title: Bearer API
  version: 1.0.0
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
paths:
  /protected:
    get:
      security:
        - bearerAuth: []
      responses:
        '200':
          description: OK
"#;
    let result = OpenApiParser::parse(content, Path::new("bearer.yaml"));
    assert!(result.is_ok());
    let spec = result.unwrap();

    assert_eq!(spec.security_schemes.len(), 1);
    assert_eq!(spec.security_schemes[0].name, "bearerAuth");
}

#[test]
fn test_parse_global_security() {
    let content = r#"
openapi: 3.0.0
info:
  title: Global Security API
  version: 1.0.0
security:
  - apiKey: []
components:
  securitySchemes:
    apiKey:
      type: apiKey
      in: header
      name: X-API-Key
paths:
  /data:
    get:
      responses:
        '200':
          description: OK
"#;
    let result = OpenApiParser::parse(content, Path::new("global.yaml"));
    assert!(result.is_ok());
    let spec = result.unwrap();

    // Global security should be populated
    assert_eq!(spec.global_security.len(), 1);
    assert_eq!(spec.global_security[0].scheme_name, "apiKey");
}

#[test]
fn test_parse_parameters() {
    let content = r#"
openapi: 3.0.0
info:
  title: Parameters API
  version: 1.0.0
paths:
  /users/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
        - name: filter
          in: query
          required: false
          schema:
            type: string
        - name: X-Custom-Header
          in: header
          schema:
            type: string
      responses:
        '200':
          description: OK
"#;
    let result = OpenApiParser::parse(content, Path::new("params.yaml"));
    assert!(result.is_ok());
    let spec = result.unwrap();

    let operation = &spec.paths[0].operations[0];
    assert_eq!(operation.parameters.len(), 3);

    // Check parameter locations
    assert_eq!(operation.parameters[0].name, "id");
    assert!(operation.parameters[0].required);
    assert_eq!(operation.parameters[1].name, "filter");
    assert!(!operation.parameters[1].required);
}

#[test]
fn test_parse_schema_references() {
    let content = include_str!("../fixtures/schema_refs.yaml");
    let result = OpenApiParser::parse(content, Path::new("test.yaml"));

    assert!(
        result.is_ok(),
        "Failed to parse spec with schema references"
    );
    let spec = result.unwrap();

    // Should have 2 paths
    assert_eq!(spec.paths.len(), 2);

    // Check that response schemas are present (not empty due to unresolved refs)
    let get_users = &spec.paths[0].operations[0];
    assert!(!get_users.responses.is_empty());
    assert!(!get_users.responses[0].content.is_empty());

    // The schema should be resolved (not empty)
    let response_schema = &get_users.responses[0].content[0].schema;
    assert!(
        response_schema.is_some(),
        "Response schema should be resolved"
    );
}

#[test]
fn test_circular_references_handled() {
    let content = include_str!("../fixtures/circular_refs.yaml");
    let result = OpenApiParser::parse(content, Path::new("test.yaml"));

    // Should not panic on circular references
    assert!(
        result.is_ok(),
        "Should handle circular references gracefully"
    );
    let spec = result.unwrap();

    assert_eq!(spec.paths.len(), 1);
}
