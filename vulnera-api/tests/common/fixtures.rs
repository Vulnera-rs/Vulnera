//! Test data fixtures for vulnera-api

/// Sample OpenAPI 3.0 specification
pub fn sample_openapi_spec() -> &'static str {
    r#"openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users:
    get:
      responses:
        '200':
          description: Success
"#
}

/// Sample OpenAPI spec with OAuth
pub fn sample_openapi_oauth() -> &'static str {
    r#"openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
components:
  securitySchemes:
    oauth2:
      type: oauth2
      flows:
        authorizationCode:
          authorizationUrl: https://example.com/oauth/authorize
          tokenUrl: https://example.com/oauth/token
"#
}

