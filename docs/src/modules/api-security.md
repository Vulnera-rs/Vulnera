# API Security

The API Security Module analyzes OpenAPI 3.x specifications to identify security vulnerabilities and misconfigurations in API designs.

## Supported Specifications

- OpenAPI 3.0
- OpenAPI 3.1

## Analysis Categories

| Category | Description |
|----------|-------------|
| **Authentication** | Missing or weak authentication mechanisms |
| **Authorization** | Missing authorization checks, RBAC gaps |
| **Input Validation** | Missing request validation, injection risks |
| **Data Exposure** | Sensitive data in URLs/headers, missing encryption |
| **Security Headers** | Missing headers, insecure CORS |
| **API Design** | Versioning issues, error handling, information disclosure |
| **OAuth/OIDC** | Insecure flows, token validation issues |

## Features

- **OpenAPI 3.x Support** — Full support via `oas3` crate
- **Configurable Analyzers** — Enable/disable specific checks
- **Severity Overrides** — Customize severity levels
- **Path Exclusion** — Exclude specific API paths
- **Strict Mode** — More aggressive security checks

## API Usage

API Security analysis is automatically executed when OpenAPI specs are detected:

```bash
curl -X POST http://localhost:3000/api/v1/analyze/job \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "source_type": "git",
    "source_uri": "https://github.com/my-org/api-project.git",
    "analysis_depth": "full"
  }'
```

## Detected Issues

### Authentication Issues

- Missing authentication on sensitive endpoints
- Weak authentication mechanisms
- JWT expiration issues
- Insecure token storage

### Authorization Issues

- Missing authorization checks
- Overly permissive access controls
- RBAC gaps
- Broken object-level authorization

### Input Validation Issues

- Missing request validation
- SQL injection risks in parameters
- File upload without size limits
- XSS vulnerabilities in responses

### Data Exposure Issues

- Sensitive data in URLs
- PII in query parameters
- Missing encryption requirements
- Verbose error messages

### Security Header Issues

- Missing Content-Security-Policy
- Insecure CORS configuration
- Missing X-Content-Type-Options
- Missing X-Frame-Options

### OAuth/OIDC Issues

- Insecure OAuth flows (implicit flow)
- Missing token validation
- Redirect URI issues
- Scope problems

## Response Format

```json
{
  "findings": [
    {
      "module": "api_security",
      "category": "authentication",
      "severity": "high",
      "path": "/api/users/{id}",
      "method": "GET",
      "message": "Endpoint lacks authentication requirement",
      "remediation": "Add security scheme requirement to this endpoint"
    },
    {
      "module": "api_security",
      "category": "input_validation",
      "severity": "medium",
      "path": "/api/search",
      "method": "GET",
      "parameter": "query",
      "message": "Query parameter lacks validation schema",
      "remediation": "Add schema validation for the 'query' parameter"
    }
  ]
}
```

## Configuration

```bash
# Enable/disable specific analyzers
VULNERA__API_SECURITY__ENABLE_AUTH_ANALYSIS=true
VULNERA__API_SECURITY__ENABLE_INJECTION_ANALYSIS=true
VULNERA__API_SECURITY__ENABLE_DATA_EXPOSURE_ANALYSIS=true

# Strict mode (more aggressive checks)
VULNERA__API_SECURITY__STRICT_MODE=false

# Path exclusions (JSON array)
VULNERA__API_SECURITY__EXCLUDE_PATHS='["/health", "/metrics"]'
```

## Severity Overrides

Customize severity levels for specific issue types:

```toml
[api_security.severity_overrides]
missing_authentication = "critical"
missing_rate_limiting = "medium"
verbose_errors = "low"
```

## Best Practices Checked

The module validates against these security best practices:

1. **All endpoints require authentication** (except explicitly public ones)
2. **Rate limiting is configured** for all endpoints
3. **Request bodies have size limits** defined
4. **Response schemas don't expose sensitive fields**
5. **HTTPS is required** for all operations
6. **OAuth 2.0 uses secure flows** (authorization code, not implicit)
7. **API versioning is implemented** properly
8. **Error responses don't leak information**

## Supported Security Schemes

| Scheme | Support |
|--------|---------|
| HTTP Basic | ✅ Detected, flagged as weak |
| HTTP Bearer | ✅ Fully supported |
| API Key | ✅ Fully supported |
| OAuth 2.0 | ✅ Flow analysis |
| OpenID Connect | ✅ Configuration analysis |
