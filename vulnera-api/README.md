# vulnera-api

OpenAPI 3.x specification security analysis module.

## Purpose

Static analysis of API specifications for security issues:

- **OpenAPI discovery** - Automatic spec file detection
- **9 security analyzers** - Authentication, authorization, data exposure, etc.
- **Contract integrity** - Schema validation and reference resolution

## Analyzers

1. **Authentication Analyzer** - Weak or missing authentication
2. **Authorization Analyzer** - Access control issues
3. **Data Exposure Analyzer** - Sensitive data in responses
4. **Design Analyzer** - API design anti-patterns
5. **Input Validation Analyzer** - Schema validation gaps
6. **OAuth Analyzer** - OAuth flow security issues
7. **Resource Restriction Analyzer** - Rate limiting, pagination
8. **Security Headers Analyzer** - Missing security headers
9. **Security Misconfiguration Analyzer** - Configuration issues

## Supported Formats

- OpenAPI 3.0
- OpenAPI 3.1
- Swagger 2.0 (limited support)

## Usage

```bash
vulnera api .  # CLI usage - auto-detects openapi.yaml/spec files
```

## License

AGPL-3.0-or-later. See [LICENSE](../LICENSE) for details.
