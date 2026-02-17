# API Security

The API Security module analyzes OpenAPI 3.x specifications to identify security vulnerabilities and design misconfigurations before deployment. It runs fully offline and is triggered when an OpenAPI spec is detected (or explicitly provided).

## Supported Specifications

- OpenAPI 3.0
- OpenAPI 3.1

## Analyzer Categories (Actual)

These analyzers run on the parsed OpenAPI spec:

- **Authentication** — missing auth, weak schemes (e.g., basic), insecure auth usage
- **Authorization** — missing authorization checks, overly permissive access
- **Input Validation** — missing request validation, unsafe parameter shapes
- **Data Exposure** — sensitive data in URLs/headers, response overexposure
- **Security Headers** — missing CSP/HSTS/XFO/XCTO; CORS review
- **OAuth/OIDC** — insecure flows, redirect issues, token validation gaps
- **Design** — versioning and error-handling issues
- **Security Misconfiguration** — insecure defaults and configuration pitfalls
- **Resource Restriction** — missing request size/limit constraints

## Notable Checks

- **CORS wildcard detection**: `Access-Control-Allow-Origin: *` is flagged as high severity.
- **Missing security headers**: required headers are validated per response.
- **Missing authentication**: endpoints with no security requirements are flagged.

## Configuration

The module is configured via `vulnera_core::config::ApiSecurityConfig`.

### Key settings

- `enabled_analyzers`: list of analyzers to run (empty = all)
- `severity_overrides`: map of vulnerability type → severity
- `exclude_paths`: skip specific API paths
- `strict_mode`: more aggressive checks

### Example (TOML)

```/dev/null/config.toml#L1-10
[api_security]
enabled_analyzers = ["authentication", "authorization", "input_validation", "security_headers"]
exclude_paths = ["/health", "/metrics"]
strict_mode = true

[api_security.severity_overrides]
"missing_authentication" = "high"
"insecure_cors" = "high"
```

## CLI Usage

Analyze a spec directly using the CLI:

```/dev/null/commands.txt#L1-6
# Auto-detect spec in a directory
vulnera api .

# Analyze an explicit spec file
vulnera api . --spec ./openapi.yaml
```

**Relevant flags:**

- `--spec <path>` — explicit OpenAPI spec path
- `--min-severity <critical|high|medium|low>`
- `--fail-on-issue`
- `--framework <name>` (optional)

## Output

Findings are emitted in the unified finding schema with:

- `severity` and `confidence`
- `location` (path + operation)
- `description` and `recommendation`

SARIF output is supported:

```/dev/null/commands.txt#L1-2
vulnera api . --format sarif > report.sarif
```

## Limitations

- Relies on the spec as the source of truth — runtime behavior is out of scope.
- Missing or incomplete specs will limit detection.

## Next Steps

- [Analysis Overview](../analysis/overview.md)
- [Configuration Reference](../reference/configuration.md)
