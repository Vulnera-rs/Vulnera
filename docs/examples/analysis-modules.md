# Analysis Modules Examples

Vulnera provides specialized analysis modules that can be executed individually or in combination through the unified orchestrator API.

## Dependency Analysis Module

Analyzes dependency manifests across multiple package ecosystems to identify known vulnerabilities.

### Supported Ecosystems

- **Python:** `requirements.txt`, `Pipfile`, `pyproject.toml`
- **Node.js:** `package.json`, `package-lock.json`, `yarn.lock`
- **Java:** `pom.xml`, `build.gradle`
- **Rust:** `Cargo.toml`, `Cargo.lock`
- **Go:** `go.mod`, `go.sum`
- **PHP:** `composer.json`, `composer.lock`
- **Ruby:** `Gemfile`, `Gemfile.lock`
- **.NET (NuGet):** `packages.config`, `*.csproj` (PackageReference), `*.props`/`*.targets` (central management)

### Example: Analyze Python Dependencies

```bash
curl -X POST http://localhost:3000/api/v1/dependencies/analyze \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "file_content": "django==3.2.0\nrequests>=2.25.0\nflask==1.1.0",
    "ecosystem": "PyPI",
    "filename": "requirements.txt"
  }'
```

### Example: Analyze Node.js Dependencies

```bash
curl -X POST http://localhost:3000/api/v1/dependencies/analyze \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "file_content": "{\"dependencies\": {\"express\": \"4.17.1\", \"lodash\": \"4.17.20\"}}",
    "ecosystem": "npm",
    "filename": "package.json"
  }'
```

### Features

- Concurrent package processing with configurable parallelism
- Aggregated vulnerability data from OSV, NVD, and GHSA
- Safe version recommendations with upgrade impact classification
- Registry version resolution with caching

## SAST (Static Application Security Testing) Module

Performs static code analysis to detect security vulnerabilities in source code using Abstract Syntax Tree (AST) parsing.

### Supported Languages

- **Python:** AST parsing via `tree-sitter-python`
- **JavaScript/TypeScript:** AST parsing via `tree-sitter-javascript`
- **Rust:** AST parsing via `syn` crate (proc-macro-based)

### Example: SAST Analysis via Orchestrator

SAST analysis is automatically executed when analyzing a repository with the orchestrator:

```bash
curl -X POST http://localhost:3000/api/v1/analyze/job \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "source_type": "git",
    "source_uri": "https://github.com/my-org/my-project.git",
    "analysis_depth": "full"
  }'
```

### Rule Configuration

Rules can be defined in TOML or JSON format:

**TOML Example:**
```toml
[[rules]]
id = "custom-sql-injection"
name = "Custom SQL Injection"
description = "Detects potential SQL injection vulnerabilities"
severity = "High"
languages = ["Python", "JavaScript"]
pattern = { FunctionCall = "query" }
```

**JSON Example:**
```json
{
  "rules": [
    {
      "id": "custom-sql-injection",
      "name": "Custom SQL Injection",
      "description": "Detects potential SQL injection vulnerabilities",
      "severity": "High",
      "languages": ["Python", "JavaScript"],
      "pattern": {
        "FunctionCall": "query"
      }
    }
  ]
}
```

### Capabilities

- Configurable rule repository (TOML/JSON file loading)
- Default rule set for common vulnerabilities (SQL injection, command injection, unsafe deserialization, etc.)
- Pattern-based detection with multiple matcher types:
  - AST node type matching
  - Function call name matching
  - Regular expression patterns
- Automatic confidence scoring based on pattern specificity
- Configurable scan depth and exclude patterns

## Secrets Detection Module

Identifies exposed secrets, credentials, API keys, and other sensitive information in source code and repositories.

### Detection Methods

- **Regex-based Detection:** Pattern matching for known secret formats
- **Entropy-based Detection:** Statistical analysis of high-entropy strings
  - Base64 strings (default threshold: 4.5)
  - Hexadecimal strings (default threshold: 3.0)
- **Git History Scanning:** Optional analysis of commit history for secrets

### Supported Secret Types

- AWS credentials (access keys, secret keys, session tokens)
- API keys (generic, Stripe, Twilio, etc.)
- OAuth tokens and JWT tokens
- Database credentials and connection strings
- Private keys (SSH, RSA, EC, PGP)
- Cloud provider credentials (Azure, GCP)
- Version control tokens (GitHub, GitLab)
- High-entropy strings (Base64, hex)

### Example: Secrets Detection via Orchestrator

```bash
curl -X POST http://localhost:3000/api/v1/analyze/job \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "source_type": "directory",
    "source_uri": "/path/to/project",
    "analysis_depth": "standard"
  }'
```

### Features

- Configurable entropy thresholds
- Optional secret verification service integration
- Baseline file support for tracking known secrets
- File size limits and timeout controls
- Comprehensive exclude patterns for build artifacts and dependencies

## API Security Module

Analyzes OpenAPI 3.x specifications to identify security vulnerabilities in API designs.

### Analysis Categories

- **Authentication:** Missing or weak authentication mechanisms, JWT expiration issues
- **Authorization:** Missing authorization checks, overly permissive access, RBAC gaps
- **Input Validation:** Missing request validation, SQL injection risks, file upload size limits
- **Data Exposure:** Sensitive data in URLs/headers, missing encryption, PII handling
- **Security Headers:** Missing security headers, insecure CORS configuration
- **API Design:** Versioning issues, error handling, information disclosure, pagination
- **OAuth/OIDC:** Insecure OAuth flows, missing token validation, redirect URI issues

### Example: API Security Analysis

API Security analysis is automatically executed when OpenAPI specifications are detected:

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

### Features

- OpenAPI 3.x specification parsing via `oas3` crate
- Configurable analyzer enablement (selective analysis)
- Severity overrides for specific vulnerability types
- Path exclusion support
- Strict mode for more aggressive security checks

## Unified Orchestrator Analysis

The orchestrator automatically selects and executes appropriate modules based on the source type and analysis depth.

### Analysis Depth Levels

- `minimal`: Fast analysis with essential checks only
- `standard`: Balanced analysis with comprehensive checks (default)
- `full`: Deep analysis including optional checks and extended scanning

### Example: Full Repository Analysis

```bash
curl -X POST http://localhost:3000/api/v1/analyze/job \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "source_type": "git",
    "source_uri": "https://github.com/my-org/my-project.git",
    "analysis_depth": "full"
  }'
```

This will automatically:
1. Detect project type and dependency files
2. Run Dependency Analysis if dependency files are found
3. Run SAST for supported languages (Python, JavaScript, Rust)
4. Run Secrets Detection across all files
5. Run API Security if OpenAPI specs are detected
6. Aggregate all findings into a unified report

### Response Format

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "summary": {
    "total_findings": 42,
    "critical": 1,
    "high": 5,
    "medium": 15,
    "low": 21
  },
  "findings": [
    {
      "module": "dependency_analysis",
      "type": "vulnerability",
      "severity": "high",
      "package": "lodash",
      "version": "4.17.20",
      "vulnerability": "CVE-2021-23337"
    },
    {
      "module": "sast",
      "type": "code_issue",
      "severity": "medium",
      "file": "src/api.js",
      "line": 42,
      "rule": "sql-injection"
    }
  ]
}
```

