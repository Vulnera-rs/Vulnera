# Analysis Modules Overview

Vulnera provides four specialized security analysis modules that can work independently or together through the unified orchestrator.

## Module Summary

| Module | Purpose | Languages/Ecosystems |
|--------|---------|---------------------|
| [Dependency Analysis](dependency-analysis.md) | Scan dependencies for known vulnerabilities | npm, PyPI, Maven, Cargo, Go, Packagist, Ruby, .NET |
| [SAST](sast.md) | Static code analysis for security issues | Python, JavaScript, Rust |
| [Secrets Detection](secrets-detection.md) | Find exposed credentials and API keys | All text files |
| [API Security](api-security.md) | Analyze OpenAPI specifications | OpenAPI 3.x |

## Unified Orchestrator

The orchestrator automatically selects and executes appropriate modules based on the source type and analysis depth.

### Analysis Depth Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `minimal` | Fast analysis with essential checks only | Quick CI checks |
| `standard` | Balanced analysis with comprehensive checks | Default for most projects |
| `full` | Deep analysis including optional checks | Security audits, compliance |

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

This automatically:

1. Detects project type and dependency files
2. Runs Dependency Analysis if dependency files are found
3. Runs SAST for supported languages (Python, JavaScript, Rust)
4. Runs Secrets Detection across all files
5. Runs API Security if OpenAPI specs are detected
6. Aggregates all findings into a unified report

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

## Data Sources

Vulnera aggregates vulnerability data from multiple authoritative sources:

| Source | Type | Coverage |
|--------|------|----------|
| **OSV** | Open Source Vulnerabilities | Multi-ecosystem, maintained by Google |
| **NVD** | National Vulnerability Database | Comprehensive CVE database |
| **GHSA** | GitHub Security Advisories | GitHub-curated advisories |

## Module Selection Logic

The orchestrator uses rule-based module selection:

```
Project Analysis → Detect Files → Select Modules → Execute → Aggregate
       │                │               │              │          │
       │                │               │              │          └─ Unified Report
       │                │               │              │
       │                │               │              └─ Parallel Execution
       │                │               │
       │                │               └─ RuleBasedModuleSelector
       │                │
       │                └─ File Pattern Detection
       │
       └─ Source Type (git, directory, file)
```

## Configuration

Each module can be configured independently. See the individual module pages for specific configuration options:

- [Dependency Analysis Configuration](dependency-analysis.md#configuration)
- [SAST Configuration](sast.md#configuration)
- [Secrets Detection Configuration](secrets-detection.md#configuration)
- [API Security Configuration](api-security.md#configuration)
