# Dependency Analysis

The Dependency Analysis Module scans dependency manifests across multiple package ecosystems to identify known vulnerabilities in your project's dependencies.

## Supported Ecosystems

| Ecosystem | Files |
|-----------|-------|
| **Python (PyPI)** | `requirements.txt`, `Pipfile`, `pyproject.toml` |
| **Node.js (npm)** | `package.json`, `package-lock.json`, `yarn.lock` |
| **Java (Maven/Gradle)** | `pom.xml`, `build.gradle` |
| **Rust (Cargo)** | `Cargo.toml`, `Cargo.lock` |
| **Go** | `go.mod`, `go.sum` |
| **PHP (Composer)** | `composer.json`, `composer.lock` |
| **Ruby (Bundler)** | `Gemfile`, `Gemfile.lock` |
| **.NET (NuGet)** | `packages.config`, `*.csproj`, `*.props`, `*.targets` |

## Features

- **Concurrent Processing** — Analyzes multiple packages in parallel for faster results
- **Safe Version Recommendations** — Provides upgrade suggestions with impact classification (major/minor/patch)
- **Registry Integration** — Resolves versions from official package registries
- **CVE Aggregation** — Combines vulnerability data from OSV, NVD, and GHSA
- **Version Constraint Analysis** — Understands complex version constraints

## API Usage

### Analyze Python Dependencies

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

### Analyze Node.js Dependencies

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

### Batch Analysis (Extension API)

For IDE extensions and batch processing:

```bash
curl -X POST "http://localhost:3000/api/v1/dependencies/analyze?detail_level=standard" \
  -H "Content-Type: application/json" \
  -d '{
    "files": [
      {
        "file_content": "express@4.17.1",
        "ecosystem": "npm",
        "filename": "package.json",
        "workspace_path": "/frontend"
      },
      {
        "file_content": "django==3.2.0",
        "ecosystem": "pypi",
        "filename": "requirements.txt",
        "workspace_path": "/backend"
      }
    ],
    "enable_cache": true
  }'
```

### Detail Levels

| Level | Best For | Includes |
|-------|----------|----------|
| `minimal` | Status bar, badges | Vulnerabilities list, basic metadata |
| `standard` | Inline decorations, quick fixes | Vulnerabilities, packages, version recommendations |
| `full` | Detailed reports, dependency trees | All data + dependency graph |

## Response Structure

```json
{
  "results": [
    {
      "filename": "package.json",
      "ecosystem": "npm",
      "workspace_path": "/frontend",
      "vulnerabilities": [...],
      "packages": [...],
      "version_recommendations": [...],
      "metadata": {
        "total_packages": 25,
        "vulnerable_packages": 3,
        "total_vulnerabilities": 5,
        "severity_breakdown": {
          "critical": 1,
          "high": 2,
          "medium": 1,
          "low": 1
        },
        "analysis_duration_ms": 1250,
        "sources_queried": ["OSV", "NVD"]
      },
      "cache_hit": false
    }
  ],
  "metadata": {
    "total_files": 1,
    "successful": 1,
    "failed": 0,
    "duration_ms": 1250
  }
}
```

## Configuration

```bash
# Maximum concurrent packages analyzed
VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES=3

# Maximum concurrent registry queries
VULNERA__ANALYSIS__MAX_CONCURRENT_REGISTRY_QUERIES=5

# Exclude prerelease versions from recommendations
VULNERA__RECOMMENDATIONS__EXCLUDE_PRERELEASES=false

# Maximum version queries per request
VULNERA__RECOMMENDATIONS__MAX_VERSION_QUERIES_PER_REQUEST=50
```

## Version Recommendations

When vulnerabilities are found, the module provides safe version recommendations:

```json
{
  "package": "lodash",
  "current_version": "4.17.15",
  "vulnerability": "CVE-2021-23337",
  "recommendations": {
    "nearest_safe": "4.17.21",
    "latest_safe": "4.17.21",
    "upgrade_impact": "patch"
  }
}
```

### Upgrade Impact Classification

| Impact | Description |
|--------|-------------|
| `patch` | Bug fix only (x.y.Z) |
| `minor` | New features, backward compatible (x.Y.z) |
| `major` | Breaking changes (X.y.z) |
