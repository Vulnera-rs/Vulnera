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

### Detail Levels

| Level | Best For | Includes |
|-------|----------|----------|
| `minimal` | Status bar, badges | Vulnerabilities list, basic metadata |
| `standard` | Inline decorations, quick fixes | Vulnerabilities, packages, version recommendations |
| `full` | Detailed reports, dependency trees | All data + dependency graph |

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
