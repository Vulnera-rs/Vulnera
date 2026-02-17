# Dependency Analysis

The Dependency Analysis module scans dependency manifests and lockfiles across multiple ecosystems to identify known vulnerabilities. It requires network access for CVE lookups (OSV, NVD, GHSA).

## Supported Ecosystems

| Ecosystem               | Files                                                 |
| ----------------------- | ----------------------------------------------------- |
| **Python (PyPI)**       | `requirements.txt`, `Pipfile`, `pyproject.toml`       |
| **Node.js (npm)**       | `package.json`, `package-lock.json`, `yarn.lock`      |
| **Java (Maven/Gradle)** | `pom.xml`, `build.gradle`                             |
| **Rust (Cargo)**        | `Cargo.toml`, `Cargo.lock`                            |
| **Go**                  | `go.mod`, `go.sum`                                    |
| **PHP (Composer)**      | `composer.json`, `composer.lock`                      |
| **Ruby (Bundler)**      | `Gemfile`, `Gemfile.lock`                             |
| **.NET (NuGet)**        | `packages.config`, `*.csproj`, `*.props`, `*.targets` |

## Online Requirement

Dependency analysis requires a server connection to query vulnerability sources:

- OSV
- NVD
- GHSA

Running in offline mode skips dependency analysis.

## Resolution Strategy

Vulnera uses a hybrid resolution approach:

- **Lockfile-first** — Extracts a fully resolved dependency tree from lockfiles for accurate transitive coverage.
- **Manifest-only fallback** — Best-effort resolution via registry metadata when lockfiles are absent.

**Known gaps:** Lockfile-independent transitive resolution is incomplete for some ecosystems (notably npm and PyPI).

## Features

- **Directed dependency graph** with reachability analysis
- **Concurrent vulnerability lookups** with configurable limits
- **Safe version recommendations** with patch/minor/major impact classification
- **CWE normalization** and filtering
- **Advisory intelligence** via `vulnera-advisor`

## Detail Levels

| Level      | Best For                           | Includes                                           |
| ---------- | ---------------------------------- | -------------------------------------------------- |
| `minimal`  | Status badges                      | Vulnerabilities list, basic metadata               |
| `standard` | Inline decorations, quick fixes    | Vulnerabilities, packages, version recommendations |
| `full`     | Detailed reports, dependency trees | All data + dependency graph                        |

## Output Example

```/dev/null/example.json#L1-13
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

## CLI Usage

Dependency analysis runs via `vulnera deps` (online only):

```/dev/null/commands.txt#L1-8
# Basic scan
vulnera deps .

# Include transitive dependencies
vulnera deps . --include-transitive

# Force rescan (ignore local cache)
vulnera deps . --force-rescan
```

## Next Steps

- [Analysis Overview](../analysis/overview.md)
- [Configuration Reference](../reference/configuration.md)
