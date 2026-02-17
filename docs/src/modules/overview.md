# Analysis Modules Overview

Vulnera provides four specialized security analysis modules that can run independently or together through the unified orchestrator. Module selection is automatic and tier-aware.

## Module Summary

| Module                                        | Purpose                                     | Coverage                                                     | Offline? |
| --------------------------------------------- | ------------------------------------------- | ------------------------------------------------------------ | -------- |
| [Dependency Analysis](dependency-analysis.md) | Scan dependencies for known vulnerabilities | npm, PyPI, Cargo, Maven/Gradle, Go, Composer, Bundler, NuGet | ❌ No    |
| [SAST](sast.md)                               | Static code analysis for security issues    | Python, JavaScript, TypeScript, Rust, Go, C, C++             | ✅ Yes   |
| [Secrets Detection](secrets-detection.md)     | Find exposed credentials and API keys       | All text files                                               | ✅ Yes   |
| [API Security](api-security.md)               | Analyze OpenAPI specifications              | OpenAPI 3.0 / 3.1                                            | ✅ Yes   |

LLM enrichment is optional post-processing. It never participates in detection and requires network access.

---

## Module Selection Logic (Orchestrator)

The orchestrator uses `RuleBasedModuleSelector` to activate modules based on project content and analysis depth:

```
Project Source (directory / git / S3)
        │
        ▼
File pattern detection
        │
        ├─ dependency manifests found?  → Dependency Analysis
        ├─ supported source files found? → SAST
        ├─ all files (Full only) → Secrets Detection
        └─ OpenAPI spec found? → API Security
        │
        ▼
Parallel execution (one sandbox per module)
        │
        ▼
Aggregated findings report
```

---

## Analysis Depth (Orchestrator)

The orchestrator uses a coarse depth model to decide which modules run:

| Depth               | Description                                      | Modules                     |
| ------------------- | ------------------------------------------------ | --------------------------- |
| `dependencies_only` | Dependencies only                                | deps                        |
| `fast_scan`         | Fast scan (dependencies + minimal code analysis) | deps + sast                 |
| `full`              | Full analysis (all applicable modules)           | deps + sast + secrets + api |

> Module coverage still depends on project content. For example, SAST only runs if supported source files are present; API Security only runs if an OpenAPI spec is detected.

---

## Module Tiers (Community vs Enterprise)

Module types are defined in `vulnera-core/src/domain/module/value_objects.rs` and tagged by tier.

**Community (open-source):**

- `DependencyAnalyzer`
- `SAST`
- `SecretDetection`
- `ApiSecurity`

**Enterprise (licensed, not enabled by default):**

- `MaliciousPackageDetection`
- `LicenseCompliance`
- `SBOM`
- `DAST`
- `FuzzTesting`
- `IaC`
- `CSPM`

The selector adds enterprise modules in `Full` analysis and filters them by entitlement. The entitlement check is present but not enforced end-to-end yet.

---

## Data Sources (Dependency Analysis)

Dependency findings are aggregated from:

- **OSV** — Open-source vulnerability database
- **NVD** — National Vulnerability Database
- **GHSA** — GitHub Security Advisories

Results are cached (Moka L1 + Dragonfly L2) to reduce repeated network calls.

---

## Module Reference

- [Dependency Analysis](dependency-analysis.md) — ecosystem coverage, lockfile strategy, version recommendations
- [SAST](sast.md) — supported languages, rule packs, taint analysis, confidence scoring
- [Secrets Detection](secrets-detection.md) — detection methods, secret types, baselines
- [API Security](api-security.md) — analysis categories, OAuth/OIDC checks, strict mode
