# Vulnera — Modular Vulnerability Analysis Platform

**Vulnera** is an open-source, async Rust platform for multi-ecosystem vulnerability analysis. It combines four purpose-built detection modules under a single orchestrator with sandboxed execution, a typed job pipeline, and optional LLM enrichment.

All core analysis — SAST, secrets detection, and API security — runs fully offline. Dependency CVE lookups require network access to OSV, NVD, and GHSA. LLM enrichment requires network access to the configured provider.

---

## The Four Analysis Modules

| Module                                                | Method                                            | Coverage                                                     | Offline? |
| ----------------------------------------------------- | ------------------------------------------------- | ------------------------------------------------------------ | -------- |
| [Dependency Analysis](modules/dependency-analysis.md) | CVE lookup (OSV · NVD · GHSA)                     | npm, PyPI, Cargo, Maven/Gradle, Go, Composer, Bundler, NuGet | ❌ No    |
| [SAST](modules/sast.md)                               | Tree-sitter AST + inter-procedural taint analysis | Python, JavaScript, TypeScript, Rust, Go, C, C++             | ✅ Yes   |
| [Secrets Detection](modules/secrets-detection.md)     | Regex + entropy detection                         | All text files                                               | ✅ Yes   |
| [API Security](modules/api-security.md)               | Rule-based OpenAPI spec analysis                  | OpenAPI 3.0 / 3.1                                            | ✅ Yes   |

LLM enrichment (Google Gemini, OpenAI, Azure OpenAI) is an optional post-processing pass — it adds explanations and fix suggestions to existing findings but is never part of detection.

---

## Documentation Structure

### Getting Started

Role-based quick-start guides:

- [Developer Quick Start](getting-started/personas/developer-quickstart.md) — run your first scan locally in under 5 minutes
- [DevSecOps Quick Start](getting-started/personas/devsecops-quickstart.md) — CI/CD integration, team setup, policy gates
- [Cloud Engineer Quick Start](getting-started/personas/cloud-engineer-quickstart.md) — repository scanning, S3 buckets, infrastructure

### Analysis Capabilities

- [Overview](analysis/overview.md) — module selection, offline vs. online, unified finding schema
- [AI-Assisted Code Analysis (SAST)](analysis/sast.md) — detection methods, language coverage, taint analysis internals
- [AI-Assisted Secret Detection](analysis/secrets-detection.md) — entropy thresholds, baseline support, Git history scanning

### Module Reference

- [Dependency Analysis](modules/dependency-analysis.md) — ecosystem coverage, lockfile strategy, version recommendations
- [SAST](modules/sast.md) — supported languages, rule packs, confidence scoring
- [Secrets Detection](modules/secrets-detection.md) — detection methods, secret types, baselines
- [API Security](modules/api-security.md) — analysis categories, OAuth/OIDC checks, strict mode

### AI-Powered Features

- [LLM Explanations & Auto-Fixes](user-guide/llm-features.md) — provider setup, quotas, caching

### Dashboard & Web Platform

- [Dashboard Guide](user-guide/website-dashboard.md) — web UI overview
- [Organization Management](user-guide/dashboard/organization-management.md) — teams, members, shared quota
- [Team Collaboration](user-guide/dashboard/team-collaboration.md) — workflows for security teams

### Reference

- [Configuration](reference/configuration.md) — environment variable reference with defaults
- [System Architecture](reference/architecture.md) — DDD layering, composition root, cache architecture
- [Orchestrator Observability](reference/orchestrator-observability.md) — job lifecycle event model, instrumentation strategy
- [FAQ](reference/faq.md) — quota, offline capabilities, false positives, troubleshooting

---

## Offline vs. Online Boundaries

**Fully offline (no network required):**

- SAST
- Secrets Detection
- API Security

**Requires network:**

- Dependency Analysis (OSV/NVD/GHSA lookups)
- LLM enrichment (explanations and fixes)

---

## Self-Hosting

The server is a single Rust binary backed by PostgreSQL and optionally Dragonfly/Redis.

**Minimum requirements:**

- Rust 1.91+ (build only)
- PostgreSQL 12+
- Linux 5.13+ recommended (for Landlock sandbox; process isolation fallback works on older kernels)

```/dev/null/commands.txt#L1-3
export DATABASE_URL='postgresql://user:pass@localhost:5432/vulnera'
sqlx migrate run
cargo run
```

Full configuration reference: [Configuration](reference/configuration.md)

---

## License

Server and all analysis modules: [AGPL-3.0-or-later](../../LICENSE)

CLI, Advisors, LSP Adapter: AGPL-3.0-or-later (see each workspace’s `LICENSE` file)

---

## Contributing

See the [project README](../../README.md) for the contribution guide, roadmap, and high-impact areas open for community work.
