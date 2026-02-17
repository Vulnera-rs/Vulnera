<div align="center">

# Vulnera

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![MSRV: 1.91](https://img.shields.io/badge/MSRV-1.91-orange.svg)](https://www.rust-lang.org/)
[![version](https://img.shields.io/badge/version-0.5.1-green.svg)](CHANGELOG.md)
[![Docs](https://img.shields.io/badge/docs-online-blue)](https://Vulnera-rs.github.io/Vulnera/)

**A modular, async Rust vulnerability analysis platform.**

[Documentation](https://Vulnera-rs.github.io/Vulnera/) · [Architecture](docs/src/reference/architecture.md) · [Changelog](CHANGELOG.md) · [Contributing](#contributing)

</div>

---

## Philosophy

Most security tooling is either a black box SaaS product or a single-purpose scanner duct-taped into a CI pipeline. Vulnera is neither.

The core conviction: **security analysis should be a composable, auditable, offline-first system** — not a phone-home service. Every finding must be traceable to a rule, a tree-sitter query, or a named entropy threshold. No mystery scores.

Design principles that govern every decision:

- **Make illegal states unrepresentable.** The type system enforces domain invariants; panics and `unwrap()` are banned in production paths via CI guardrails.
- **Least-privilege execution.** Analysis modules run inside Landlock + seccomp sandboxes on Linux. The sandbox is not optional glue — it is a first-class domain concept with a typed policy builder.
- **Dependency inversion at every boundary.** Nothing instantiates its own database pool or HTTP client. Everything is wired at the composition root (`src/app.rs`) and injected via `Arc<dyn Trait>`.
- **Offline first, network optional.** SAST, secrets detection, and API analysis run fully offline. Network is opt-in (dependency CVE lookups, LLM enrichment).

---

## What It Does

Four analysis modules, one orchestrator, one job queue:

| Module                  | Method                                            | Ecosystems / Languages                                       |
| ----------------------- | ------------------------------------------------- | ------------------------------------------------------------ |
| **Dependency Analysis** | CVE lookup via OSV · NVD · GHSA                   | npm, PyPI, Cargo, Maven/Gradle, Go, Composer, Bundler, NuGet |
| **SAST**                | Tree-sitter AST + inter-procedural taint analysis | Python, JavaScript, TypeScript, Rust, Go, C, C++             |
| **Secrets Detection**   | ML-pattern + Shannon entropy                      | All text files                                               |
| **API Security**        | Spec-rule engine                                  | OpenAPI 3.0 / 3.1                                            |

LLM enrichment (Google Gemini, OpenAI, Azure OpenAI) is an optional post-processing pass — it explains and proposes fixes for findings but is never part of detection itself.

---

## Architecture at a Glance

```
vulnera-rust  (binary — Axum HTTP server, composition root)
  ├─ vulnera-orchestrator   async job queue · module registry · REST API · analytics
  │    ├─ vulnera-sandbox   Landlock + seccomp · process isolation · typed policy builder
  │    ├─ vulnera-deps      dependency graph · lockfile parsers · registry clients
  │    ├─ vulnera-sast      Tree-sitter engine · taint/call-graph · TOML rule packs
  │    ├─ vulnera-secrets   entropy analysis · ML pattern matching
  │    ├─ vulnera-api       OpenAPI 3.x rule engine
  │    └─ vulnera-llm       provider registry (Gemini · OpenAI · Azure) · resilience layer
  └─ vulnera-core           domain models · config · shared traits · infra abstractions

vulnera-cli      (separate workspace — offline scanner + server client)
vulnera-advisor  (separate workspace — advisory intelligence crate)
adapter          (separate workspace — LSP server)
```

Each crate follows strict DDD layering: `domain/` has zero side effects, `application/` orchestrates use cases, `infrastructure/` owns all I/O, `presentation/` owns HTTP controllers and DTOs.

Full architecture detail: [`docs/src/reference/architecture.md`](docs/src/reference/architecture.md)

---

## Current State

**Working and tested:**

- Full job-based analysis pipeline (HTTP → queue → sandbox → modules → persist)
- All four analysis modules with configurable depth (`minimal` / `standard` / `full`)
- Landlock + seccomp sandbox with typed `SandboxPolicy` and `fail_closed` mode
- JWT + Argon2 cookie auth with CSRF · API key auth with SHA-256 storage
- Token-bucket rate limiting with per-tier quotas (anonymous / API key / org)
- Organization model with RBAC (owner / admin / analyst / viewer)
- Two-level cache: Moka L1 (in-memory) + Dragonfly L2 (distributed)
- SARIF output · webhook delivery · analytics aggregation
- LLM provider registry with circuit-breaker + exponential backoff
- SAST V5: declarative TOML rule packs · `SymbolTable` · inter-procedural taint · OXC frontend option for JS/TS and semantic analysis
- Data-driven CVE fixture harness with precision/recall quality gates in CI

**Known gaps / active work:**

- Transitive dependency resolution for manifest-only projects (no lockfile) is incomplete in some ecosystems
- Enterprise license gating (`ModuleTier`) is plumbed but the entitlement check is not enforced end-to-end
- WASM sandbox backend is scaffolded but not functional
- OpenTelemetry export is not yet wired (observability event model is defined, spans are not exported)
- Windows support is untested; Landlock is Linux-only by design

---

## Quick Start (Server)

**Requirements:** Rust 1.91+, PostgreSQL 12+, `sqlx-cli`

```bash
git clone https://github.com/Vulnera-rs/Vulnera.git
cd Vulnera

# Database
export DATABASE_URL='postgresql://user:pass@localhost:5432/vulnera'
sqlx migrate run

# Minimal config
cat > .env <<'EOF'
DATABASE_URL=postgresql://user:pass@localhost:5432/vulnera
VULNERA__AUTH__JWT_SECRET=change-me-to-a-random-32-char-secret
EOF

cargo run
# → http://localhost:3000
# → http://localhost:3000/docs  (Swagger UI)
```

See [`docs/src/reference/configuration.md`](docs/src/reference/configuration.md) for the full env-var reference.

---

## Roadmap

Roughly ordered by impact-to-effort ratio:

### Near-term (next 1–3 months)

- [ ] Complete lockfile-independent transitive resolution for npm and PyPI
- [ ] OpenTelemetry span export (Jaeger / OTLP)
- [ ] Enforce enterprise tier gating end-to-end
- [ ] WASM sandbox backend (portable alternative to Landlock for non-Linux)
- [ ] Formal reachability scoring: combine CVE severity + call-graph reachability
- [ ] GitHub Actions integration
- [ ] Self-hosted deployment guide

### Medium-term (3–6 months)

- [ ] Policy-as-code: org-level `vulnera.policy.toml` with block / warn / ignore rules
- [ ] False-positive management loop: per-finding suppression with audit trail
- [ ] DAST module scaffold (HTTP fuzzing via OpenAPI spec)
- [ ] IaC security module (Terraform, Dockerfile, Kubernetes manifests)
- [ ] SCIM provisioning for enterprise SSO

### Longer-term

- [ ] Best-in-class Rust-specific analysis: MIR-level unsafe auditing, `unsafe` attribution across FFI boundaries
- [ ] Measurable MTTR reduction pipeline: auto-PR generation for dependency upgrades
- [ ] Cross-repo dependency graph for monorepos
- [ ] Custom rule IDE (web-based TOML rule editor with live preview)
- [ ] Vulnera-Monitor as Darkweb and in real-time monitoring of vulnerabilities

---

## Contributing

This is an early-stage open-source project. Contributions in any of these areas accelerate it the most:

**High-impact, well-scoped:**

- SAST rules — new Tree-sitter queries in `vulnera-sast/rules/*.toml` with a matching CVE fixture in `vulnera-sast/tests/fixtures/` and we will open a new repo for community contributions.
- Lockfile parsers — completing `go.sum`, `Gemfile.lock`, and `composer.lock` transitive resolution in `vulnera-deps`
- False positives — improving entropy thresholds and pattern filters in `vulnera-secrets`

**Architectural:**

- OpenTelemetry integration — wire the existing observability event model (`docs/src/reference/orchestrator-observability.md`) to an OTLP exporter
- WASM sandbox backend — implement `SandboxExecutor` for `wasmtime` in `vulnera-sandbox`

**Quality:**

- Expanding the CVE fixture corpus (`vulnera-sast/tests/fixtures/`) with real-world vulnerable code samples
- Integration tests for the full HTTP → queue → analysis → persist pipeline

### Setup

```bash
# Install git hooks
chmod +x .githooks/pre-commit
git config core.hooksPath .githooks

# Run full CI check locally
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
cargo nextest run --workspace

# Review snapshot changes after logic edits
cargo insta review
```

**Before opening a PR**, read [`CONTRIBUTING.md`](CONTRIBUTING.md). The short version: conventional commits, no `unwrap()`/`expect()` in production paths (CI will reject it), and new SQL must use `sqlx::query!` macros. Also, please approve the CLA.

---

## Security

Vulnerabilities should be reported privately. See [`SECURITY.md`](SECURITY.md).

---

## License

**Server, analysis modules, orchestration** (`vulnera-rust`, `vulnera-core`, `vulnera-orchestrator`, `vulnera-sast`, `vulnera-deps`, `vulnera-secrets`, `vulnera-api`, `vulnera-llm`, `vulnera-sandbox`): [AGPL-3.0-or-later](LICENSE)

**CLI, Advisors, LSP Adapter** (`vulnera-cli`, `advisors`, `adapter`): AGPL-3.0-or-later (see each Repo's LICENSE file)
