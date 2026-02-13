# Vulnera Copilot Instructions

Vulnera is a multi-module async Rust vulnerability analysis platform (MSRV 1.91+). AI agents should focus on domain-driven design (DDD) patterns, the sandbox-isolated execution model, and the modular analysis pipeline orchestrated by the composition root.

## Architecture: The Big Picture

**Workspace structure** (dependency order):

```
vulnera-rust (binary - HTTP API server)
  ├─ vulnera-orchestrator  [async job orchestration, job queue, module registry]
  │  ├─ vulnera-sandbox    [hybrid isolation: Landlock, seccomp, WASM, Process]
  │  ├─ vulnera-deps       [dependency scanning, cross-ecosystem resolution]
  │  ├─ vulnera-sast       [Multi-lang static analysis via Tree-sitter]
  │  ├─ vulnera-secrets    [entropy & pattern-based credential detection]
  │  ├─ vulnera-api        [OpenAPI/REST security analysis]
  │  └─ vulnera-llm        [Gemini-powered explanations & auto-fixes]
  └─ vulnera-core          [domain models, shared traits, infra, config]

vulnera-cli (standalone workspace and repository - offline analysis cli client + server API calls)
vulnera-advisor (standalone workspace and repository - advisors crate + server API calls)
vulnera-adapter (standalone workspace and repository - lsp crate + server API calls)
```

**Composition Root**: `src/app.rs` is the **single composition root**. It delegates module setup to `src/modules/mod.rs` and wires all use cases, repositories, caches, and HTTP state. Never instantiate services (PgPool, Cache, etc.) inside crate internals—wire everything at the top level and inject via `Arc<dyn Trait>`.

**Domain-Driven Layering**:

- `domain/`: Pure types (entities, value objects, traits), zero side effects.
- `application/`: Use cases orchestrating domain logic (e.g., `ExecuteAnalysisJobUseCase`).
- `infrastructure/`: SQL queries, HTTP clients, cache backends (Dragonfly), parsers.
- `presentation/`: Axum controllers, DTOs with `utoipa` OpenAPI annotations.

## Critical Files & Patterns

| Task                 | Key Files                                                              | Pattern                                                                                        |
| :------------------- | :--------------------------------------------------------------------- | :--------------------------------------------------------------------------------------------- |
| **New Module**       | `vulnera-core/.../traits.rs`, `src/modules/mod.rs`                     | Implement `AnalysisModule`; register in `ModuleRegistry`                                       |
| **Sandbox Policy**   | `vulnera-sandbox/src/domain/policy.rs`, `.../application/use_cases.rs` | Build `SandboxPolicy::for_profile(SandboxPolicyProfile::...)`; execution via `SandboxExecutor` |
| **SAST Rules**       | `vulnera-sast/src/infrastructure/rules/`                               | Tree-sitter queries + visitor pattern for taint/data-flow                                      |
| **Job Lifecycle**    | `vulnera-orchestrator/src/infrastructure/job_queue.rs`                 | Dragonfly-backed queue -> worker pool -> `ExecuteAnalysisJobUseCase` -> Sandbox                |
| **Job Storage**      | `vulnera-orchestrator/src/infrastructure/job_store/`                   | Persist snapshots (`FindingsSummary`, metadata) with optional webhook delivery                 |
| **Module Selection** | `vulnera-orchestrator/src/infrastructure/module_selector.rs`           | `RuleBasedModuleSelector` decides modules by `AnalysisDepth` + project metadata                |
| **Auth/API Keys**    | `vulnera-core/src/infrastructure/auth/`, `.../presentation/auth/`      | JWT + Argon2; cookie auth with CSRF; API key endpoints under `/api/v1/auth/api-keys`           |
| **Database**         | `migrations/`, `vulnera-core/.../infrastructure/`                      | SQLx `query!` macros (compile-time checked); `IEntityRepository` traits                        |

## Analysis Capabilities

- **SAST**: Supports **Python, JavaScript, TypeScript, Rust, Go, C, C++** using Tree-sitter.
- **Sandboxing**: Tiered isolation. Linux (Landlock + Seccomp) -> Process -> fallback. `SandboxPolicy::for_analysis` includes system paths, `/tmp` RW, and optional HTTP/Redis ports.
- **Dependency Analysis**: Cross-ecosystem (NPM, PyPI, Cargo, Maven) with `vulnera-advisor` intelligence. Supports CWE filtering and Git commit range matching.
- **LLM**: Integrated `GeminiLlmProvider` for automated remediation and finding enrichment.

## Configuration & Secrets

- **Strongly-typed config**: `vulnera-core/src/config/mod.rs`.
- **Env Var Pattern**: `VULNERA__SECTION__KEY=value` (e.g., `VULNERA__SANDBOX__BACKEND=landlock`). `DATABASE_URL` overrides `config.database.url` at load time.
- **Cache**: Dragonfly/Redis only (`Config.cache.dragonfly_url`).
- **DB**: PostgreSQL via SQLx. `DATABASE_URL` is required for compilation.

## Essential Developer Commands

```bash
# Database setup
sqlx migrate run

# Development
cargo run                    # Server (loads .env)
cargo watch -x run           # Hot-reload

# Testing (Nextest is preferred)
cargo nextest run --workspace              # Run all tests (respects nextest.toml)
cargo insta review                         # Review snapshot changes
cargo test --test datatest_*               # Data-driven SAST/Deps tests

# CLI (Standalone workspace)
cd vulnera-cli && cargo run -- scan .
```

## Adding a Feature: Best Practices

### 1. New Analysis Module

- Implement `AnalysisModule` in a dedicated crate.
- Add the module to `AnalysisModules::init` in `src/modules/mod.rs`.
- Update `RuleBasedModuleSelector` in `vulnera-orchestrator` to trigger it based on file patterns.

### 2. New API Endpoint

- Add handler in `vulnera-orchestrator/src/presentation/controllers/`.
- Use `#[openapi(paths(...))]` for documentation.
- Inject dependencies via `State<Arc<OrchestratorServices>>`.

### 2.1 Request Pipeline & Middleware

- Routes and middleware are assembled in `vulnera-orchestrator/src/presentation/routes.rs`.
- CSRF protection is required for state-changing routes (cookie auth).
- CORS rules differ for wildcard vs specific origins; wildcard disables credentials.
- Rate limiting uses tiered limits (`Config.server.rate_limit`) and runs after early auth extraction.

### 3. CLI Command

- `vulnera-cli` is a separate workspace. Use `CliContext` for shared state.
- Offline commands should use modules directly; online commands use `ctx.api_client`.
- Output must use `ctx.output.*` methods for consistent JSON/Table formatting.

### 4. Sandbox Integration

- Analysis execution is wrapped in `SandboxExecutor`.
- Policies should be "Least Privilege": Read-only source access, no network (unless `allow_network` config is set).
- Dependency analysis enables network and adds port 6379 for Dragonfly when required.

## Background Workers

- Sync and analytics cleanup workers live in `src/workers/mod.rs`.
- Job worker pool is spawned from `vulnera-orchestrator/src/infrastructure/job_queue.rs` and respects `Config.analysis.max_job_workers`.

## Code Style & Implementation Rules

- **Error Handling**: Use `thiserror` for library errors and `anyhow` for application/CLI wiring. Never `unwrap()` in production.
- **Concurrency**: Respect `Config.analysis.max_job_workers`. Use `tokio::sync::JoinSet` for parallel analysis tasks.
- **Traits**: Prefix traits with `I` (e.g., `IUserRepository`) for clear separation from implementations.
- **Performance**: Leverage `moka` for L1 (In-memory) and Dragonfly for L2 (Distributed) caching.
- **Testing**: Use `#[serial]` for tests hitting the database. Use `insta` for all API response snapshots.

## Testing & Pre-Commit Checklist

- [ ] `cargo clippy` is clean.
- [ ] New SQL queries are verified via `sqlx-data.json` or live DB.
- [ ] Any new config has a default in `config/default.toml`.
- [ ] Public API changes are reflected in `ApiDoc` (utoipa).
- [ ] Sandbox compatibility verified for Linux/Non-Linux backends.
