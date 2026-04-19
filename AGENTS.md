# Vulnera - AI Agent Instructions

Vulnera is a multi-module async Rust vulnerability analysis platform (MSRV 1.92, edition 2024). All AI agents working on this codebase must follow these instructions.

## Architecture: The Big Picture

**Workspace structure** (dependency order):

```
vulnera-rust (binary - HTTP API server, composition root)
  ├─ vulnera-orchestrator  [async job orchestration, job queue, module registry, job workflow]
  │  ├─ vulnera-core       [domain models, shared traits, infra, config]
  │  ├─ vulnera-deps       [dependency scanning, cross-ecosystem resolution]
  │  ├─ vulnera-llm        [LLM providers (GoogleAI, OpenAI) + auto-fix generation]
  │  └─ vulnera-sandbox    [hybrid isolation: Landlock, Seccomp+Process, WASM, NoOp]
  │     ├─ vulnera-sast    [multi-lang static analysis via Tree-sitter]
  │     ├─ vulnera-secrets [entropy & pattern-based credential detection + verification]
  │     ├─ vulnera-deps    [dependency scanning]
  │     └─ vulnera-api    [OpenAPI/REST security analysis]
  ├─ vulnera-sast          [depends on vulnera-core]
  ├─ vulnera-secrets       [depends on vulnera-core]
  ├─ vulnera-api           [depends on vulnera-core]
  └─ vulnera-deps          [depends on vulnera-core]

vulnera-cli       (standalone workspace + repo - offline analysis CLI + server API calls)
vulnera-advisor   (standalone workspace + repo - advisory aggregation from GHSA/NVD/OSV/CISA KEV/EPSS/OSS Index)
vulnera-adapter   (standalone workspace + repo - LSP server for IDE integration via tower-lsp)
```

**Composition Root**: `src/app.rs` is the **single composition root**. It delegates module setup to `src/modules/mod.rs` and wires all use cases, repositories, caches, and HTTP state. Never instantiate services (PgPool, Cache, etc.) inside crate internals - wire everything at the top level and inject via `Arc<dyn Trait>`.

**Domain-Driven Layering** (in most crates):

- `domain/`: Pure types (entities, value objects, traits), zero side effects.
- `application/`: Use cases orchestrating domain logic (e.g., `ExecuteAnalysisJobUseCase`).
- `infrastructure/`: SQL queries, HTTP clients, cache backends (Dragonfly), parsers, external integrations.
- `presentation/`: Axum controllers, DTOs with `utoipa` OpenAPI annotations.

**Exceptions**: `vulnera-deps` has top-level `module.rs`, `use_cases.rs`, `types.rs`, and a `services/` directory outside the DDD layers. `vulnera-cli` uses `commands/` + `application/use_cases/` instead of DDD layering.

## Critical Files & Patterns

| Task | Key Files | Pattern |
|:-----|:----------|:---------|
| **New Module** | `vulnera-core/src/domain/module/traits.rs`, `src/modules/mod.rs` | Implement `AnalysisModule` (async `execute` + optional `prepare_config`); register in `ModuleRegistry` |
| **Sandbox Policy** | `vulnera-sandbox/src/domain/policy.rs`, `.../application/executor.rs`, `.../application/selector.rs` | Build `SandboxPolicy::for_profile(source_path, profile)`; `SandboxPolicyProfile::ReadOnlyAnalysis` or `DependencyResolution { include_cache_port }`; execute via `SandboxExecutor` |
| **SAST Rules** | `vulnera-sast/src/infrastructure/rules/` | `RuleLoader` trait: `BuiltinRuleLoader` (embedded TOML), `FileRuleLoader` (TOML/JSON/YAML), `RulePackLoader` (git+checksum), `CompositeRuleLoader`; default rules in `vulnera-sast/rules/*.toml` |
| **Job Lifecycle** | `vulnera-orchestrator/src/application/workflow.rs`, `.../infrastructure/job_queue.rs`, `.../infrastructure/job_store/` | `JobWorkflow` centralizes state transitions: `Pending → Queued → Running → Completed/Failed`, plus `Cancelled` from Pending/Queued. Dragonfly-backed queue, `spawn_job_worker_pool()` worker pattern |
| **Job Storage** | `vulnera-orchestrator/src/infrastructure/job_store/` | `DragonflyJobStore` implements `JobStore` trait; persists `JobSnapshot` with HMAC-SHA256 webhook delivery (3 retries, exponential backoff) |
| **Module Selection** | `vulnera-orchestrator/src/infrastructure/module_selector.rs` | `RuleBasedModuleSelector` - community vs enterprise tiers; selects modules by `AnalysisDepth` (DependenciesOnly, FastScan, Full) + project metadata + entitlement flag |
| **Auth/API Keys** | `vulnera-core/src/infrastructure/auth/`, `vulnera-orchestrator/src/presentation/auth/` | Dual auth: HttpOnly cookies (web) + API keys (CLI/extensions); JWT + Argon2; CSRF protection; `TokenBlacklistService`; `MasterKey` support; 15+ infrastructure files |
| **Rate Limiting** | `vulnera-core/src/infrastructure/rate_limiter/` | Tiered: `api_key`/`authenticated`/`anonymous` with per-minute/hour/burst; `TokenBucket` + `SlidingWindow`; Dragonfly or in-memory storage |
| **Organizations** | `vulnera-core/src/domain/organization/`, `.../application/organization/` | CRUD + member management (invite/remove/leave), ownership transfer, hierarchical orgs with inherited subscription limits |
| **Analytics** | `vulnera-core/src/application/analytics/`, `vulnera-orchestrator/src/presentation/controllers/analytics.rs` | Dashboard overview, monthly stats, per-org & per-user analytics, quota checking |
| **Database** | `migrations/`, `vulnera-core/src/infrastructure/auth/*.rs` (repositories) | SQLx `query!` macros (compile-time checked, 52 offline queries in `.sqlx/`); `IEntityRepository` trait pattern; single baseline migration with GIN indexes on JSONB |
| **Resilience** | `vulnera-core/src/infrastructure/resilience.rs` | Circuit breaker + exponential backoff with jitter |
| **S3 Source** | `vulnera-orchestrator/src/infrastructure/s3/` | AWS S3 bucket source for analysis; cleaned up after job completion |
| **Reporting** | `vulnera-core/src/application/reporting/` | `ReportServiceImpl` with SARIF/JSON output formats |

## Analysis Capabilities

- **SAST**: Supports **Python, JavaScript, TypeScript, Rust, Go, C, C++, JSON** via Tree-sitter. OXC parser frontend for JS/TS. Taint tracking, CFG, call graph, data-flow analysis, incremental scanning (content-hash based), metavariable patterns.
- **Sandboxing**: Platform-conditional backends. Linux: `LandlockSandbox` (5.13+), `SeccompConfig` + `ProcessSandbox` (fallback). Non-Linux: `WasmSandbox`. Universal: `NoOpSandbox`. `SandboxPolicy::for_analysis` includes system paths, `/tmp` RW, optional HTTP/Redis ports. `ResourceLimits` dynamically scale timeout/memory by module type multipliers.
- **Dependency Analysis**: Cross-ecosystem (NPM, PyPI, Cargo, Maven, Go, Ruby, PHP, NuGet, Gradle) with `vulnera-advisor` intelligence (GHSA, NVD, OSV, CISA KEV, EPSS, OSS Index). CWE filtering and Git commit range matching. `VersionResolutionService` + `VulneraRegistryAdapter` for version resolution.
- **Secret Detection**: Entropy-based + regex pattern detection. AST-aware extraction, semantic validation, baseline support (known-secret baselining), Git history scanning, live verification (AWS, GitHub, GitLab, generic webhooks). `--baseline`/`--save-baseline`/`--only-new` for differential scanning.
- **API Security**: 9 analyzers - authentication, authorization, data_exposure, design, input_validation, oauth, resource_restriction, security_headers, security_misconfig.
- **LLM**: `GoogleAIProvider` and `OpenAIProvider` wrapped by `ResilientProvider` (circuit breaker + retry). 4 use cases: `GenerateCodeFix`, `ExplainVulnerability`, `NaturalLanguageQuery`, `EnrichFindings`. Configurable per-use-case model overrides.

## Configuration & Secrets

- **Strongly-typed config**: `vulnera-core/src/config/mod.rs` (~1430 lines). 17 top-level sections.
- **Env Var Pattern**: `VULNERA__SECTION__KEY=value` (e.g., `VULNERA__SANDBOX__BACKEND=landlock`, `VULNERA__LLM__PROVIDER=google_ai`). `DATABASE_URL` overrides `config.database.url` at load time.
- **Config sections**: server (host, port, workers, timeouts, security, rate_limit), cache (L1 moka + L2 Dragonfly, compression), apis (NVD, GHSA, GitHub), analysis (concurrency, timeouts), sync (interval, on_startup), sast (depth, quality gates, AST cache, incrementality), secret_detection, api_security, auth (JWT, cookies, CSRF, blacklist), database, analytics (retention, cleanup), popular_packages, llm (provider, model overrides, resilience, enrichment), sandbox (backend, failure_mode, dynamic limits), enterprise (license key).
- **Defaults**: `config/default.toml` with sensible defaults for all sections.
- **Validation**: `vulnera-core/src/config/validation.rs` - `Validate` impl for `ServerConfig`, `CacheConfig`, `NvdConfig`, `GhsaConfig`, `ApiConfig`, `AnalysisConfig`, `AuthConfig`, `DatabaseConfig`, `SecretDetectionConfig`, `ApiSecurityConfig`, `TieredRateLimitConfig`.

## Essential Developer Commands

```bash
# Database setup
sqlx migrate run                           # Run migrations (requires DATABASE_URL)
sqlx migrate run --source /app/migrations  # Docker entrypoint runs this automatically

# Development
cargo run                    # Server (loads .env)
cargo watch -x run           # Hot-reload

# Lint & format
cargo fmt --all --check      # Format check
cargo clippy --all-targets --all-features -- -D warnings  # Lint

# Testing (Nextest is preferred)
cargo nextest run --workspace              # Run all tests (respects nextest.toml)
cargo insta review                         # Review snapshot changes
cargo test --test datatest_sast_rules      # Data-driven SAST rule tests

# CLI (Standalone workspace)
cd vulnera-cli && cargo run -- analyze .   # Full analysis (offline+online)
cd vulnera-cli && cargo run -- sast .       # Offline SAST only
cd vulnera-cli && cargo run -- deps .       # Dependency scan (online)
cd vulnera-cli && cargo run -- secrets .    # Offline secret detection
cd vulnera-cli && cargo run -- api .        # Offline API security
cd vulnera-cli && cargo run -- auth login   # Authenticate
cd vulnera-cli && cargo run -- config show  # Show configuration

# Coverage
cargo tarpaulin                             # Uses tarpaulin.toml config
```

## Adding a Feature: Best Practices

### 1. New Analysis Module

- Implement `AnalysisModule` trait (`module_type`, `prepare_config`, `execute`) in a dedicated crate.
- Add the module to `AnalysisModules::init` in `src/modules/mod.rs`.
- Update `RuleBasedModuleSelector` in `vulnera-orchestrator` to trigger it based on `AnalysisDepth` + project metadata.
- Register `ModuleType` variant in `vulnera-core/src/domain/module/value_objects.rs` (Community or Enterprise tier).
- `SandboxExecutor` will discover and use the `vulnera-worker` binary for out-of-process execution; falls back to in-process.

### 2. New API Endpoint

- Add handler in `vulnera-orchestrator/src/presentation/controllers/`.
- Use `#[openapi(paths(...))]` for documentation.
- Inject dependencies via `State<Arc<OrchestratorState>>`.
- Wire service structs in composition root (`src/app.rs`).
- Add route in `vulnera-orchestrator/src/presentation/routes.rs`.

### 2.1 Request Pipeline & Middleware

- Routes and middleware are assembled in `vulnera-orchestrator/src/presentation/routes.rs`.
- Middleware order (outermost→inner): Tracing → CORS → Global timeout → GHSA token → Auth state → Logging → Security headers → HTTPS enforcement → Rate limiting + early auth extraction.
- CSRF protection is required for state-changing routes (cookie auth).
- CORS rules differ for wildcard vs specific origins; wildcard disables credentials.
- Rate limiting uses tiered limits (`Config.server.rate_limit`) and runs after early auth extraction.

### 3. CLI Command

- `vulnera-cli` is a separate workspace with its own `Cargo.lock`. Use `CliContext` for shared state.
- Offline commands (sast, secrets, api) use modules directly via `AnalysisExecutor`; online commands (deps, generate-fix, quota) use `ctx.api_client` (VulneraClient over reqwest).
- Output must use `ctx.output.*` methods for consistent JSON/Table formatting.
- Exit codes: 0=SUCCESS, 1=VULNERABILITIES_FOUND, 2=CONFIG_ERROR, 3=NETWORK_ERROR, 4=QUOTA_EXCEEDED, 5=AUTH_REQUIRED, 99=INTERNAL_ERROR.
- SAST supports `--watch` (file watching), `--fix` (LLM-powered), `--baseline`/`--save-baseline`/`--only-new` (differential scanning).
- `config hooks install/remove/status` manages git pre-commit hooks or `.pre-commit-config.yaml`.

### 4. Sandbox Integration

- Analysis execution is wrapped in `SandboxExecutor` using `SandboxBackend` trait.
- Policies use "Least Privilege": Read-only source access, no network (unless `SandboxPolicyProfile::DependencyResolution { include_cache_port }`).
- `SandboxSelector::select()` auto-picks best available backend; `SandboxSelector::select_by_name(name)` for explicit choice.
- `ResourceLimits::calculate_limits()` dynamically scales timeout/memory by module type (DependencyAnalyzer: 2.5x/1.5x, SAST: 2.0x/2.0x, others: 1.0x/1.0x).
- Worker binary discovery checks `./target/debug/vulnera-worker`, `./target/release/vulnera-worker`, `/usr/local/bin/vulnera-worker`, and `which vulnera-worker`.

### 5. New Repository Trait

- Define `I<Entity>Repository` trait in `vulnera-core/src/domain/<domain>/repositories.rs`.
- Implement in `vulnera-core/src/infrastructure/auth/` or `vulnera-core/src/infrastructure/repositories/`.
- Use SQLx `query!` macros with offline mode (`.sqlx/` directory has 52 cached queries).
- Wire concrete implementation in composition root (`src/app.rs` or `src/auth/mod.rs`).

### 6. New Config Section

- Add field to `Config` struct in `vulnera-core/src/config/mod.rs`.
- Add defaults in `config/default.toml`.
- Add `Validate` impl in `vulnera-core/src/config/validation.rs`.
- Use `VULNERA__<SECTION>__<KEY>` env var pattern.

## Domain Model Reference

### AnalysisModule Trait

```rust
#[async_trait]
pub trait AnalysisModule: Send + Sync {
    fn module_type(&self) -> ModuleType;
    async fn prepare_config(&self, _project: &Project) -> Result<HashMap<String, serde_json::Value>, ModuleExecutionError>;
    async fn execute(&self, config: &ModuleConfig) -> Result<ModuleResult, ModuleExecutionError>;
}
```

### ModuleType Variants

**Community**: `DependencyAnalyzer`, `SAST`, `SecretDetection`, `ApiSecurity`
**Enterprise**: `MaliciousPackageDetection`, `LicenseCompliance`, `SBOM`, `DAST`, `FuzzTesting`, `IaC`, `CSPM`

### Job Status State Machine

```
Pending → Queued → Running → Completed
  |         |         |
  +----→ Cancelled ←+→ Failed
```
Terminal states: `Completed`, `Failed`, `Cancelled`.

### Key Entities

- `Finding`: id, type (Vulnerability/Secret/LicenseViolation/Misconfiguration), rule_id, location, severity (Critical>High>Medium>Low>Info), confidence, description, recommendation, secret_metadata, vulnerability_metadata, enrichment
- `ModuleResult`: job_id, module_type, findings, metadata (files_scanned, duration_ms), optional error
- `JobInvocationContext`: user_id, email, auth_strategy, api_key_id, organization_id, is_master_key

### I-Prefixed Traits (Repository Pattern)

- `IUserRepository`, `IApiKeyRepository`, `IOrganizationRepository`, `IOrganizationMemberRepository`
- `IVulnerabilityRepository`, `IAnalysisEventRepository`, `IPersistedJobResultRepository`
- `IUserStatsMonthlyRepository`, `IPersonalStatsMonthlyRepository`, `ISubscriptionLimitsRepository`
- `IJobQueue` (in orchestrator domain)
- Non-repository domain traits: `ProjectDetector`, `ModuleSelector`, `AnalysisModule`, `SandboxBackend`, `LlmProvider`

## Background Workers

- `spawn_sync_worker`: Periodic advisory sync (configurable interval, runs on startup if enabled).
- `spawn_analytics_cleanup_worker`: Periodic analytics event cleanup (configurable retention days).
- Job worker pool: `spawn_job_worker_pool()` in `vulnera-orchestrator/src/infrastructure/job_queue.rs`, respects `Config.analysis.max_concurrent_packages` (semaphore-bounded).

## Code Style & Implementation Rules

- **Error Handling**: Use `thiserror` for library errors and `anyhow` for application/CLI wiring. Never `unwrap()` in production.
- **Concurrency**: Respect `Config.analysis.max_concurrent_packages`. Use `tokio::sync::JoinSet` for parallel analysis tasks.
- **Traits**: Prefix repository traits with `I` (e.g., `IUserRepository`). Domain service traits (`ProjectDetector`, `ModuleSelector`, `SandboxBackend`, `LlmProvider`) do NOT use `I` prefix.
- **Async Traits**: Use `#[async_trait]` for trait objects with async methods.
- **Serialization**: `serde` with `#[derive]` for all domain types. JSON is the canonical wire format.
- **Logging**: Use `tracing` (`info!`, `warn!`, `error!`, `debug!`) everywhere.
- **Performance**: L1 `moka` (in-memory) + L2 Dragonfly (distributed) caching.
- **Testing**: `#[serial]` for tests hitting the database. `insta` for API response snapshots. `datatest-stable` for data-driven SAST rule tests. `proptest` for property-based tests. `testcontainers` for integration tests requiring PostgreSQL/Dragonfly. Use `nextest` as the test runner.
- **Compression**: Always compress advisory data with `zstd` before storing in Redis/Dragonfly.

## Pre-Commit & CI

- **Githooks** (`.githooks/pre-commit`): `cargo fmt --all --check && cargo check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --lib --tests`
- **Pre-commit** (`.pre-commit-config.yaml`): Same checks as local hooks.
- **Docker**: Multi-stage build with stub-based dependency caching. Runtime includes `python3` + `pipx`. Entrypoint runs migrations before starting server. Health check on `/health`.

## Testing & Pre-Commit Checklist

- [ ] `cargo clippy --all-targets --all-features -- -D warnings` is clean.
- [ ] `cargo fmt --all --check` passes.
- [ ] New SQL queries are verified via `.sqlx/` offline data or live DB.
- [ ] Any new config has a default in `config/default.toml`.
- [ ] Any new config section has a `Validate` impl in `vulnera-core/src/config/validation.rs`.
- [ ] Public API changes are reflected in `ApiDoc` (utoipa).
- [ ] Sandbox compatibility verified for Linux (Landlock) and non-Linux (Wasm) backends.
- [ ] Enterprise-only features gated behind `enterprise_entitled` flag in `ModuleRegistry`/`RuleBasedModuleSelector`.
- [ ] New repository traits follow `IXxxRepository` naming convention.
- [ ] New domain traits do NOT use `I` prefix (only repository traits do).

## Standalone Repos Reference

### vulnera-cli
- **Depends on**: vulnera-core, vulnera-sast, vulnera-secrets, vulnera-api (via git from GitHub, local override for dev)
- **Commands**: `analyze`, `deps`, `sast`, `secrets`, `api`, `quota`, `auth`, `config`, `generate-fix`
- **Auth**: OS keyring (preferred) or AES-256-GCM encrypted file fallback at `~/.vulnera/credentials.enc`
- **Quota**: 10/day unauthenticated, 40/day authenticated. SAST/Secrets/API are free. UTC midnight reset.
- **Default server**: `https://api.vulnera.studio/`
- **SAST extras**: `--watch` (watch mode), `--fix` (LLM fixes), `--baseline`/`--save-baseline`/`--only-new`

### vulnera-advisor
- **Sources**: GHSA (GraphQL), NVD, OSV, CISA KEV, EPSS, OSS Index (with caching)
- **Storage**: DragonflyDB/Redis with zstd compression
- **Key patterns**: `vuln:data:{id}` (data), `vuln:idx:{eco}:{pkg}` (index), `vuln:enrich:{cve}` (enrichment), `vuln:ossidx:{hash}` (OSS Index cache, 1h TTL)
- **Builder pattern**: `VulnerabilityManagerBuilder::new().redis_url(url).with_ghsa().with_nvd().with_osv_defaults().build()`

### vulnera-adapter
- **LSP server** using `tower-lsp` for IDE integration
- **Connects to Vulnera server** via `POST /api/v1/dependencies/analyze` with `X-API-Key` header
- **Features**: Document sync, diagnostics, code actions (quick-fix version upgrades), debounced batch analysis (500ms), workspace-keyed grouping
