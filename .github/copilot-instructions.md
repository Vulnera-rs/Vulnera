# Vulnera Copilot Instructions

Vulnera is a multi-module async Rust vulnerability analysis platform (MSRV 1.82+). AI agents should focus on domain-driven design patterns, composition root wiring, and the orchestrator's modular analysis pipeline.

## Architecture: The Big Picture

**Workspace structure** (dependency order):

```
vulnera-rust (binary + CLI)
  ├─ vulnera-orchestrator  [async job orchestration, HTTP API, middleware]
  │  ├─ vulnera-deps       [dependency scanning, cross-ecosystem]
  │  ├─ vulnera-sast       [Python/JS/Rust static analysis]
  │  ├─ vulnera-secrets    [credential/API key detection]
  │  ├─ vulnera-api        [OpenAPI spec analysis]
  │  └─ vulnera-llm        [LLM-powered explanations & fixes]
  └─ vulnera-core          [domain models, shared traits, infra]
```

**Why this matters**: `src/app.rs` is the **single composition root** where all services (PgPool, DragonflyCache, HTTP clients, module registry) are instantiated and injected via `OrchestratorState`. Never instantiate services inside crate internals—wire everything at the top level.

**Domain-Driven Layering** (applies to every crate):

- `domain/`: Pure types (entities, value objects, traits), zero side effects
- `application/`: Use cases orchestrating domain logic; repositories abstract data access
- `infrastructure/`: SQL queries, HTTP clients, cache backends, parsers, file I/O
- `presentation/`: Controllers, request/response DTOs with OpenAPI annotations

## Critical Files & Patterns

| Task                    | Key Files                                                                                  | Pattern                                                                             |
| ----------------------- | ------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| Add new analysis module | `vulnera-deps/src/module.rs` (ref), `src/app.rs`                                           | Implement `AnalysisModule` trait; register in `ModuleRegistry`                      |
| Add API endpoint        | `vulnera-orchestrator/src/presentation/controllers/`, `routes.rs`, `models.rs`             | Handler + route + `#[openapi(...)]` + `#[derive(ToSchema)]` DTO                     |
| Job lifecycle           | `vulnera-orchestrator/src/infrastructure/{job_queue,job_worker}`                           | Async job store (Dragonfly), worker pool respects `Config.analysis.max_job_workers` |
| Concurrency limits      | `vulnera-core/src/config/mod.rs`, `config/default.toml`                                    | Use `Config.analysis.max_concurrent_packages`, never hardcode                       |
| Auth/API keys           | `vulnera-core/src/infrastructure/auth/`, controllers use `OptionalApiKeyAuth`/`ApiKeyAuth` | JWT + API key extractors; never parse headers manually                              |
| Rate limiting           | `vulnera-core/src/infrastructure/rate_limiter.rs`                                          | Tier-based (API key > authenticated > anonymous); dragonfly-backed token buckets    |
| Module selection        | `vulnera-orchestrator/src/infrastructure/module_selector.rs`                               | `RuleBasedModuleSelector` picks modules by `ModuleType` + source file detection     |

## Configuration & Secrets

- **Strongly-typed config**: `vulnera-core/src/config/mod.rs`; defaults in `config/default.toml`
- **Environment variable pattern**: `VULNERA__SECTION__KEY=value` (double underscore separators, uppercase)
  - E.g., `VULNERA__AUTH__JWT_SECRET`, `VULNERA__CACHE__DRAGONFLY_URL`
- **Required at startup**: `DATABASE_URL` (PostgreSQL), `VULNERA__AUTH__JWT_SECRET` (min 32 chars in production)
- **Cache backend**: Only Dragonfly/Redis supported (`Config.cache.dragonfly_url`); don't add alternatives
- **SQLx query validation**: Requires `DATABASE_URL` at compile time; run `scripts/prepare-sqlx.sh` if offline

## Essential Developer Commands

```bash
# Quick iteration (from repo root or scripts/build_workflow/)
make quick-check             # fmt + clippy + fast unit tests
make test-comprehensive      # full suite with coverage + property tests

# Database (required for integration tests)
export DATABASE_URL='postgresql://user:pass@localhost/vulnera'
make migrate                 # Apply pending migrations
make migrate-info            # Check migration status

# Server with hot-reload
cargo run                    # Load .env via dotenvy
cargo watch -x run           # Auto-rebuild on file changes

# Testing specifics
cargo nextest run --workspace              # Run tests (respects nextest.toml retries: 3x, 300s timeout)
cargo nextest run -p vulnera-deps          # Run single crate tests
cargo insta review                         # Review snapshot test changes after API updates
cargo test --test proptest_*               # Property-based tests (version/parser edge cases)
cargo test --test datatest_*               # Data-driven tests (SAST/deps analysis)
cargo test --features cli                  # Test CLI commands locally
```

**Test organization**:

- Unit tests: `crate/tests/` dirs (run with cargo, no `#[cfg(test)]` inline)
- Snapshot tests: `vulnera-orchestrator/tests/snapshots/` using `insta` crate—review with `cargo insta review` after API shape changes
- Integration tests: In `tests/` dirs; use `#[serial]` decorator if sharing DB state
- Nextest config: `nextest.toml` defines 3x retries, 300s unit timeout, 600s integration timeout

## Adding a Feature: By Type

### New Analysis Module (e.g., SBOM analysis)

1. Create `vulnera-sbom/src/module.rs`: struct implementing `AnalysisModule` trait (see `vulnera-deps/src/module.rs` as template)
2. In `src/app.rs`, instantiate and register: `module_registry.register(Arc::new(SbomModule::new(...)))`
3. `RuleBasedModuleSelector` will auto-detect based on `ModuleType` and file patterns

### New API Endpoint

1. Add handler in `vulnera-orchestrator/src/presentation/controllers/{feature_name}.rs`
2. Add route in `routes.rs` under `api_routes` function (or create new nested router)
3. Add `#[openapi(paths(...))]` path entry in `ApiDoc`
4. Add request/response types to `models.rs` with `#[derive(ToSchema, Serialize, Deserialize)]`

### New CLI Command

1. Add `CommandName(Args)` variant to `Commands` enum in `vulnera-cli/src/lib.rs`
2. Create handler in `vulnera-cli/src/commands/{command_name}.rs`; add `pub mod {command_name};` to `commands/mod.rs`
3. Implement `async fn run(ctx: &CliContext, cli: &Cli, args: &Args) -> Result<i32>`
4. For offline execution: use embedded module (e.g., `SecretDetectionModule::new()`)
5. For server calls: use `ctx.api_client` (pre-authenticated with credentials)
6. Output via `ctx.output.*` methods (never direct `println!`); return exit codes from `exit_codes` module

### New Config Section

1. Add struct in `vulnera-core/src/config/mod.rs` with `#[serde(default)]`
2. Add field to root `Config` struct; implement `Default` trait
3. Add to `Validate` impl if validation rules needed
4. Add section to `config/default.toml` with sensible defaults
5. Override via `VULNERA__SECTION__KEY` env vars

## Code Patterns (Project-Specific)

### Async/Job Architecture

- **Job lifecycle**: HTTP handler → `CreateAnalysisJobUseCase` → `JobQueueHandle.push_job()` → Dragonfly queue → worker pool dequeues → `ExecuteAnalysisJobUseCase` → module execution → result persistence
- **Concurrency**: Reference `Config.analysis.max_concurrent_packages` and `Config.analysis.max_job_workers` (set in `config/default.toml`), never hardcode thread pools
- **Worker pool**: Spawned in `src/app.rs` via `spawn_job_worker_pool()`; respects `max_job_workers` from config

### CLI Structure (in `vulnera-cli/`)

- **Entry point**: `src/lib.rs::CliApp::run()` → command dispatch → individual command handler
- **Offline modules**: SAST, Secrets, API use embedded analyzers (no server needed); Deps requires server
- **Context**: `CliContext` (lightweight) vs `OrchestratorState` (full HTTP server); CLI initializes only needed services
- **Output**: `OutputWriter` wraps `OutputFormat` (Table/JSON/Plain/SARIF); use `ctx.output.*` methods, never direct `println!`
- **Credentials**: Stored via `CredentialManager` (macOS Keychain / Linux Secret Service / Windows Credential Manager, falls back to encrypted file)
- **Config**: Searched in order: `.vulnera.toml` (project), `$XDG_CONFIG_HOME/vulnera/config.toml`, `~/.config/vulnera/config.toml`

### Service Injection & Traits

- **All services**: `Arc<dyn Trait + Send + Sync>` in `OrchestratorState` or `CliContext`, never bare structs
- **Trait pattern**: `Irepository`, `IService`, `IClient` prefixes for traits; implementation structs in `infrastructure/`
- **Error handling**: Domain errors in `domain/errors.rs`; infrastructure errors wrapped in use cases; HTTP responses use `ErrorResponse` DTO

### Database & Queries

- **All SQLx queries**: In `infrastructure/` module with `sqlx::query!` or `sqlx::query_as!` macros (compile-time validated)
- **Migrations**: In `migrations/` numbered sequentially; run `make migrate` before tests
- **Repositories**: All DB access abstracted via repository traits (`IUserRepository`, `IOrganizationRepository`, etc.)

### External APIs

- **Circuit breaker pattern**: Use existing `crate::infrastructure::api_clients` wrappers (HTTP clients pre-configured with retry/timeout)
- **Resilience config**: `CircuitBreakerConfigSerializable` and `RetryConfigSerializable` in config; never instantiate ad-hoc clients
- **Cache layer**: Use `CacheServiceImpl` wrapper; configure TTL via `Config.cache.ttl_hours`; backend is Dragonfly/Redis only

### Module System

- Each analysis module (Deps, SAST, Secrets, API, LLM) implements `AnalysisModule` trait defined in `vulnera-core::domain::module`
- Module registration: `ModuleRegistry` in `vulnera-orchestrator/src/infrastructure/`
- Module selection: `RuleBasedModuleSelector` auto-picks by `ModuleType` and source file detection (e.g., `requirements.txt` → PyPI module)

## Testing Patterns

- **Unit tests**: Keep domain logic testable; use `#[cfg(test)]` modules
- **Integration tests**: In `tests/` dirs; use test fixtures in `tests/fixtures/`
- **Snapshot tests**: After API changes, regenerate with `cargo insta review` before committing
- **Property tests**: `proptest_*.rs` files for parser/version handling edge cases
- **Data-driven tests**: `datatest_*.rs` files for SAST/dependency test cases
- **Serial tests**: Mark with `#[serial]` if they share DB state; nextest runs them single-threaded (configured in `nextest.toml`)
- **Timeouts**: Integration tests timeout at 600s, unit tests 300s (see `nextest.toml` overrides)

## Testing & Pre-Commit Checklist

- [ ] `make quick-check` passes (fmt + clippy + fast tests)
- [ ] New public APIs annotated with `#[openapi(...)]` and `#[derive(ToSchema)]`
- [ ] Snapshot tests updated: `cargo insta review` if API responses changed
- [ ] Config changes merged into `config/default.toml` with sensible defaults
- [ ] Database migrations tested: `make migrate-reset && make migrate` for integration tests
- [ ] Concurrency limits use `Config.*`, not hardcoded values
- [ ] External API calls wrapped with existing circuit breaker clients from `vulnera-core/infrastructure/api_clients`
- [ ] Service injection: all dependencies `Arc<dyn Trait + Send + Sync>` in `OrchestratorState`
- [ ] CLI output uses `ctx.output.*` methods (no direct `println!`)
- [ ] All SQLx queries use `sqlx::query!` or `sqlx::query_as!` for compile-time validation
- [ ] New repositories implement `I{Entity}Repository` trait abstraction
