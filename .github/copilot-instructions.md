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

# Database
export DATABASE_URL='postgresql://user:pass@localhost/vulnera'
make migrate                 # Apply pending migrations
make migrate-info            # Check migration status

# Server
cargo run                    # Load .env via dotenvy

# Testing specifics
cargo nextest run --workspace              # Run tests (respects nextest.toml retries)
cargo insta review                         # Review snapshot test changes after API updates
cargo test --test proptest_*               # Property-based tests
cargo test --test datatest_*               # Data-driven tests
```

**Test organization**: Unit tests live in crate `tests/` dirs. Snapshot tests in `vulnera-orchestrator/tests/snapshots/` use `insta`—must review after any API response shape change.

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

### New Config Section

1. Add struct in `vulnera-core/src/config/mod.rs` with `#[serde(default)]`
2. Add field to root `Config` struct; implement `Default` trait
3. Add to `Validate` impl if validation rules needed
4. Add section to `config/default.toml` with sensible defaults
5. Override via `VULNERA__SECTION__KEY` env vars

## Code Patterns (Project-Specific)

- **Service injection**: All fields in `OrchestratorState` must be `Arc<dyn Trait + Send + Sync>`; use dependency injection, not singletons
- **Concurrency**: Reference `Config.analysis.*` limits (e.g., `max_concurrent_packages`), never hardcode thread pools or max requests
- **Async/await**: Use `tokio` primitives; wrap long-running work in `tokio::spawn` for non-blocking
- **Error handling**: Domain errors in `domain/`, infrastructure errors wrapped in use cases; OpenAPI errors use `ErrorResponse` DTO
- **DB queries**: All SQLx queries in `infrastructure/` with compile-time validation via `sqlx::query!` macros
- **External APIs**: Reuse circuit-breaker-wrapped clients from `vulnera-core/infrastructure/api_clients`; leverage existing retry/timeout config
- **Cache**: Use `CacheServiceImpl` wrapper (never raw Redis/Dragonfly calls); configure TTL via `Config.cache.ttl_hours`

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
- [ ] New public APIs annotated with `#[openapi(...)]`
- [ ] Snapshot tests updated: `cargo insta review` if API responses changed
- [ ] Config changes merged into `config/default.toml` with defaults
- [ ] Migrations tested: `make migrate-reset && make migrate`
- [ ] Concurrency limits use `Config.*`, not hardcoded values
- [ ] External API calls wrapped with existing circuit breaker clients
