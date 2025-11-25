# Vulnera Copilot Instructions

## Architecture Overview

Vulnera is a multi-module vulnerability analysis platform using Rust 2024 edition with workspace crates:

```
vulnera-rust (binary) → vulnera-orchestrator → vulnera-{deps,sast,secrets,api} → vulnera-core
```

- **`src/app.rs`** is the single composition root—all infrastructure (PgPool, DragonflyCache, API clients, module registry) is instantiated here and injected via `OrchestratorState`. Add new services here, not in crate internals.
- **Domain-Driven layering**: each crate follows `domain/` → `application/` → `infrastructure/` → `presentation/`. Side effects (DB, HTTP, cache) belong in `infrastructure/`; keep `domain/` pure.
- **Module system**: implement `AnalysisModule` trait (`vulnera-core/src/domain/module/traits.rs`), register in `ModuleRegistry` (`src/app.rs`). The orchestrator auto-selects modules via `RuleBasedModuleSelector`.

## Key Files to Know

| Purpose                       | Location                                            |
| ----------------------------- | --------------------------------------------------- |
| Service composition & DI      | `src/app.rs`                                        |
| HTTP routes + OpenAPI schemas | `vulnera-orchestrator/src/presentation/routes.rs`   |
| Middleware stack              | `vulnera-orchestrator/src/presentation/middleware/` |
| Config struct + validation    | `vulnera-core/src/config/mod.rs`                    |
| Module trait definition       | `vulnera-core/src/domain/module/traits.rs`          |
| Example module impl           | `vulnera-deps/src/module.rs`                        |
| API response DTOs             | `vulnera-orchestrator/src/presentation/models.rs`   |

## Configuration & Environment

- Strongly-typed config in `vulnera-core/src/config`; defaults in `config/default.toml`, env overrides use `VULNERA__` prefix with `__` separators (e.g., `VULNERA__AUTH__JWT_SECRET`).
- **Required env vars**: `DATABASE_URL` (Postgres), `VULNERA__AUTH__JWT_SECRET` (≥32 chars for production).
- Dragonfly/Redis is the only cache backend (`Config.cache.dragonfly_url`); don't introduce alternatives.
- SQLx needs `DATABASE_URL` at compile time for query validation; run `scripts/prepare-sqlx.sh` if offline.

## Developer Workflow

```bash
# Quick iteration (from scripts/build_workflow/)
make quick-check          # fmt + clippy + fast tests
make test-comprehensive   # full suite with coverage

# Database
export DATABASE_URL='postgresql://user:pass@localhost/vulnera'
make migrate              # run migrations
make migrate-info         # check status

# Run server
cargo run                 # loads .env via dotenvy
```

- Tests: `cargo nextest run --workspace` (see `nextest.toml` for retries). Snapshot tests in `vulnera-orchestrator/tests/snapshots/` use `insta`—run `cargo insta review` after API changes.
- Property tests: `vulnera-core/tests/proptest_*.rs`, data-driven: `vulnera-sast/tests/datatest_*.rs`.

## Adding Features

### New Analysis Module

1. Create module struct implementing `AnalysisModule` trait (see `vulnera-deps/src/module.rs`)
2. Register in `src/app.rs` via `module_registry.register(Arc::new(YourModule::new(...)))`
3. Selector rules pick modules based on `ModuleType` and source detection

### New API Endpoint

1. Add handler in `vulnera-orchestrator/src/presentation/controllers/`
2. Register route in `routes.rs` under `api_routes`
3. Add to `#[openapi(paths(...))]` in `ApiDoc` struct
4. Add request/response types to `models.rs` with `#[derive(ToSchema)]`

### New Config Section

1. Add struct in `vulnera-core/src/config/mod.rs` with `#[serde(default)]`
2. Add to `Config` struct, implement `Default`, add to `Validate` impl
3. Add defaults in `config/default.toml`

## Patterns to Follow

- **Services**: `Arc<dyn Trait + Send + Sync>` for all `OrchestratorState` fields
- **Concurrency**: use `Config.analysis.*` limits (e.g., `max_concurrent_packages`), not hardcoded values
- **Auth extraction**: use `OptionalApiKeyAuth`/`ApiKeyAuth` extractors, not manual header parsing
- **External APIs**: reuse clients from `vulnera-core/infrastructure/api_clients` with built-in circuit breakers
- **DTOs**: reuse types from `models.rs`; keep OpenAPI schemas (`utoipa`) in sync

## Testing Checklist

- [ ] `make quick-check` passes
- [ ] New public APIs have OpenAPI annotations
- [ ] Snapshot tests updated if API shape changed (`cargo insta review`)
- [ ] Config changes reflected in `config/default.toml`
- [ ] Migrations tested: `make migrate-reset` → `make migrate`
