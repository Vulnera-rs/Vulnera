# Contributing to Vulnera

Thank you for your interest in contributing to Vulnera!

Vulnera is developed by **Vulnera Industries**, a for-profit company. We welcome contributions from the community and are grateful for every pull request, bug report, and feature suggestion.

## Contributor License Agreement

By submitting a contribution (pull request, patch, or any other form), you agree to the terms of our [Contributor License Agreement](CLA.md). In summary:

- **You** (the contributor) are entering into an agreement with Vulnera Industries.
- You're giving Vulnera Industries permission to use and share your contributions (like original works or modifications).
- You assure us that the contributions are truly your own and you have the legal right to share them.
- You're not required to support your contributions, but you're welcome to if you wish.
- If you ever notice an error or change in the details you've given us, you agree to let us know.

## Sponsorship

If you'd like to financially support the project, you can do so via [GitHub Sponsors](https://github.com/sponsors/Vulnera-rs). Sponsorships go directly to Vulnera Industries and are used as general company revenue. There are no perks or entitlements associated with sponsorship.

---

## Getting Started

1. Fork the repo and create a feature branch from `main`.
2. Install Rust stable (MSRV 1.91+) and PostgreSQL 12+.
3. Set up the development database:

   ```bash
   export DATABASE_URL='postgresql://user:pass@localhost:5432/vulnera'
   sqlx migrate run --source migrations
   ```

4. Run the full CI check:

   ```bash
   cargo clippy --workspace -- -D warnings
   cargo fmt --all -- --check
   cargo nextest run --workspace
   ```

5. Run repository guardrails locally before opening a PR:

   ```bash
   cargo clippy --no-deps -p vulnera-orchestrator -p vulnera-sandbox -p vulnera-llm -p vulnera-advisor -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
   bash .github/scripts/sql_query_safety_audit.sh
   ```

## Development Workflow

- **Format and lint** before every commit: `cargo fmt --all && cargo clippy --workspace`
- **Add tests** for all new features and bug fixes. Target **80%+ test coverage**.
- **Keep changes focused** — one logical change per PR. Open draft PRs early for feedback.
- **Run the full test suite** before marking a PR as ready: `cargo nextest run --workspace`

## Architecture Guidelines

Vulnera follows Domain-Driven Design (DDD) with strict layering:

| Layer | Purpose | Side Effects |
| --- | --- | --- |
| `domain/` | Pure types, entities, value objects, traits | None |
| `application/` | Use cases orchestrating domain logic | Minimal |
| `infrastructure/` | DB queries, HTTP clients, cache | Yes |
| `presentation/` | Axum controllers, DTOs, OpenAPI | Yes |

- **Never** instantiate services inside crate internals — wire everything in `src/app.rs` (composition root).
- **Traits** are prefixed with `I` (e.g., `IUserRepository`).
- **Error handling:** `thiserror` for libraries, `anyhow` for application wiring. Never `.unwrap()` in production code.

## Module Tiers

Vulnera uses an open-core model:

- **Community modules** (open-source): Dependency Analysis, SAST, Secrets Detection, API Security
- **Enterprise modules** (commercial license): LLM Enrichment, Advanced DAST, IaC Security, CSPM, Fuzz Testing

If you're contributing a new analysis module, it will be part of the **community tier** by default. See [docs/EXTENSION_GUIDE.md](docs/EXTENSION_GUIDE.md) for the module development guide.

## Testing

```bash
# Full workspace tests (preferred)
cargo nextest run --workspace

# Coverage report
cargo tarpaulin --workspace --out Html

# Snapshot testing (review changes)
cargo insta review

# Data-driven tests
cargo test --test datatest_*
```

- Use `#[serial]` for tests that hit the database.
- Use `insta` for API response snapshot assertions.
- Use `mockito` or `wiremock` for HTTP mocking.

## Commit & PR Guidelines

- **Conventional commits** are required: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `ci:`, `chore:`
- **Link related issues** in the PR description (e.g., `Closes #123`).
- **Update OpenAPI annotations** (`utoipa`) when API shapes change.
- **Update documentation** in `docs/` when behavior changes.
- **All CI checks must pass** before merge (clippy, fmt, tests, coverage).
- **Guardrails are enforced in CI**:
  - panic primitives in production code are blocked via clippy (`unwrap/expect/panic`)
  - non-macro SQLx query function forms are blocked in production paths

## Code of Conduct

This project adheres to the [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Security

If you discover a security vulnerability, **do not open a public issue**. Please follow the [Security Policy](SECURITY.md).
