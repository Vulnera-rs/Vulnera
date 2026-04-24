# vulnera-core

Core domain models, shared traits, and infrastructure abstractions for the Vulnera security analysis platform.

## Purpose

This crate provides the foundational layer used by all other Vulnera modules:

- **Domain models** - Entities, value objects, and domain events
- **Shared traits** - `AnalysisModule`, `IRepository`, `ICache`, `IAuthenticator`
- **Configuration** - Strongly-typed config with 17 sections
- **Infrastructure abstractions** - Database, cache, HTTP client interfaces

## Key Components

| Module | Purpose |
|--------|---------|
| `domain/` | Pure types with zero side effects |
| `application/` | Shared use cases and services |
| `infrastructure/` | Concrete implementations (SQLx, Dragonfly, etc.) |
| `config/` | Configuration structs and validation |

## Usage

This crate is not typically used directly by end users. It's a dependency of all other Vulnera crates.

```toml
[dependencies]
vulnera-core = { path = "../vulnera-core" }
```

## License

AGPL-3.0-or-later. See [LICENSE](../LICENSE) for details.
