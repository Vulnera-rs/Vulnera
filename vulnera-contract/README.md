# vulnera-contract

Pure analysis contract crate for the Vulnera platform.

## Purpose

This crate defines the **shared interface contract** between the Vulnera orchestrator and all analysis modules (SAST, secrets, API security, dependency scanning, and future submodules). It is the only dependency that modules need to implement the `AnalysisModule` trait.

- **Plugin contract** - `AnalysisModule` trait that every analysis module implements
- **Finding data model** - `Finding`, `FindingType`, `FindingSeverity`, `FindingConfidence`, `Location`
- **Module envelope** - `ModuleConfig` / `ModuleResult` / `ModuleExecutionError`
- **Module identity** - `ModuleType`, `ModuleTier` (Community / Enterprise)
- **Project metadata** - `Project`, `SourceType`, `ProjectMetadata`

## Architecture

```
vulnera-contract/
└── domain/
    ├── module/       # AnalysisModule trait + Finding types + Module types
    └── project/      # Project metadata for prepare_config
```

## Stability

All public enums are `#[non_exhaustive]`. Adding variants or optional fields
(with `#[serde(default)]`) is a semver-minor bump. Removing or changing
existing variants is a semver-major bump.

## Usage

```toml
[dependencies]
vulnera-contract = { path = "../vulnera-contract" }
```

## Build

```
cargo check -p vulnera-contract
```

## License

AGPL-3.0-or-later. See [LICENSE](../LICENSE) for details.
