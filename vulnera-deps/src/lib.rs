//! Vulnera Dependency Analyzer - Multi-ecosystem vulnerability scanning
//!
//! This crate provides dependency vulnerability analysis across multiple package ecosystems,
//! aggregating vulnerability data from OSV, NVD, and GitHub Security Advisories.
//!
//! # Supported Ecosystems
//!
//! | Ecosystem | Files |
//! |-----------|-------|
//! | npm | `package.json`, `package-lock.json`, `yarn.lock` |
//! | PyPI | `requirements.txt`, `Pipfile`, `pyproject.toml` |
//! | Maven | `pom.xml`, `build.gradle` |
//! | Cargo | `Cargo.toml`, `Cargo.lock` |
//! | Go | `go.mod`, `go.sum` |
//! | Composer | `composer.json`, `composer.lock` |
//! | RubyGems | `Gemfile`, `Gemfile.lock` |
//! | NuGet | `*.csproj`, `packages.config` |
//!
//! # Features
//!
//! - **Concurrent Processing** — Parallel package analysis with configurable limits
//! - **Version Resolution** — Registry integration for accurate version lookup
//! - **Safe Recommendations** — Upgrade suggestions with impact classification
//! - **CVE Aggregation** — Combined data from multiple vulnerability sources
//!
//! # Usage
//!
//! ```rust,ignore
//! use vulnera_deps::DependencyModule;
//! use vulnera_core::config::DependencyConfig;
//!
//! let module = DependencyModule::new(config, osv_client, nvd_client, ghsa_client);
//! let results = module.analyze(input).await?;
//! ```
//!
//! # Architecture
//!
//! ```text
//! vulnera-deps/
//! ├── domain/         # Package, Vulnerability entities
//! ├── application/    # Analysis use cases
//! ├── services/       # Repository analysis service
//! ├── types/          # Version resolution traits
//! └── module.rs       # AnalysisModule implementation
//! ```

pub mod application;
pub mod domain;
pub mod module;
pub mod services;
pub mod types;
pub mod use_cases;

pub use application::*;
pub use domain::*;
pub use module::*;
pub use services::*;
pub use types::*;
pub use use_cases::*;
