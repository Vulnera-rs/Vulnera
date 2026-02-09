//! Vulnera SAST - Static Application Security Testing module
//!
//! This crate provides static code analysis capabilities to detect security vulnerabilities
//! in source code. It supports multiple programming languages (Python, JavaScript, Rust)
//! and uses configurable rule sets to identify potential security issues.
//!
//! ## Features
//!
//! - Configurable rule repository (TOML/JSON file loading)
//! - Default rule set for common vulnerabilities
//! - Automatic confidence calculation based on pattern specificity
//! - File counting and comprehensive logging
//! - Configurable scanning depth and exclude patterns
//!
//! ## Usage
//!
//! ```rust
//! use vulnera_sast::SastModule;
//! use vulnera_core::config::SastConfig;
//!
//! let module = SastModule::with_config(&SastConfig::default());
//! ```
//!
//! See the [README.md](../README.md) for more detailed documentation.

pub mod application;
pub mod domain;
pub mod infrastructure;
pub mod module;

pub use module::*;

// Re-export key types for composition root wiring
pub use application::use_cases::{AnalysisConfig, ScanError, ScanProjectUseCase, ScanResult};
pub use infrastructure::ast_cache::{AstCacheService, DragonflyAstCache};
