//! Vulnera Contract - Pure analysis contract crate
//!
//! This crate defines the shared interface contract between the Vulnera
//! orchestrator and all analysis modules (SAST, secrets, API security,
//! dependency scanning, and future submodules).
//!
//! # What lives here
//!
//! - [`AnalysisModule`] trait - the core plugin contract that every module implements
//! - [`Finding`] and related types - the unified output data model
//! - [`ModuleConfig`]/[`ModuleResult`] - input/output envelopes for module execution
//! - [`ModuleType`] - module identity (Community/Enterprise tier)
//! - [`Project`] - input project metadata for module configuration
//!
//! # What does NOT live here
//!
//! - Config loading/validation → `vulnera-infrastructure`
//! - Auth, organizations, analytics → `vulnera-enterprise` (proprietary)
//! - Cache, rate limiter, DB repos → `vulnera-infrastructure`
//! - Ecosystem/Version/Package types → each module's own domain
//!
//! # Architecture
//!
//! ```text
//! vulnera-contract/
//! └── domain/
//!     ├── module/    # AnalysisModule trait + Finding types + Module types
//!     └── project/   # Project metadata for prepare_config
//! ```
//!
//! # Stability
//!
//! All public enums are `#[non_exhaustive]`. Adding variants or optional
//! fields (with `#[serde(default)]`) is a semver-minor bump. Removing or
//! changing existing variants is a semver-major bump.

pub mod domain;

pub use domain::*;
