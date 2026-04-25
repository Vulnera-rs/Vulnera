//! Vulnera Contract - Pure analysis contract crate
//!
//! This crate defines the shared interface contract between the Vulnera
//! orchestrator and all analysis modules.
//!
//! # Architecture
//!
//! ```text
//! vulnera-contract/
//! └── domain/
//!     ├── module/    # AnalysisModule trait + Finding types
//!     └── project/   # Project metadata
//! └── infrastructure/
//!     └── cache/     # CacheBackend trait (only trait, no implementations)
//! ```

pub mod domain;
pub mod infrastructure;

pub use domain::*;
pub use infrastructure::*;
