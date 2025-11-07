//! Dependency analysis services
//!
//! This module contains application services that support dependency vulnerability analysis operations.

pub mod popular_packages;
pub mod repository_analysis;
pub mod version_resolution;

pub use popular_packages::*;
pub use repository_analysis::*;
pub use version_resolution::*;
