//! Dependency analysis services
//!
//! This module contains application services that support dependency vulnerability analysis operations.

pub mod dependency_resolver;
pub mod popular_packages;
pub mod repository_analysis;
pub mod resolution_algorithms;
pub mod version_resolution;

pub use dependency_resolver::*;
pub use popular_packages::*;
pub use repository_analysis::*;
pub use resolution_algorithms::*;
pub use version_resolution::*;
