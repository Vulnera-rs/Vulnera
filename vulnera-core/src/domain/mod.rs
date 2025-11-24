//! Domain Layer - Core business logic and entities
//!
//! This module contains the core domain entities, value objects, and domain services
//! that represent the business logic of vulnerability analysis.

pub mod auth;
pub mod module;
pub mod vulnerability;

// Re-export common types from both modules
#[allow(ambiguous_glob_reexports)]
pub use auth::*;
#[allow(ambiguous_glob_reexports)]
pub use module::*;
#[allow(ambiguous_glob_reexports)]
pub use vulnerability::*;
