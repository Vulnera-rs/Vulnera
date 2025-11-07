//! Domain Layer - Core business logic and entities
//!
//! This module contains the core domain entities, value objects, and domain services
//! that represent the business logic of vulnerability analysis.

pub mod auth;
pub mod vulnerability;

// Re-export common types from both modules
// Note: Both auth and vulnerability modules have sub-modules with similar names (entities, errors, repositories, value_objects)
// Use explicit paths like `domain::auth::entities::User` or `domain::vulnerability::entities::Package` to avoid ambiguity
#[allow(ambiguous_glob_reexports)]
pub use auth::*;
#[allow(ambiguous_glob_reexports)]
pub use vulnerability::*;
