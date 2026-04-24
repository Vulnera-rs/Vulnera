//! Organization domain module
//!
//! Contains domain entities, value objects, errors, and repository traits
//! for multi-tenant organization management and team collaboration.

pub mod entities;
pub mod errors;
pub mod repositories;
pub mod value_objects;

pub use entities::*;
pub use errors::*;
pub use repositories::*;
pub use value_objects::*;
