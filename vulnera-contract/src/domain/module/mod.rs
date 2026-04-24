//! Analysis module plugin interface
//!
//! This module defines the plugin interface that all analysis modules must implement.
//! It provides a unified way for the orchestrator to interact with different analysis modules
//! (dependency analysis, SAST, etc.) without knowing their specific implementations.

pub mod entities;
pub mod traits;
pub mod value_objects;

pub use entities::*;
pub use traits::*;
pub use value_objects::*;
