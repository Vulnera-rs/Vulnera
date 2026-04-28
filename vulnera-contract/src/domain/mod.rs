//! Domain Layer - Pure analysis contract types
//!
//! This module defines the shared types that form the interface contract
//! between the orchestrator and all analysis modules.

pub mod module;
pub mod project;

pub use module::*;
pub use project::*;
