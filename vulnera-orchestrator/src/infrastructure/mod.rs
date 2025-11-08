//! Orchestrator infrastructure layer

pub mod module_registry;
pub mod module_selector;
pub mod project_detection;

pub use module_registry::*;
pub use module_selector::*;
pub use project_detection::*;

