//! Orchestrator domain layer

pub mod entities;
pub mod services;
pub mod value_objects;

pub use entities::*;
pub use services::*;
pub use value_objects::*;

// Re-export module types from core for convenience
pub use vulnera_core::domain::module::{
    AnalysisModule, Finding, ModuleConfig, ModuleExecutionError, ModuleResult, ModuleType,
};
