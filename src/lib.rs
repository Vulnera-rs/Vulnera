//! Vulnera Rust - Main application library
//!
//! This is the main binary crate that wires together all modules

mod app;

pub use app::{AppHandle, create_app};
pub use vulnera_core::{Config, init_tracing};
pub use vulnera_orchestrator::presentation::controllers::OrchestratorState;

// Re-export for convenience
pub use vulnera_core;
pub use vulnera_deps;
pub use vulnera_orchestrator;
pub use vulnera_sast;
