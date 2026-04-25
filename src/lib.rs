//! Vulnera Rust - Main application library
//!
//! This is the main binary crate that runs the HTTP API server.
//! The composition root lives in `app.rs`.

mod app;
pub use app::{AppHandle, create_app};
pub use vulnera_infrastructure::{Config, init_tracing};
pub use vulnera_orchestrator::presentation::controllers::OrchestratorState;

pub use vulnera_contract;
pub use vulnera_orchestrator;
