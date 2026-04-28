//! Vulnera Infrastructure - Infrastructure layer
//!
//! Provides configuration, caching, database connectivity, and logging
//! for the open-source Vulnera vulnerability analysis platform.

pub mod cache;
pub mod config;
pub mod database;
pub mod logging;

// Re-exports for the composition root
pub use config::Config;
pub use logging::init_tracing;
