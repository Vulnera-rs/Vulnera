//! Vulnera Core - Shared domain models, infrastructure, and utilities
//!
//! This crate provides the core functionality shared across all Vulnera modules:
//! - Domain models and value objects
//! - Infrastructure implementations (API clients, parsers, cache, repositories)
//! - Configuration and logging
//! - Application error types

pub mod application;
pub mod config;
pub mod domain;
pub mod infrastructure;
pub mod logging;

pub use config::Config;
pub use logging::init_tracing;

