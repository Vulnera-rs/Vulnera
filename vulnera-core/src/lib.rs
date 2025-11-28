//! Vulnera Core - Foundation crate for the Vulnera security platform
//!
//! This crate provides shared functionality used across all Vulnera modules:
//!
//! # Modules
//!
//! - [`config`] — Strongly-typed configuration with TOML and environment variable support
//! - [`domain`] — Core domain models, entities, and value objects
//! - [`application`] — Shared application services and error types
//! - [`infrastructure`] — API clients, parsers, cache, and repository implementations
//! - [`logging`] — Structured logging with tracing
//!
//! # Architecture
//!
//! The crate follows Domain-Driven Design principles:
//!
//! ```text
//! vulnera-core/
//! ├── domain/           # Pure business logic
//! │   ├── entities/     # Core domain objects
//! │   ├── value_objects/# Immutable values
//! │   └── traits/       # Domain interfaces
//! ├── application/      # Use cases and services
//! ├── infrastructure/   # External integrations
//! │   ├── api_clients/  # OSV, NVD, GHSA clients
//! │   ├── parsers/      # Dependency file parsers
//! │   ├── cache/        # Dragonfly/Redis cache
//! │   └── repositories/ # PostgreSQL data access
//! └── config/           # Configuration management
//! ```
//!
//! # Configuration
//!
//! Load configuration from files and environment:
//!
//! ```rust,ignore
//! use vulnera_core::Config;
//!
//! let config = Config::load()?;
//! ```
//!
//! Environment variables use the `VULNERA__` prefix with double underscore separators:
//!
//! ```bash
//! VULNERA__SERVER__PORT=3000
//! VULNERA__CACHE__TTL_HOURS=24
//! ```
//!
//! # Logging
//!
//! Initialize structured logging:
//!
//! ```rust,ignore
//! use vulnera_core::init_tracing;
//!
//! init_tracing("info")?;
//! ```

pub mod application;
pub mod config;
pub mod domain;
pub mod infrastructure;
pub mod logging;

pub use config::Config;
pub use logging::init_tracing;
