//! CLI Commands Module
//!
//! This module contains all CLI subcommand implementations.
//! Offline modules (SAST, Secrets, API) run locally via embedded analyzers.
//! Dependency analysis requires server connection.

pub mod analyze;
pub mod api;
pub mod auth;
pub mod config;
pub mod deps;
pub mod quota;
pub mod sast;
pub mod secrets;
