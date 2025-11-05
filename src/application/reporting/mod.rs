//! Reporting module for vulnerability analysis reports
//!
//! This module provides services for generating and formatting vulnerability analysis reports
//! in various output formats (JSON, HTML, text).

pub mod formats;
pub mod models;
pub mod service;

pub use models::*;
pub use service::*;

