//! Vulnera API Security - API Security Scanning module
//!
//! This crate provides API security scanning capabilities for OpenAPI/Swagger specifications,
//! detecting common security vulnerabilities in API designs.

pub mod application;
pub mod domain;
pub mod infrastructure;
pub mod module;

pub use module::*;


