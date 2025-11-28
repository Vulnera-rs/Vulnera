//! Vulnera API Security - OpenAPI Specification Security Analysis
//!
//! This crate analyzes OpenAPI 3.x specifications to identify security vulnerabilities
//! and misconfigurations in API designs before deployment.
//!
//! # Analysis Categories
//!
//! - **Authentication** — Missing/weak auth, JWT issues, insecure token storage
//! - **Authorization** — Missing checks, overly permissive access, RBAC gaps
//! - **Input Validation** — Missing validation, injection risks, file upload limits
//! - **Data Exposure** — Sensitive data in URLs, missing encryption, PII handling
//! - **Security Headers** — Missing headers, insecure CORS, missing CSP
//! - **OAuth/OIDC** — Insecure flows, token validation, redirect URI issues
//!
//! # Features
//!
//! - **OpenAPI 3.x Support** — Full support for OpenAPI 3.0 and 3.1 specifications
//! - **Configurable Analyzers** — Enable/disable specific security checks
//! - **Severity Overrides** — Customize severity levels per vulnerability type
//! - **Path Exclusion** — Skip specific API paths from analysis
//! - **Strict Mode** — Aggressive checks for high-security environments
//!
//! # Usage
//!
//! ```rust,ignore
//! use vulnera_api::ApiSecurityModule;
//! use vulnera_core::config::ApiSecurityConfig;
//!
//! let module = ApiSecurityModule::with_config(&ApiSecurityConfig::default());
//! let findings = module.analyze(openapi_spec).await?;
//! ```
//!
//! # Architecture
//!
//! ```text
//! vulnera-api/
//! ├── domain/           # Finding entities, severity types
//! ├── application/      # Analysis use cases
//! ├── infrastructure/   # OpenAPI parsing, analyzers
//! └── module.rs         # AnalysisModule implementation
//! ```

pub mod application;
pub mod domain;
pub mod infrastructure;
pub mod module;

pub use module::*;
