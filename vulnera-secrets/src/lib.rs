//! Vulnera Secrets - Secret Detection module
//!
//! This crate provides secret detection capabilities to identify exposed secrets,
//! credentials, API keys, and other sensitive information in source code.
//!
//! ## Features
//!
//! - Regex-based detection for known secret patterns (AWS, API keys, tokens, etc.)
//! - Entropy-based detection for high-entropy strings (Base64, hex)
//! - Configurable rule repository (TOML/JSON file loading)
//! - Default rule set for common secret types
//! - Automatic confidence calculation based on pattern specificity and entropy
//! - File counting and comprehensive logging
//! - Configurable scanning depth and exclude patterns
//!
//! ## Usage
//!
//! ```rust
//! use vulnera_secrets::SecretDetectionModule;
//! use vulnera_core::config::SecretDetectionConfig;
//!
//! let module = SecretDetectionModule::with_config(&SecretDetectionConfig::default());
//! ```
//!

pub mod application;
pub mod domain;
pub mod infrastructure;
pub mod module;

pub use module::*;


