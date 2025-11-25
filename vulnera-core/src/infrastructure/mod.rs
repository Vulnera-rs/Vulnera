//! Infrastructure Layer - External concerns and implementations
//!
//! This module handles external systems like APIs, file systems, and databases.

pub mod api_clients;
pub mod auth;
pub mod cache;
pub mod parsers;
pub mod registries;
pub mod repositories;
pub mod repository_source;
pub mod resilience;
pub mod vulnerability_advisor;

// Re-export specific items to avoid ambiguous glob conflicts
pub use api_clients::traits::VulnerabilityApiClient;
pub use cache::*;
pub use parsers::ParserFactory;
pub use parsers::traits::PackageFileParser;
pub use repository_source::*;
pub use resilience::*;
pub use vulnerability_advisor::{VulneraAdvisorConfig, VulneraAdvisorRepository};
