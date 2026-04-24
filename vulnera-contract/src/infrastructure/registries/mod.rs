/*
 Infrastructure: Package Registry Clients

 This module defines the core abstractions and types to query package registries
 (npm, PyPI, Maven Central, crates.io, Go proxy, Packagist, RubyGems, NuGet, ...).

 The main implementation is `VulneraRegistryAdapter` which wraps the
 `vulnera-advisor` crate's `PackageRegistry` for unified registry access.

 - Domain:    Version/Ecosystem types live in crate::domain
 - Application: A VersionResolutionService will orchestrate calls to this trait
 - Infrastructure: VulneraRegistryAdapter implements the trait below
*/

pub mod batch_client;
pub mod vulnera_registry_adapter;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::vulnerability::value_objects::{Ecosystem, Version};

// Re-export the adapter as the primary registry client
pub use vulnera_registry_adapter::VulneraRegistryAdapter;

/// Information about a single published version in a package registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    /// Semantic version (normalized to our domain Version).
    pub version: Version,
    /// Whether this is a pre-release (alpha/beta/rc).
    pub is_prerelease: bool,
    /// Whether this version is yanked/withdrawn/unlisted (when the registry exposes this).
    pub yanked: bool,
    /// Publish timestamp if available from the registry.
    pub published_at: Option<DateTime<Utc>>,
}

impl VersionInfo {
    /// Helper to construct VersionInfo inferring prerelease flag from semver metadata.
    pub fn new(version: Version, yanked: bool, published_at: Option<DateTime<Utc>>) -> Self {
        // semver::Version has `pre` identifiers; non-empty means pre-release
        let is_prerelease = !version.0.pre.is_empty();
        Self {
            version,
            is_prerelease,
            yanked,
            published_at,
        }
    }
}

/// A dependency relationship as reported by a package registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryDependency {
    /// Name of the dependent package.
    pub name: String,
    /// Version requirement string (e.g., "^1.2.3", "~> 2.0").
    pub requirement: String,
    /// Whether this is a development dependency.
    pub is_dev: bool,
    /// Whether this is an optional dependency.
    pub is_optional: bool,
}

/// Detailed metadata for a specific package version from a registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryPackageMetadata {
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: Version,
    /// List of dependencies.
    pub dependencies: Vec<RegistryDependency>,
    /// Homepage or repository URL if available.
    pub project_url: Option<String>,
    /// License information if available.
    pub license: Option<String>,
}

/// Error type for registry operations.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// HTTP/network-level error (optional status code).
    #[error("registry HTTP error: {message}, status={status:?}")]
    Http {
        message: String,
        status: Option<u16>,
    },

    /// Registry rate-limited the request (consider retry/backoff).
    #[error("registry rate limited the request")]
    RateLimited,

    /// Package not found (or deleted).
    #[error("package not found")]
    NotFound,

    /// Parsing/conversion error (e.g., invalid version format).
    #[error("registry parse error: {0}")]
    Parse(String),

    /// This registry does not support the requested ecosystem.
    #[error("unsupported ecosystem: {0}")]
    UnsupportedEcosystem(Ecosystem),

    /// Any other error condition.
    #[error("registry error: {0}")]
    Other(String),
}

/// Trait for querying package registries for available versions.
/// - Implementations should:
///   - Normalize versions to domain `Version`
///   - Set `is_prerelease` based on semver pre identifiers
///   - Set `yanked`/`unlisted` where supported by the registry (default false if unknown)
///   - Respect rate limits and apply centralized resilience (retry/backoff)
#[async_trait]
pub trait PackageRegistryClient: Send + Sync {
    /// List available versions for a package in a given ecosystem.
    ///
    /// Requirements:
    /// - Return at least all published versions (yanked/unlisted MAY be filtered out by the impl).
    /// - Prefer ascending sort (callers can re-sort as needed).
    /// - Normalize formats to our domain `Version` using best-effort cleaning where ecosystems differ.
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<VersionInfo>, RegistryError>;

    /// Fetch detailed metadata including dependencies for a specific version.
    async fn fetch_metadata(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &Version,
    ) -> Result<RegistryPackageMetadata, RegistryError>;
}

/// Optional blanket helpers for implementations
pub mod helpers {
    use super::*;

    /// Infer `is_prerelease` directly from a domain `Version`.
    #[inline]
    pub fn is_prerelease(version: &Version) -> bool {
        !version.0.pre.is_empty()
    }

    /// Make a VersionInfo from a Version with sane defaults.
    #[inline]
    pub fn make_version_info(version: Version) -> VersionInfo {
        VersionInfo::new(version, false, None)
    }
}
