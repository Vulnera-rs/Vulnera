//! Adapter that wraps vulnera-advisor's PackageRegistry to implement PackageRegistryClient
//!
//! This adapter bridges the gap between vulnera-advisor's `VersionRegistry` trait
//! and our domain's `PackageRegistryClient` trait, allowing us to leverage the
//! vulnera-advisor crate's unified registry implementation.

use async_trait::async_trait;
use tracing::debug;
use vulnera_advisor::{PackageRegistry, VersionRegistry};

use crate::domain::vulnerability::value_objects::{Ecosystem, Version};

use super::{PackageRegistryClient, RegistryError, VersionInfo};

/// Adapter that wraps vulnera-advisor's `PackageRegistry` to implement `PackageRegistryClient`.
///
/// This allows the rest of the codebase to use a single, well-maintained implementation
/// for fetching package versions across all supported ecosystems (npm, PyPI, Maven, etc.)
pub struct VulneraRegistryAdapter {
    registry: PackageRegistry,
}

impl VulneraRegistryAdapter {
    /// Create a new adapter with default configuration.
    pub fn new() -> Self {
        Self {
            registry: PackageRegistry::new(),
        }
    }

    /// Convert our domain Ecosystem enum to the string format expected .
    fn ecosystem_to_string(ecosystem: &Ecosystem) -> &'static str {
        match ecosystem {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "pypi",
            Ecosystem::Maven => "maven",
            Ecosystem::Cargo => "cargo",
            Ecosystem::Go => "go",
            Ecosystem::Packagist => "composer",
            Ecosystem::RubyGems => "rubygems",
            Ecosystem::NuGet => "nuget",
        }
    }
}

impl Default for VulneraRegistryAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PackageRegistryClient for VulneraRegistryAdapter {
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<VersionInfo>, RegistryError> {
        let ecosystem_str = Self::ecosystem_to_string(&ecosystem);

        debug!(
            "Fetching versions via vulnera-advisor for {} in {}",
            name, ecosystem_str
        );

        let version_strings = self
            .registry
            .get_versions(ecosystem_str, name)
            .await
            .map_err(|e| {
                let message = e.to_string();
                if message.contains("HTTP 404") || message.contains("not found") {
                    RegistryError::NotFound
                } else if message.contains("rate limit") || message.contains("429") {
                    RegistryError::RateLimited
                } else if message.contains("Unsupported ecosystem") {
                    RegistryError::UnsupportedEcosystem(ecosystem.clone())
                } else {
                    RegistryError::Http {
                        message,
                        status: None,
                    }
                }
            })?;

        // Convert version strings to VersionInfo with lenient parsing
        let mut versions: Vec<VersionInfo> = version_strings
            .into_iter()
            .filter_map(|v| {
                parse_version_lenient(&v)
                    .or_else(|| Version::parse(&v).ok())
                    .map(|version| VersionInfo::new(version, false, None))
            })
            .collect();

        // Sort by version ascending
        versions.sort_by(|a, b| a.version.cmp(&b.version));

        debug!(
            "Fetched {} versions for {} in {}",
            versions.len(),
            name,
            ecosystem_str
        );

        Ok(versions)
    }
}

/// Internal: best-effort version parsing with lenient handling for non-standard versions.
///
/// Handles cases like:
/// - 4-segment versions (4.2.11.1 -> 4.2.11)
/// - Leading 'v' prefix (v1.0.0 -> 1.0.0)
fn parse_version_lenient(s: &str) -> Option<Version> {
    // Try direct parse first
    if let Ok(v) = Version::parse(s) {
        return Some(v);
    }

    // Strip leading 'v' if present
    let s = s.strip_prefix('v').unwrap_or(s);
    if let Ok(v) = Version::parse(s) {
        return Some(v);
    }

    // Handle 4-segment versions: 4.2.11.1 -> 4.2.11
    let parts: Vec<&str> = s.split('-').collect();
    let core = parts[0];
    let pre = if parts.len() > 1 {
        Some(parts[1])
    } else {
        None
    };

    let nums: Vec<&str> = core.split('.').collect();
    if nums.len() > 3 {
        let mut base = format!("{}.{}.{}", nums[0], nums[1], nums[2]);
        if let Some(preid) = pre {
            if !preid.is_empty() {
                base = format!("{}-{}", base, preid);
            }
        }
        Version::parse(&base).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecosystem_to_string() {
        assert_eq!(
            VulneraRegistryAdapter::ecosystem_to_string(&Ecosystem::Npm),
            "npm"
        );
        assert_eq!(
            VulneraRegistryAdapter::ecosystem_to_string(&Ecosystem::PyPI),
            "pypi"
        );
        assert_eq!(
            VulneraRegistryAdapter::ecosystem_to_string(&Ecosystem::Maven),
            "maven"
        );
        assert_eq!(
            VulneraRegistryAdapter::ecosystem_to_string(&Ecosystem::Cargo),
            "cargo"
        );
        assert_eq!(
            VulneraRegistryAdapter::ecosystem_to_string(&Ecosystem::Go),
            "go"
        );
        assert_eq!(
            VulneraRegistryAdapter::ecosystem_to_string(&Ecosystem::Packagist),
            "composer"
        );
        assert_eq!(
            VulneraRegistryAdapter::ecosystem_to_string(&Ecosystem::RubyGems),
            "rubygems"
        );
        assert_eq!(
            VulneraRegistryAdapter::ecosystem_to_string(&Ecosystem::NuGet),
            "nuget"
        );
    }

    #[test]
    fn test_parse_version_lenient() {
        // Standard semver
        assert!(parse_version_lenient("1.0.0").is_some());

        // With 'v' prefix
        assert!(parse_version_lenient("v1.0.0").is_some());

        // 4-segment version
        let v = parse_version_lenient("4.2.11.1");
        assert!(v.is_some());
        assert_eq!(v.unwrap().to_string(), "4.2.11");

        // Prerelease
        assert!(parse_version_lenient("1.0.0-alpha.1").is_some());

        // Invalid
        assert!(parse_version_lenient("not-a-version").is_none());
    }
}
