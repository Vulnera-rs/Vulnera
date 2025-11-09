//! UV (Python) ecosystem parsers
//!
//! UV is a fast Python package manager that uses pyproject.toml and uv.lock files.
//! This module provides parsers for UV's lockfile format.

use super::traits::PackageFileParser;
use crate::application::errors::ParseError;
use crate::domain::vulnerability::{
    entities::Package,
    value_objects::{Ecosystem, Version},
};
use async_trait::async_trait;

/// Parser for uv.lock files
///
/// UV lockfiles are TOML-based and similar in structure to Cargo.lock.
/// They contain exact versions of all dependencies (direct and transitive).
pub struct UvLockParser;

impl Default for UvLockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl UvLockParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract packages from UV lockfile
    fn extract_lock_packages(&self, toml_value: &toml::Value) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();
        let mut seen_packages = std::collections::HashSet::new();

        // UV lockfiles have a [[package]] array
        if let Some(packages_array) = toml_value.get("package").and_then(|p| p.as_array()) {
            for package_info in packages_array {
                if let Some(package_table) = package_info.as_table() {
                    let name = package_table
                        .get("name")
                        .and_then(|n| n.as_str())
                        .ok_or_else(|| ParseError::MissingField {
                            field: "package name".to_string(),
                        })?;

                    let version_str = package_table
                        .get("version")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| ParseError::MissingField {
                            field: "package version".to_string(),
                        })?;

                    // Skip if we've already seen this package (deduplicate)
                    let package_key = format!("{}@{}", name, version_str);
                    if seen_packages.contains(&package_key) {
                        continue;
                    }
                    seen_packages.insert(package_key);

                    // Clean version string (remove 'v' prefix if present)
                    let clean_version = self.clean_uv_version(version_str)?;

                    let version =
                        Version::parse(&clean_version).map_err(|_| ParseError::Version {
                            version: version_str.to_string(),
                        })?;

                    let package = Package::new(name.to_string(), version, Ecosystem::PyPI)
                        .map_err(|e| ParseError::MissingField { field: e })?;

                    packages.push(package);
                }
            }
        }

        Ok(packages)
    }

    /// Clean UV version string
    fn clean_uv_version(&self, version_str: &str) -> Result<String, ParseError> {
        let version_str = version_str.trim();

        if version_str.is_empty() {
            return Ok("0.0.0".to_string());
        }

        // Remove 'v' prefix if present (UV sometimes includes it)
        let cleaned = if let Some(stripped) = version_str.strip_prefix('v') {
            stripped
        } else {
            version_str
        };

        // Handle pre-release versions and build metadata
        // UV versions are typically PEP 440 compliant, but we normalize to semver
        let cleaned = cleaned.trim();

        Ok(cleaned.to_string())
    }
}

#[async_trait]
impl PackageFileParser for UvLockParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "uv.lock"
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let toml_value: toml::Value = toml::from_str(content)?;
        self.extract_lock_packages(&toml_value)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPI
    }

    fn priority(&self) -> u8 {
        20 // High priority for lockfiles (exact versions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_uv_lock_parser() {
        let parser = UvLockParser::new();
        let content = r#"
version = 1

[[package]]
name = "requests"
version = "2.31.0"
source = { type = "registry", url = "https://pypi.org/simple" }
dependencies = [
    "certifi>=2021",
    "charset-normalizer<4,>=2",
]

[[package]]
name = "certifi"
version = "2023.7.22"
source = { type = "registry", url = "https://pypi.org/simple" }

[[package]]
name = "charset-normalizer"
version = "3.2.0"
source = { type = "registry", url = "https://pypi.org/simple" }
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        assert_eq!(packages.len(), 3);

        let requests_pkg = packages.iter().find(|p| p.name == "requests").unwrap();
        assert_eq!(requests_pkg.version, Version::parse("2.31.0").unwrap());
        assert_eq!(requests_pkg.ecosystem, Ecosystem::PyPI);

        let certifi_pkg = packages.iter().find(|p| p.name == "certifi").unwrap();
        assert_eq!(certifi_pkg.version, Version::parse("2023.7.22").unwrap());
    }

    #[tokio::test]
    async fn test_uv_lock_parser_with_v_prefix() {
        let parser = UvLockParser::new();
        let content = r#"
version = 1

[[package]]
name = "requests"
version = "v2.31.0"
source = { type = "registry", url = "https://pypi.org/simple" }
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        assert_eq!(packages.len(), 1);

        let requests_pkg = packages.iter().find(|p| p.name == "requests").unwrap();
        assert_eq!(requests_pkg.version, Version::parse("2.31.0").unwrap());
    }

    #[tokio::test]
    async fn test_uv_lock_parser_deduplication() {
        let parser = UvLockParser::new();
        let content = r#"
version = 1

[[package]]
name = "requests"
version = "2.31.0"
source = { type = "registry", url = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.31.0"
source = { type = "registry", url = "https://pypi.org/simple" }
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        // Should deduplicate identical packages
        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn test_clean_uv_version() {
        let parser = UvLockParser::new();

        assert_eq!(parser.clean_uv_version("2.31.0").unwrap(), "2.31.0");
        assert_eq!(parser.clean_uv_version("v2.31.0").unwrap(), "2.31.0");
        assert_eq!(parser.clean_uv_version("2023.7.22").unwrap(), "2023.7.22");
    }

    #[test]
    fn test_parser_supports_file() {
        let parser = UvLockParser::new();

        assert!(parser.supports_file("uv.lock"));
        assert!(!parser.supports_file("pyproject.toml"));
        assert!(!parser.supports_file("requirements.txt"));
    }
}
