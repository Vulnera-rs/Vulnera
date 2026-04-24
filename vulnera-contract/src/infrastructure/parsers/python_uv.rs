//! UV (Python) ecosystem parsers
//!
//! UV is a fast Python package manager that uses pyproject.toml and uv.lock files.
//! This module provides parsers for UV's lockfile format.

use super::traits::{PackageFileParser, ParseResult};
use crate::application::errors::ParseError;
use crate::domain::vulnerability::{
    entities::{Dependency, Package},
    value_objects::{Ecosystem, Version},
};
use async_trait::async_trait;
use std::collections::HashMap;

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

    /// Extract packages and dependencies from UV lockfile
    fn extract_lock_data(&self, toml_value: &toml::Value) -> Result<ParseResult, ParseError> {
        let mut packages = Vec::new();
        let mut dependencies = Vec::new();
        let mut seen_packages = std::collections::HashSet::new();
        let mut pending_dependencies: Vec<(Package, String, String)> = Vec::new();

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

                    packages.push(package.clone());

                    // Collect dependencies for second-pass target resolution
                    if let Some(deps) = package_table.get("dependencies").and_then(|d| d.as_array())
                    {
                        for dep_val in deps {
                            if let Some(dep_str) = dep_val.as_str() {
                                // dep_str is like "certifi>=2021" or "charset-normalizer<4,>=2"
                                // We need to split name and requirement
                                let (dep_name, dep_req) = self.parse_dependency_string(dep_str);
                                pending_dependencies.push((
                                    package.clone(),
                                    dep_name.to_string(),
                                    dep_req.to_string(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        let mut package_by_name: HashMap<String, Package> = HashMap::new();
        for package in &packages {
            package_by_name
                .entry(package.name.clone())
                .and_modify(|current| {
                    if package.version > current.version {
                        *current = package.clone();
                    }
                })
                .or_insert_with(|| package.clone());
        }

        for (from, dep_name, dep_req) in pending_dependencies {
            if let Some(to) = package_by_name.get(&dep_name) {
                dependencies.push(Dependency::new(from, to.clone(), dep_req, false));
            }
        }

        Ok(ParseResult {
            packages,
            dependencies,
        })
    }

    /// Parse dependency string into (name, requirement)
    fn parse_dependency_string<'a>(&self, dep_str: &'a str) -> (&'a str, &'a str) {
        // Find the first character that indicates a version requirement
        let split_chars = ['<', '>', '=', '!', '~'];
        if let Some(idx) = dep_str.find(&split_chars[..]) {
            (&dep_str[..idx], &dep_str[idx..])
        } else {
            // No requirement specified, or it's just a name
            (dep_str, "*")
        }
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

    async fn parse_file(&self, content: &str) -> Result<ParseResult, ParseError> {
        let toml_value: toml::Value = toml::from_str(content)?;
        self.extract_lock_data(&toml_value)
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

        let result = parser.parse_file(content).await.unwrap();
        assert_eq!(result.packages.len(), 3);

        let requests_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "requests")
            .unwrap();
        assert_eq!(requests_pkg.version, Version::parse("2.31.0").unwrap());
        assert_eq!(requests_pkg.ecosystem, Ecosystem::PyPI);

        let certifi_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "certifi")
            .unwrap();
        assert_eq!(certifi_pkg.version, Version::parse("2023.7.22").unwrap());

        // Check dependencies
        assert_eq!(result.dependencies.len(), 2);
        let dep1 = result
            .dependencies
            .iter()
            .find(|d| d.to.name == "certifi")
            .unwrap();
        assert_eq!(dep1.from.name, "requests");
        assert_eq!(dep1.requirement, ">=2021");
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

        let result = parser.parse_file(content).await.unwrap();
        assert_eq!(result.packages.len(), 1);

        let requests_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "requests")
            .unwrap();
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

        let result = parser.parse_file(content).await.unwrap();
        // Should deduplicate identical packages
        assert_eq!(result.packages.len(), 1);
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
