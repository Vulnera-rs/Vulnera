//! Rust ecosystem parsers

use super::traits::{PackageFileParser, ParseResult};
use crate::application::errors::ParseError;
use crate::domain::vulnerability::{
    entities::{Dependency, Package},
    value_objects::{Ecosystem, Version},
};
use async_trait::async_trait;

/// Parser for Cargo.toml files
pub struct CargoParser;

impl Default for CargoParser {
    fn default() -> Self {
        Self::new()
    }
}

impl CargoParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract dependencies from TOML section
    fn extract_dependencies(
        &self,
        toml_value: &toml::Value,
        section: &str,
        root_package: &Package,
    ) -> Result<ParseResult, ParseError> {
        let mut packages = Vec::new();
        let mut dependencies = Vec::new();

        if let Some(deps) = toml_value.get(section).and_then(|s| s.as_table()) {
            for (name, version_info) in deps {
                let version_str = match version_info {
                    toml::Value::String(v) => v.clone(),
                    toml::Value::Table(t) => {
                        // Handle complex dependency specifications
                        if let Some(version) = t.get("version").and_then(|v| v.as_str()) {
                            version.to_string()
                        } else if t.get("git").is_some() || t.get("path").is_some() {
                            // Skip git and path dependencies for now
                            continue;
                        } else {
                            "0.0.0".to_string()
                        }
                    }
                    _ => "0.0.0".to_string(),
                };

                // Clean version string
                let clean_version = self.clean_cargo_version(&version_str)?;

                let version = Version::parse(&clean_version).map_err(|_| ParseError::Version {
                    version: version_str.clone(),
                })?;

                let package = Package::new(name.clone(), version, Ecosystem::Cargo)
                    .map_err(|e| ParseError::MissingField { field: e })?;

                packages.push(package.clone());

                // Create dependency edge from root
                dependencies.push(Dependency::new(
                    root_package.clone(),
                    package,
                    version_str,
                    false, // Direct dependency from manifest
                ));
            }
        }

        Ok(ParseResult {
            packages,
            dependencies,
        })
    }

    /// Clean Cargo version specifier
    fn clean_cargo_version(&self, version_str: &str) -> Result<String, ParseError> {
        let version_str = version_str.trim();

        if version_str.is_empty() || version_str == "*" {
            return Ok("0.0.0".to_string());
        }

        // Remove common Cargo prefixes
        let cleaned = if version_str.starts_with('^') || version_str.starts_with('~') {
            &version_str[1..]
        } else if version_str.starts_with(">=") || version_str.starts_with("<=") {
            &version_str[2..]
        } else if version_str.starts_with('>')
            || version_str.starts_with('<')
            || version_str.starts_with('=')
        {
            &version_str[1..]
        } else {
            version_str
        };

        // Handle version ranges (take the first version)
        let cleaned = if let Some(comma_pos) = cleaned.find(',') {
            &cleaned[..comma_pos]
        } else {
            cleaned
        };

        let cleaned = cleaned.trim();

        if cleaned.is_empty() {
            Ok("0.0.0".to_string())
        } else {
            Ok(cleaned.to_string())
        }
    }
}

#[async_trait]
impl PackageFileParser for CargoParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "Cargo.toml"
    }

    async fn parse_file(&self, content: &str) -> Result<ParseResult, ParseError> {
        let toml_value: toml::Value = toml::from_str(content)?;
        let mut result = ParseResult::default();

        // Extract root package info
        let root_name = toml_value
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("root")
            .to_string();
        let root_version_str = toml_value
            .get("package")
            .and_then(|p| p.get("version"))
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0");
        let root_version =
            Version::parse(root_version_str).unwrap_or_else(|_| Version::new(0, 0, 0));
        let root_package = Package::new(root_name, root_version, Ecosystem::Cargo)
            .map_err(|e| ParseError::MissingField { field: e })?;

        // Extract from dependencies section
        let deps = self.extract_dependencies(&toml_value, "dependencies", &root_package)?;
        result.packages.extend(deps.packages);
        result.dependencies.extend(deps.dependencies);

        // Extract from dev-dependencies section
        let dev_deps = self.extract_dependencies(&toml_value, "dev-dependencies", &root_package)?;
        result.packages.extend(dev_deps.packages);
        result.dependencies.extend(dev_deps.dependencies);

        // Extract from build-dependencies section
        let build_deps =
            self.extract_dependencies(&toml_value, "build-dependencies", &root_package)?;
        result.packages.extend(build_deps.packages);
        result.dependencies.extend(build_deps.dependencies);

        Ok(result)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cargo
    }

    fn priority(&self) -> u8 {
        10 // High priority for Cargo.toml
    }
}

/// Parser for Cargo.lock files
pub struct CargoLockParser;

impl Default for CargoLockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl CargoLockParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract packages and dependencies from Cargo.lock
    fn extract_lock_data(&self, toml_value: &toml::Value) -> Result<ParseResult, ParseError> {
        let mut packages = Vec::new();
        let mut dependencies = Vec::new();
        let mut package_map = std::collections::HashMap::new();

        // First pass: Collect all packages
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

                    let version = Version::parse(version_str).map_err(|_| ParseError::Version {
                        version: version_str.to_string(),
                    })?;

                    let package = Package::new(name.to_string(), version, Ecosystem::Cargo)
                        .map_err(|e| ParseError::MissingField { field: e })?;

                    packages.push(package.clone());
                    // Key by name and version for precise lookup
                    package_map.insert((name.to_string(), version_str.to_string()), package);
                }
            }
        }

        // Second pass: Build dependency edges
        if let Some(packages_array) = toml_value.get("package").and_then(|p| p.as_array()) {
            for package_info in packages_array {
                if let Some(package_table) = package_info.as_table() {
                    let name = package_table
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or_default();
                    let version_str = package_table
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();

                    if let Some(source_pkg) =
                        package_map.get(&(name.to_string(), version_str.to_string()))
                    {
                        if let Some(deps) =
                            package_table.get("dependencies").and_then(|d| d.as_array())
                        {
                            for dep_val in deps {
                                if let Some(dep_str) = dep_val.as_str() {
                                    // Format: "name version" or just "name"
                                    let parts: Vec<&str> = dep_str.split_whitespace().collect();
                                    let dep_name = parts[0];

                                    // If version is specified, use it. If not, we have to guess or find the only one.
                                    // Cargo.lock usually specifies version if ambiguous.
                                    let target_pkg = if parts.len() >= 2 {
                                        let dep_version = parts[1];
                                        package_map
                                            .get(&(dep_name.to_string(), dep_version.to_string()))
                                    } else {
                                        // Find any package with this name (assuming unique or taking first)
                                        // In a real implementation we should handle this better, but for now this is a reasonable fallback
                                        package_map
                                            .iter()
                                            .find(|((n, _), _)| n == dep_name)
                                            .map(|(_, p)| p)
                                    };

                                    if let Some(target) = target_pkg {
                                        dependencies.push(Dependency::new(
                                            source_pkg.clone(),
                                            target.clone(),
                                            target.version.to_string(), // Requirement is effectively the locked version
                                            false, // We don't know if it's transitive from here easily, but in a lockfile everything is explicit
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(ParseResult {
            packages,
            dependencies,
        })
    }
}

#[async_trait]
impl PackageFileParser for CargoLockParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "Cargo.lock"
    }

    async fn parse_file(&self, content: &str) -> Result<ParseResult, ParseError> {
        let toml_value: toml::Value = toml::from_str(content)?;
        self.extract_lock_data(&toml_value)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cargo
    }

    fn priority(&self) -> u8 {
        15 // Higher priority than Cargo.toml for exact versions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cargo_toml_parser() {
        let parser = CargoParser::new();
        let content = r#"
[package]
name = "my-package"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
reqwest = "^0.11"
clap = "~3.2"

[dev-dependencies]
tokio-test = "0.4"
        "#;

        let result = parser.parse_file(content).await.unwrap();
        assert_eq!(result.packages.len(), 5);

        let serde_pkg = result.packages.iter().find(|p| p.name == "serde").unwrap();
        assert_eq!(serde_pkg.version, Version::parse("1.0").unwrap());
        assert_eq!(serde_pkg.ecosystem, Ecosystem::Cargo);

        let tokio_pkg = result.packages.iter().find(|p| p.name == "tokio").unwrap();
        assert_eq!(tokio_pkg.version, Version::parse("1.0").unwrap());
    }

    #[tokio::test]
    async fn test_cargo_lock_parser() {
        let parser = CargoLockParser::new();
        let content = r#"
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "serde"
version = "1.0.136"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.17.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "pin-project-lite",
]
        "#;

        let result = parser.parse_file(content).await.unwrap();
        assert_eq!(result.packages.len(), 2);

        let serde_pkg = result.packages.iter().find(|p| p.name == "serde").unwrap();
        assert_eq!(serde_pkg.version, Version::parse("1.0.136").unwrap());

        let tokio_pkg = result.packages.iter().find(|p| p.name == "tokio").unwrap();
        assert_eq!(tokio_pkg.version, Version::parse("1.17.0").unwrap());
    }

    #[test]
    fn test_clean_cargo_version() {
        let parser = CargoParser::new();

        assert_eq!(parser.clean_cargo_version("1.0").unwrap(), "1.0");
        assert_eq!(parser.clean_cargo_version("^1.0").unwrap(), "1.0");
        assert_eq!(parser.clean_cargo_version("~1.0").unwrap(), "1.0");
        assert_eq!(parser.clean_cargo_version(">=1.0").unwrap(), "1.0");
        assert_eq!(parser.clean_cargo_version("1.0, <2.0").unwrap(), "1.0");
        assert_eq!(parser.clean_cargo_version("*").unwrap(), "0.0.0");
    }

    #[test]
    fn test_parser_supports_file() {
        let cargo_parser = CargoParser::new();
        let lock_parser = CargoLockParser::new();

        assert!(cargo_parser.supports_file("Cargo.toml"));
        assert!(!cargo_parser.supports_file("Cargo.lock"));

        assert!(lock_parser.supports_file("Cargo.lock"));
        assert!(!lock_parser.supports_file("Cargo.toml"));
    }
}
