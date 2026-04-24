//! PHP ecosystem parsers

use super::traits::{PackageFileParser, ParseResult};
use crate::application::errors::ParseError;
use crate::domain::vulnerability::{
    entities::{Dependency, Package},
    value_objects::{Ecosystem, Version},
};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

/// Parser for composer.json files
pub struct ComposerParser;

impl Default for ComposerParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ComposerParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract dependencies from JSON object
    fn extract_dependencies(
        &self,
        json: &Value,
        dep_type: &str,
        root_package: &Package,
    ) -> Result<ParseResult, ParseError> {
        let mut packages = Vec::new();
        let mut dependencies = Vec::new();

        if let Some(deps) = json.get(dep_type).and_then(|d| d.as_object()) {
            for (name, version_value) in deps {
                // Skip PHP version requirement
                if name == "php" {
                    continue;
                }

                let version_str =
                    version_value
                        .as_str()
                        .ok_or_else(|| ParseError::MissingField {
                            field: format!("version for package {}", name),
                        })?;

                // Clean version string
                let clean_version = self.clean_composer_version(version_str)?;

                let version = Version::parse(&clean_version).map_err(|_| ParseError::Version {
                    version: version_str.to_string(),
                })?;

                let package = Package::new(name.clone(), version, Ecosystem::Packagist)
                    .map_err(|e| ParseError::MissingField { field: e })?;

                packages.push(package.clone());

                // Create dependency edge from root
                dependencies.push(Dependency::new(
                    root_package.clone(),
                    package,
                    version_str.to_string(),
                    false, // Direct dependency from manifest
                ));
            }
        }

        Ok(ParseResult {
            packages,
            dependencies,
        })
    }

    /// Clean Composer version string
    fn clean_composer_version(&self, version_str: &str) -> Result<String, ParseError> {
        let version_str = version_str.trim();

        if version_str.is_empty() || version_str == "*" {
            return Ok("0.0.0".to_string());
        }

        // Remove common Composer prefixes
        let cleaned = if version_str.starts_with('^') || version_str.starts_with('~') {
            &version_str[1..]
        } else if version_str.starts_with(">=") || version_str.starts_with("<=") {
            &version_str[2..]
        } else if version_str.starts_with('>') || version_str.starts_with('<') {
            &version_str[1..]
        } else {
            version_str
        };

        // Handle version ranges (take the first version)
        let cleaned = if let Some(pipe_pos) = cleaned.find('|') {
            &cleaned[..pipe_pos]
        } else if let Some(comma_pos) = cleaned.find(',') {
            &cleaned[..comma_pos]
        } else {
            cleaned
        };

        // Handle stability flags (remove -dev, -alpha, etc.)
        let cleaned = if let Some(dash_pos) = cleaned.find('-') {
            let base_part = &cleaned[..dash_pos];
            // Only keep the base if it looks like a version
            if base_part.matches('.').count() >= 1 {
                base_part
            } else {
                cleaned
            }
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
impl PackageFileParser for ComposerParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "composer.json"
    }

    async fn parse_file(&self, content: &str) -> Result<ParseResult, ParseError> {
        let json: Value = serde_json::from_str(content)?;
        let mut result = ParseResult::default();

        // Extract root package info
        let root_name = json
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("root")
            .to_string();
        let root_version_str = json
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0");
        let root_version =
            Version::parse(root_version_str).unwrap_or_else(|_| Version::new(0, 0, 0));
        let root_package = Package::new(root_name, root_version, Ecosystem::Packagist)
            .map_err(|e| ParseError::MissingField { field: e })?;

        // Extract different types of dependencies
        let deps = self.extract_dependencies(&json, "require", &root_package)?;
        result.packages.extend(deps.packages);
        result.dependencies.extend(deps.dependencies);

        let dev_deps = self.extract_dependencies(&json, "require-dev", &root_package)?;
        result.packages.extend(dev_deps.packages);
        result.dependencies.extend(dev_deps.dependencies);

        Ok(result)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Packagist
    }

    fn priority(&self) -> u8 {
        10 // High priority for composer.json
    }
}

/// Parser for composer.lock files
pub struct ComposerLockParser;

impl Default for ComposerLockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ComposerLockParser {
    pub fn new() -> Self {
        Self
    }

    fn infer_dependency_version(requirement: &str) -> Option<Version> {
        let req = requirement.trim();
        if req.is_empty() || req == "*" {
            return None;
        }

        let cleaned = req
            .trim_start_matches('^')
            .trim_start_matches('~')
            .trim_start_matches("<=")
            .trim_start_matches(">=")
            .trim_start_matches('<')
            .trim_start_matches('>')
            .trim_start_matches('=')
            .split(['|', ','])
            .next()
            .unwrap_or(req)
            .trim();

        let cleaned = cleaned.strip_prefix('v').unwrap_or(cleaned);
        Version::parse(cleaned).ok()
    }

    /// Extract packages and dependencies from composer.lock
    fn extract_lock_data(&self, json: &Value, section: &str) -> Result<ParseResult, ParseError> {
        let mut packages = Vec::new();
        let mut dependencies = Vec::new();
        let mut pending_dependencies: Vec<(Package, String, String)> = Vec::new();

        if let Some(packages_array) = json.get(section).and_then(|p| p.as_array()) {
            for package_info in packages_array {
                if let Some(package_obj) = package_info.as_object() {
                    let name = package_obj
                        .get("name")
                        .and_then(|n| n.as_str())
                        .ok_or_else(|| ParseError::MissingField {
                            field: "package name".to_string(),
                        })?;

                    let version_str = package_obj
                        .get("version")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| ParseError::MissingField {
                            field: "package version".to_string(),
                        })?;

                    let clean_version = if let Some(stripped) = version_str.strip_prefix('v') {
                        stripped
                    } else {
                        version_str
                    };

                    let version =
                        Version::parse(clean_version).map_err(|_| ParseError::Version {
                            version: version_str.to_string(),
                        })?;

                    let package = Package::new(name.to_string(), version, Ecosystem::Packagist)
                        .map_err(|e| ParseError::MissingField { field: e })?;

                    packages.push(package.clone());

                    // Extract dependencies from "require" block inside the package
                    if let Some(require) = package_obj.get("require").and_then(|r| r.as_object()) {
                        for (dep_name, dep_req_val) in require {
                            if dep_name == "php" {
                                continue;
                            }

                            if let Some(dep_req) = dep_req_val.as_str() {
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
            if let Some(existing_target) = package_by_name.get(&dep_name) {
                dependencies.push(Dependency::new(
                    from,
                    existing_target.clone(),
                    dep_req,
                    false,
                ));
                continue;
            }

            if let Some(inferred_version) = Self::infer_dependency_version(&dep_req)
                && let Ok(inferred_target) =
                    Package::new(dep_name, inferred_version, Ecosystem::Packagist)
            {
                dependencies.push(Dependency::new(from, inferred_target, dep_req, false));
            }
        }

        Ok(ParseResult {
            packages,
            dependencies,
        })
    }
}

#[async_trait]
impl PackageFileParser for ComposerLockParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "composer.lock"
    }

    async fn parse_file(&self, content: &str) -> Result<ParseResult, ParseError> {
        let json: Value = serde_json::from_str(content)?;
        let mut packages = Vec::new();
        let mut dependencies = Vec::new();

        // Extract from packages section
        let result = self.extract_lock_data(&json, "packages")?;
        packages.extend(result.packages);
        dependencies.extend(result.dependencies);

        // Extract from packages-dev section
        let result_dev = self.extract_lock_data(&json, "packages-dev")?;
        packages.extend(result_dev.packages);
        dependencies.extend(result_dev.dependencies);

        Ok(ParseResult {
            packages,
            dependencies,
        })
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Packagist
    }

    fn priority(&self) -> u8 {
        15 // Higher priority than composer.json for exact versions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_composer_json_parser() {
        let parser = ComposerParser::new();
        let content = r#"
        {
            "name": "my/project",
            "require": {
                "php": "^8.0",
                "symfony/console": "^5.4",
                "guzzlehttp/guzzle": "~7.0",
                "monolog/monolog": ">=2.0"
            },
            "require-dev": {
                "phpunit/phpunit": "^9.5",
                "symfony/var-dumper": "*"
            }
        }
        "#;

        let result = parser.parse_file(content).await.unwrap();
        assert_eq!(result.packages.len(), 5); // Excluding php version

        let symfony_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "symfony/console")
            .unwrap();
        assert_eq!(symfony_pkg.version, Version::parse("5.4").unwrap());
        assert_eq!(symfony_pkg.ecosystem, Ecosystem::Packagist);

        let guzzle_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "guzzlehttp/guzzle")
            .unwrap();
        assert_eq!(guzzle_pkg.version, Version::parse("7.0").unwrap());
    }

    #[tokio::test]
    async fn test_composer_lock_parser() {
        let parser = ComposerLockParser::new();
        let content = r#"
        {
            "_readme": [
                "This file locks the dependencies of your project to a known state"
            ],
            "packages": [
                {
                    "name": "symfony/console",
                    "version": "v5.4.8",
                    "source": {
                        "type": "git",
                        "url": "https://github.com/symfony/console.git",
                        "reference": "7fccea8728aa2d431a6725b02b3ce759049fc84d"
                    },
                    "require": {
                        "php": ">=7.2.5",
                        "symfony/polyfill-mbstring": "~1.0",
                        "symfony/service-contracts": "^1.1|^2"
                    }
                },
                {
                    "name": "monolog/monolog",
                    "version": "2.5.0",
                    "source": {
                        "type": "git",
                        "url": "https://github.com/Seldaek/monolog.git",
                        "reference": "4192345e260f1d51b365536199744b987e160edc"
                    }
                }
            ],
            "packages-dev": [
                {
                    "name": "phpunit/phpunit",
                    "version": "9.5.20",
                    "source": {
                        "type": "git",
                        "url": "https://github.com/sebastianbergmann/phpunit.git",
                        "reference": "12bc8879fb65aef2138b26fc633cb1e3620cffba"
                    }
                }
            ]
        }
        "#;

        let result = parser.parse_file(content).await.unwrap();
        assert_eq!(result.packages.len(), 3);

        let symfony_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "symfony/console")
            .unwrap();
        assert_eq!(symfony_pkg.version, Version::parse("5.4.8").unwrap());

        // Check dependencies
        let deps: Vec<_> = result
            .dependencies
            .iter()
            .filter(|d| d.from.name == "symfony/console")
            .collect();
        assert_eq!(deps.len(), 2); // php is skipped

        let polyfill_dep = deps
            .iter()
            .find(|d| d.to.name == "symfony/polyfill-mbstring")
            .unwrap();
        assert_eq!(polyfill_dep.requirement, "~1.0");

        let monolog_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "monolog/monolog")
            .unwrap();
        assert_eq!(monolog_pkg.version, Version::parse("2.5.0").unwrap());
    }

    #[test]
    fn test_clean_composer_version() {
        let parser = ComposerParser::new();

        assert_eq!(parser.clean_composer_version("^5.4").unwrap(), "5.4");
        assert_eq!(parser.clean_composer_version("~7.0").unwrap(), "7.0");
        assert_eq!(parser.clean_composer_version(">=2.0").unwrap(), "2.0");
        assert_eq!(parser.clean_composer_version("*").unwrap(), "0.0.0");
        assert_eq!(parser.clean_composer_version("5.4|6.0").unwrap(), "5.4");
        assert_eq!(parser.clean_composer_version("2.5.0-dev").unwrap(), "2.5.0");
    }

    #[test]
    fn test_parser_supports_file() {
        let composer_parser = ComposerParser::new();
        let lock_parser = ComposerLockParser::new();

        assert!(composer_parser.supports_file("composer.json"));
        assert!(!composer_parser.supports_file("composer.lock"));

        assert!(lock_parser.supports_file("composer.lock"));
        assert!(!lock_parser.supports_file("composer.json"));
    }
}
