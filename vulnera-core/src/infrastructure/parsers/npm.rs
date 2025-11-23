//! Node.js ecosystem parsers

use super::traits::{PackageFileParser, ParseResult};
use crate::application::errors::ParseError;
use crate::domain::vulnerability::{
    entities::{Dependency, Package},
    value_objects::{Ecosystem, Version},
};
use async_trait::async_trait;
use serde_json::Value;

/// Parser for package.json files
pub struct NpmParser;

impl Default for NpmParser {
    fn default() -> Self {
        Self::new()
    }
}

impl NpmParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract dependencies from a JSON object
    fn extract_dependencies(
        &self,
        json: &Value,
        dep_type: &str,
    ) -> Result<ParseResult, ParseError> {
        let mut packages = Vec::new();
        let dependencies = Vec::new(); // NpmParser doesn't extract edges, so this will remain empty

        if let Some(deps) = json.get(dep_type).and_then(|d| d.as_object()) {
            for (name, version_value) in deps {
                let version_str =
                    version_value
                        .as_str()
                        .ok_or_else(|| ParseError::MissingField {
                            field: format!("version for package {}", name),
                        })?;

                // Clean version string (remove npm-specific prefixes like ^, ~, >=, etc.)
                let clean_version = self.clean_version_string(version_str)?;

                let version = Version::parse(&clean_version).map_err(|_| ParseError::Version {
                    version: version_str.to_string(),
                })?;

                let package = Package::new(name.clone(), version, Ecosystem::Npm)
                    .map_err(|e| ParseError::MissingField { field: e })?;

                packages.push(package);
            }
        }

        Ok(ParseResult {
            packages,
            dependencies,
        })
    }

    /// Clean npm version string by removing prefixes and ranges
    fn clean_version_string(&self, version_str: &str) -> Result<String, ParseError> {
        let version_str = version_str.trim();

        // Handle common npm version patterns
        if version_str.is_empty() {
            return Err(ParseError::Version {
                version: version_str.to_string(),
            });
        }

        // Handle special cases
        if version_str == "*" || version_str == "latest" {
            return Ok("0.0.0".to_string());
        }

        // Remove common prefixes
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
        let cleaned = if let Some(space_pos) = cleaned.find(' ') {
            &cleaned[..space_pos]
        } else {
            cleaned
        };

        // Handle OR conditions (take the first version)
        let cleaned = if let Some(or_pos) = cleaned.find("||") {
            &cleaned[..or_pos]
        } else {
            cleaned
        };

        let cleaned = cleaned.trim();

        if cleaned.is_empty() {
            return Err(ParseError::Version {
                version: version_str.to_string(),
            });
        }

        Ok(cleaned.to_string())
    }
}

#[async_trait]
impl PackageFileParser for NpmParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "package.json"
    }

    async fn parse_file(&self, content: &str) -> Result<ParseResult, ParseError> {
        let json: Value = serde_json::from_str(content)?;
        let mut result = ParseResult::default();

        // Extract different types of dependencies
        let deps = self.extract_dependencies(&json, "dependencies")?;
        result.packages.extend(deps.packages);
        result.dependencies.extend(deps.dependencies);

        let dev_deps = self.extract_dependencies(&json, "devDependencies")?;
        result.packages.extend(dev_deps.packages);
        result.dependencies.extend(dev_deps.dependencies);

        let peer_deps = self.extract_dependencies(&json, "peerDependencies")?;
        result.packages.extend(peer_deps.packages);
        result.dependencies.extend(peer_deps.dependencies);

        let opt_deps = self.extract_dependencies(&json, "optionalDependencies")?;
        result.packages.extend(opt_deps.packages);
        result.dependencies.extend(opt_deps.dependencies);

        Ok(result)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn priority(&self) -> u8 {
        10 // High priority for package.json
    }
}

/// Parser for package-lock.json files
pub struct PackageLockParser;

impl Default for PackageLockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PackageLockParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract packages and dependencies from lockfile
    fn extract_lockfile_data(deps: &Value) -> Result<ParseResult, ParseError> {
        let mut packages = Vec::new();
        let mut dependencies = Vec::new();

        if let Some(deps_obj) = deps.as_object() {
            for (key, dep_info) in deps_obj {
                if let Some(version_str) = dep_info.get("version").and_then(|v| v.as_str()) {
                    let version = Version::parse(version_str).map_err(|_| ParseError::Version {
                        version: version_str.to_string(),
                    })?;

                    // Handle root package in v2/v3 lockfiles (key is empty string)
                    let name = if key.is_empty() {
                        dep_info
                            .get("name")
                            .and_then(|n| n.as_str())
                            .map(|n| n.to_string())
                            .ok_or_else(|| ParseError::MissingField {
                                field: "Package name cannot be empty".to_string(),
                            })?
                    } else {
                        key.clone()
                    };

                    let package = Package::new(name.clone(), version, Ecosystem::Npm)
                        .map_err(|e| ParseError::MissingField { field: e })?;

                    packages.push(package.clone());

                    // Extract dependencies from 'requires' (v1) or 'dependencies' (v2/v3 packages)
                    // Note: In v1 'dependencies' is the nested tree, 'requires' is the logical deps.
                    // In v2/v3 'packages' entries, 'dependencies' is the logical deps.
                    // We check both 'requires' and 'dependencies' here but treat them as logical deps if they are simple key-value pairs
                    // However, 'dependencies' in v1 is nested objects, so we need to be careful.
                    // A simple heuristic: if the value is a string, it's a version requirement (logical dep).
                    // If it's an object, it's a nested dependency (physical tree).

                    let mut extract_edges_from = |key: &str| {
                        if let Some(reqs) = dep_info.get(key).and_then(|r| r.as_object()) {
                            for (dep_name, dep_ver_val) in reqs {
                                if let Some(dep_req) = dep_ver_val.as_str() {
                                    // This is a logical dependency edge
                                    // We create a dependency edge. The 'to' package version is not fully known here
                                    // without resolving it against the whole tree, but we can create a placeholder
                                    // or just use the requirement.
                                    // For now, we'll use 0.0.0 as a placeholder for the 'to' package version if it's a range,
                                    // effectively saying "depends on package X with requirement Y".

                                    let dep_pkg_version = Version::parse("0.0.0").unwrap();
                                    if let Ok(dep_pkg) = Package::new(
                                        dep_name.clone(),
                                        dep_pkg_version,
                                        Ecosystem::Npm,
                                    ) {
                                        dependencies.push(Dependency::new(
                                            package.clone(),
                                            dep_pkg,
                                            dep_req.to_string(),
                                            false,
                                        ));
                                    }
                                }
                            }
                        }
                    };

                    extract_edges_from("requires");
                    // For v2/v3 'packages' entries, 'dependencies' lists logical deps as strings
                    // But we need to distinguish from v1 'dependencies' which are objects.
                    if let Some(deps_val) = dep_info.get("dependencies") {
                        if let Some(deps_obj) = deps_val.as_object() {
                            // Instead of checking only the first value, iterate over all values.
                            for (dep_name, dep_ver_val) in deps_obj {
                                if let Some(dep_req) = dep_ver_val.as_str() {
                                    // This is a logical dependency edge
                                    let dep_pkg_version = Version::parse("0.0.0").unwrap();
                                    if let Ok(dep_pkg) = Package::new(
                                        dep_name.clone(),
                                        dep_pkg_version,
                                        Ecosystem::Npm,
                                    ) {
                                        dependencies.push(Dependency::new(
                                            package.clone(),
                                            dep_pkg,
                                            dep_req.to_string(),
                                            false,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }

                // Recursively process nested dependencies (physical tree)
                if let Some(nested_deps) = dep_info.get("dependencies") {
                    // Check if values are objects (nested deps)
                    if let Some(deps_obj) = nested_deps.as_object() {
                        if let Some((_, val)) = deps_obj.iter().next() {
                            if val.is_object() {
                                let nested_result = Self::extract_lockfile_data(nested_deps)?;
                                packages.extend(nested_result.packages);
                                dependencies.extend(nested_result.dependencies);
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
impl PackageFileParser for PackageLockParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "package-lock.json"
    }

    async fn parse_file(&self, content: &str) -> Result<ParseResult, ParseError> {
        let json: Value = serde_json::from_str(content)?;
        let mut result = ParseResult::default();

        // Extract from dependencies section
        if let Some(deps) = json.get("dependencies") {
            let res = Self::extract_lockfile_data(deps)?;
            result.packages.extend(res.packages);
            result.dependencies.extend(res.dependencies);
        }

        // Extract from packages section (npm v7+)
        if let Some(pkgs) = json.get("packages") {
            let res = Self::extract_lockfile_data(pkgs)?;
            result.packages.extend(res.packages);
            result.dependencies.extend(res.dependencies);
        }

        Ok(result)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn priority(&self) -> u8 {
        15 // Higher priority than package.json for exact versions
    }
}

/// Parser for yarn.lock files
pub struct YarnLockParser;

impl Default for YarnLockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl YarnLockParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse yarn.lock format which is a custom format
    fn parse_yarn_lock(&self, content: &str) -> Result<ParseResult, ParseError> {
        let mut packages = Vec::new();
        let mut dependencies = Vec::new();

        let mut current_package_names: Vec<String> = Vec::new();
        let mut current_version: Option<String> = None;
        let mut current_dependencies: Vec<(String, String)> = Vec::new();
        let mut in_dependencies = false;

        for line in content.lines() {
            let line_trim = line.trim();

            // Skip comments and empty lines
            if line_trim.is_empty() || line_trim.starts_with('#') {
                continue;
            }

            // Indentation check
            let indent = line.len() - line.trim_start().len();

            if indent == 0 {
                // New entry
                // Save previous
                if let Some(version) = &current_version {
                    if let Ok(parsed_version) = Version::parse(version) {
                        for name in &current_package_names {
                            // Name might be "pkg@range", extract just name
                            let pkg_name = if let Some(at_pos) = name.rfind('@') {
                                if at_pos > 0 { &name[..at_pos] } else { name }
                            } else {
                                name
                            };

                            if let Ok(package) = Package::new(
                                pkg_name.to_string(),
                                parsed_version.clone(),
                                Ecosystem::Npm,
                            ) {
                                packages.push(package.clone());

                                // Add dependencies
                                for (dep_name, dep_req) in &current_dependencies {
                                    let dep_pkg_version = Version::parse("0.0.0").unwrap();
                                    if let Ok(dep_pkg) = Package::new(
                                        dep_name.clone(),
                                        dep_pkg_version,
                                        Ecosystem::Npm,
                                    ) {
                                        dependencies.push(Dependency::new(
                                            package.clone(),
                                            dep_pkg,
                                            dep_req.clone(),
                                            false,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }

                // Reset
                current_package_names.clear();
                current_version = None;
                current_dependencies.clear();
                in_dependencies = false;

                // Parse names (comma separated)
                // "pkg-a@^1.0.0, pkg-a@^1.1.0:"
                let line_no_colon = line_trim.trim_end_matches(':');
                for part in line_no_colon.split(',') {
                    let part = part.trim();
                    let part = part.trim_matches('"');
                    current_package_names.push(part.to_string());
                }
            } else if indent == 2 {
                if line_trim.starts_with("version ") {
                    let version_str = line_trim
                        .trim_start_matches("version ")
                        .trim()
                        .trim_matches('"');
                    current_version = Some(version_str.to_string());
                    in_dependencies = false;
                } else if line_trim.starts_with("dependencies:") {
                    in_dependencies = true;
                } else if in_dependencies {
                    // Dependency entry: "dep-name" "range"
                    // or "dep-name" "range"
                    // split by space
                    if let Some(space_pos) = line_trim.find(' ') {
                        let name = line_trim[..space_pos].trim_matches('"');
                        let req = line_trim[space_pos..].trim().trim_matches('"');
                        current_dependencies.push((name.to_string(), req.to_string()));
                    }
                }
            }
        }

        // Save last
        if let Some(version) = &current_version {
            if let Ok(parsed_version) = Version::parse(version) {
                for name in &current_package_names {
                    let pkg_name = if let Some(at_pos) = name.rfind('@') {
                        if at_pos > 0 { &name[..at_pos] } else { name }
                    } else {
                        name
                    };

                    if let Ok(package) =
                        Package::new(pkg_name.to_string(), parsed_version.clone(), Ecosystem::Npm)
                    {
                        packages.push(package.clone());
                        for (dep_name, dep_req) in &current_dependencies {
                            let dep_pkg_version = Version::parse("0.0.0").unwrap();
                            if let Ok(dep_pkg) =
                                Package::new(dep_name.clone(), dep_pkg_version, Ecosystem::Npm)
                            {
                                dependencies.push(Dependency::new(
                                    package.clone(),
                                    dep_pkg,
                                    dep_req.clone(),
                                    false,
                                ));
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
impl PackageFileParser for YarnLockParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "yarn.lock"
    }

    async fn parse_file(&self, content: &str) -> Result<ParseResult, ParseError> {
        self.parse_yarn_lock(content)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn priority(&self) -> u8 {
        12 // Medium-high priority for yarn.lock
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_npm_parser_package_json() {
        let parser = NpmParser::new();
        let content = r#"
        {
            "name": "test-package",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.17.1",
                "lodash": "~4.17.21"
            },
            "devDependencies": {
                "jest": ">=26.0.0"
            }
        }
        "#;

        let result = parser.parse_file(content).await.unwrap();
        assert_eq!(result.packages.len(), 3);

        let express_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "express")
            .unwrap();
        assert_eq!(express_pkg.version, Version::parse("4.17.1").unwrap());
        assert_eq!(express_pkg.ecosystem, Ecosystem::Npm);
        assert_eq!(result.dependencies.len(), 0); // package.json doesn't define dependency edges
    }

    #[tokio::test]
    async fn test_package_lock_parser() {
        let parser = PackageLockParser::new();
        let content = r#"
        {
            "name": "test-package",
            "version": "1.0.0",
            "dependencies": {
                "express": {
                    "version": "4.17.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz"
                },
                "lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                }
            }
        }
        "#;

        let result = parser.parse_file(content).await.unwrap();
        assert_eq!(result.packages.len(), 2);

        let express_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "express")
            .unwrap();
        assert_eq!(express_pkg.version, Version::parse("4.17.1").unwrap());
    }

    #[tokio::test]
    async fn test_yarn_lock_parser() {
        let parser = YarnLockParser::new();
        let content = r#"
# yarn lockfile v1

express@^4.17.1:
  version "4.17.1"
  resolved "https://registry.yarnpkg.com/express/-/express-4.17.1.tgz"

lodash@~4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
        "#;

        let result = parser.parse_file(content).await.unwrap();
        assert_eq!(result.packages.len(), 2);

        let express_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "express")
            .unwrap();
        assert_eq!(express_pkg.version, Version::parse("4.17.1").unwrap());
    }

    #[test]
    fn test_clean_version_string() {
        let parser = NpmParser::new();

        assert_eq!(parser.clean_version_string("^4.17.1").unwrap(), "4.17.1");
        assert_eq!(parser.clean_version_string("~4.17.21").unwrap(), "4.17.21");
        assert_eq!(parser.clean_version_string(">=26.0.0").unwrap(), "26.0.0");
        assert_eq!(parser.clean_version_string("4.17.1").unwrap(), "4.17.1");
        assert_eq!(
            parser.clean_version_string("1.0.0 - 2.0.0").unwrap(),
            "1.0.0"
        );
    }

    #[test]
    fn test_parser_supports_file() {
        let npm_parser = NpmParser::new();
        let lock_parser = PackageLockParser::new();
        let yarn_parser = YarnLockParser::new();

        assert!(npm_parser.supports_file("package.json"));
        assert!(!npm_parser.supports_file("package-lock.json"));

        assert!(lock_parser.supports_file("package-lock.json"));
        assert!(!lock_parser.supports_file("package.json"));

        assert!(yarn_parser.supports_file("yarn.lock"));
        assert!(!yarn_parser.supports_file("package.json"));
    }
}
