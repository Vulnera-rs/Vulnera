//! Node.js ecosystem parsers

use super::traits::{PackageFileParser, ParseResult};
use crate::application::errors::ParseError;
use crate::domain::vulnerability::{
    entities::{Dependency, Package},
    value_objects::{Ecosystem, Version},
};
use async_trait::async_trait;
use serde_json::Value;

/// Check if a version string is a URL-based or non-semver dependency that cannot be scanned.
fn is_non_semver_version(version_str: &str) -> bool {
    let v = version_str.trim();
    v.starts_with("git+")
        || v.starts_with("git://")
        || v.starts_with("http://")
        || v.starts_with("https://")
        || v.starts_with("file:")
        || v.starts_with("link:")
        || v.starts_with("workspace:")
        || v.starts_with("npm:")
        || v.starts_with("github:")
        || v.starts_with("gitlab:")
        || v.starts_with("bitbucket:")
        || v.contains("://") // catch-all for URLs
        || (v.contains('/') && v.contains('#')) // github shorthand: user/repo#ref
        || v == "."
        || v == ".."
        || v.starts_with("./")
        || v.starts_with("../")
}

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
        let mut dependencies = Vec::new();

        let root_name = json
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("root")
            .to_string();
        let root_version = json
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0");
        let root_pkg = Package::new(
            root_name,
            Version::parse(root_version).unwrap_or_else(|_| Version::new(0, 0, 0)),
            Ecosystem::Npm,
        )
        .map_err(|e| ParseError::MissingField { field: e })?;

        if let Some(deps) = json.get(dep_type).and_then(|d| d.as_object()) {
            for (name, version_value) in deps {
                let version_str =
                    version_value
                        .as_str()
                        .ok_or_else(|| ParseError::MissingField {
                            field: format!("version for package {}", name),
                        })?;

                // Skip non-semver dependencies (git, tarball, path, file URLs, workspace refs, etc.)
                // These are valid npm specifiers but not scannable for vulnerabilities
                if is_non_semver_version(version_str) {
                    continue;
                }

                // Clean version string (remove npm-specific prefixes like ^, ~, >=, etc.)
                let clean_version = self.clean_version_string(version_str)?;

                let version = Version::parse(&clean_version).map_err(|_| ParseError::Version {
                    version: version_str.to_string(),
                })?;

                let package = Package::new(name.clone(), version, Ecosystem::Npm)
                    .map_err(|e| ParseError::MissingField { field: e })?;

                packages.push(package.clone());

                // Extract dependency relationship from the manifest root
                dependencies.push(crate::domain::vulnerability::entities::Dependency::new(
                    root_pkg.clone(),
                    package,
                    version_str.to_string(),
                    false, // Direct dependency
                ));
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

    fn resolve_dependency_target(
        packages: &[Package],
        dep_name: &str,
        dep_req: &str,
    ) -> Option<Package> {
        let matching: Vec<&Package> = packages.iter().filter(|pkg| pkg.name == dep_name).collect();
        if matching.is_empty() {
            return None;
        }

        if let Ok(req) = semver::VersionReq::parse(dep_req) {
            let best = matching
                .iter()
                .filter(|pkg| req.matches(&pkg.version.0))
                .max_by(|left, right| left.version.cmp(&right.version));

            if let Some(package) = best {
                return Some((*package).clone());
            }
        }

        matching
            .iter()
            .max_by(|left, right| left.version.cmp(&right.version))
            .map(|package| (*package).clone())
    }

    /// Extract packages and dependencies from lockfile
    ///
    /// # Arguments
    /// * `deps` - The JSON value containing package data
    /// * `is_packages_section` - True if processing "packages" section (lockfileVersion 2/3), false for "dependencies" section (v1)
    fn extract_lockfile_data(
        deps: &Value,
        is_packages_section: bool,
    ) -> Result<ParseResult, ParseError> {
        let mut packages = Vec::new();
        let mut dependencies = Vec::new();
        let mut pending_dependencies: Vec<(Package, String, String)> = Vec::new();

        if let Some(deps_obj) = deps.as_object() {
            for (key, dep_info) in deps_obj {
                if let Some(version_str) = dep_info.get("version").and_then(|v| v.as_str()) {
                    // Skip non-semver dependencies (git, tarball, path, file URLs, workspace refs, etc.)
                    // These are valid npm specifiers but not scannable for vulnerabilities
                    if is_non_semver_version(version_str) {
                        continue;
                    }

                    let version = Version::parse(version_str).map_err(|_| ParseError::Version {
                        version: version_str.to_string(),
                    })?;

                    // Extract the actual package name based on the lockfile format
                    let name = if is_packages_section {
                        // In lockfileVersion 2/3 (npm v7+), the "packages" section uses:
                        // - "" (empty string) for the root package
                        // - "node_modules/package-name" for other packages
                        if key.is_empty() {
                            // Root package: extract name from the "name" field
                            dep_info
                                .get("name")
                                .and_then(|n| n.as_str())
                                .map(|n| n.to_string())
                                .ok_or_else(|| ParseError::MissingField {
                                    field: "name".to_string(),
                                })?
                        } else if let Some(stripped) = key.strip_prefix("node_modules/") {
                            // Regular package: strip the "node_modules/" prefix to get the actual package name
                            stripped.to_string()
                        } else {
                            // Fallback: use the key as-is (shouldn't happen in well-formed lockfiles)
                            key.clone()
                        }
                    } else {
                        // In v1 lockfiles, the "dependencies" section uses package names directly as keys
                        key.clone()
                    };

                    let package = Package::new(name.clone(), version, Ecosystem::Npm)
                        .map_err(|e| ParseError::MissingField { field: e })?;

                    packages.push(package.clone());

                    for (dep_name, dep_req) in
                        Self::extract_logical_dependency_specs(dep_info, is_packages_section)
                    {
                        pending_dependencies.push((package.clone(), dep_name, dep_req));
                    }
                }

                // Recursively process nested dependencies (physical tree)
                // Skip for lockfileVersion 2/3 as they use a flat packages structure instead of nested dependencies
                if !is_packages_section {
                    if let Some(nested_deps) = dep_info.get("dependencies") {
                        // Recurse when v1 dependencies map contains nested package objects.
                        if let Some(deps_obj) = nested_deps.as_object() {
                            if deps_obj.values().any(Value::is_object) {
                                let nested_result = Self::extract_lockfile_data(nested_deps, false)?;
                                packages.extend(nested_result.packages);
                                dependencies.extend(nested_result.dependencies);
                            }
                        }
                    }
                }
            }
        }

        for (from, dep_name, dep_req) in pending_dependencies {
            if let Some(target) = Self::resolve_dependency_target(&packages, &dep_name, &dep_req) {
                dependencies.push(Dependency::new(from, target, dep_req, false));
            }
        }

        Ok(ParseResult {
            packages,
            dependencies,
        })
    }

    fn extract_string_dependency_map(dep_info: &Value, key: &str) -> Vec<(String, String)> {
        dep_info
            .get(key)
            .and_then(Value::as_object)
            .map(|obj| {
                obj.iter()
                    .filter_map(|(dep_name, dep_val)| {
                        dep_val
                            .as_str()
                            .map(|req| (dep_name.clone(), req.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn extract_logical_dependency_specs(
        dep_info: &Value,
        is_packages_section: bool,
    ) -> Vec<(String, String)> {
        let mut out = Vec::new();

        if is_packages_section {
            // npm lockfile v2/v3 package entries use string maps for logical dependency specs.
            for key in [
                "dependencies",
                "optionalDependencies",
                "peerDependencies",
                "devDependencies",
            ] {
                out.extend(Self::extract_string_dependency_map(dep_info, key));
            }
            return out;
        }

        // npm lockfile v1: `requires` is the canonical logical dependency map.
        let requires = Self::extract_string_dependency_map(dep_info, "requires");
        if !requires.is_empty() {
            return requires;
        }

        // Compatibility fallback for malformed/non-standard lockfiles.
        Self::extract_string_dependency_map(dep_info, "dependencies")
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

        // Extract from dependencies section (v1 lockfiles)
        if let Some(deps) = json.get("dependencies") {
            let res = Self::extract_lockfile_data(deps, false)?;
            result.packages.extend(res.packages);
            result.dependencies.extend(res.dependencies);
        }

        // Extract from packages section (lockfileVersion 2/3, npm v7+)
        if let Some(pkgs) = json.get("packages") {
            let res = Self::extract_lockfile_data(pkgs, true)?;
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
        let mut pending_dependencies: Vec<(Package, String, String)> = Vec::new();

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
                                    pending_dependencies.push((
                                        package.clone(),
                                        dep_name.clone(),
                                        dep_req.clone(),
                                    ));
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
                            pending_dependencies.push((
                                package.clone(),
                                dep_name.clone(),
                                dep_req.clone(),
                            ));
                        }
                    }
                }
            }
        }

        for (from, dep_name, dep_req) in pending_dependencies {
            if let Some(target) =
                PackageLockParser::resolve_dependency_target(&packages, &dep_name, &dep_req)
            {
                dependencies.push(Dependency::new(from, target, dep_req, false));
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

    #[test]
    fn test_is_non_semver_version() {
        // URL-based versions should be detected
        assert!(is_non_semver_version(
            "https://github.com/user/repo/tarball/master"
        ));
        assert!(is_non_semver_version("http://example.com/package.tgz"));
        assert!(is_non_semver_version(
            "git+https://github.com/user/repo.git"
        ));
        assert!(is_non_semver_version("git://github.com/user/repo.git"));
        assert!(is_non_semver_version(
            "git+ssh://git@github.com/user/repo.git"
        ));

        // File/path references should be detected
        assert!(is_non_semver_version("file:../local-package"));
        assert!(is_non_semver_version("file:./local-package"));
        assert!(is_non_semver_version("./local-package"));
        assert!(is_non_semver_version("../local-package"));
        assert!(is_non_semver_version("."));
        assert!(is_non_semver_version(".."));

        // Workspace/link references should be detected
        assert!(is_non_semver_version("workspace:*"));
        assert!(is_non_semver_version("workspace:^"));
        assert!(is_non_semver_version("link:./packages/pkg"));

        // npm aliases should be detected
        assert!(is_non_semver_version("npm:actual-package@1.0.0"));

        // GitHub/GitLab/Bitbucket shorthand should be detected
        assert!(is_non_semver_version("github:user/repo"));
        assert!(is_non_semver_version("gitlab:user/repo"));
        assert!(is_non_semver_version("bitbucket:user/repo"));
        assert!(is_non_semver_version("user/repo#branch")); // GitHub shorthand with ref

        // Valid semver versions should NOT be detected as non-semver
        assert!(!is_non_semver_version("1.0.0"));
        assert!(!is_non_semver_version("^1.0.0"));
        assert!(!is_non_semver_version("~1.0.0"));
        assert!(!is_non_semver_version(">=1.0.0"));
        assert!(!is_non_semver_version("1.0.0-alpha.1"));
        assert!(!is_non_semver_version("*"));
        assert!(!is_non_semver_version("latest"));
    }

    #[tokio::test]
    async fn test_npm_parser_skips_url_dependencies() {
        let parser = NpmParser::new();
        let content = r#"
        {
            "name": "test-package",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.17.1",
                "tarball-pkg": "https://github.com/user/repo/tarball/master",
                "git-pkg": "git+https://github.com/user/repo.git",
                "file-pkg": "file:../local-package",
                "path-pkg": "./local-package",
                "lodash": "~4.17.21"
            }
        }
        "#;

        let result = parser.parse_file(content).await.unwrap();
        // Should only have express and lodash, URL-based deps should be skipped
        assert_eq!(result.packages.len(), 2);

        let names: Vec<&str> = result.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"express"));
        assert!(names.contains(&"lodash"));
        assert!(!names.contains(&"tarball-pkg"));
        assert!(!names.contains(&"git-pkg"));
        assert!(!names.contains(&"file-pkg"));
        assert!(!names.contains(&"path-pkg"));
    }

    #[tokio::test]
    async fn test_package_lock_parser_skips_url_versions() {
        let parser = PackageLockParser::new();
        let content = r#"
        {
            "name": "test-package",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "test-package",
                    "version": "1.0.0"
                },
                "node_modules/express": {
                    "version": "4.17.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz"
                },
                "node_modules/tarball-pkg": {
                    "version": "https://github.com/user/repo/tarball/master"
                },
                "node_modules/git-pkg": {
                    "version": "git+https://github.com/user/repo.git#v1.0.0"
                },
                "node_modules/workspace-pkg": {
                    "version": "workspace:*"
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                }
            }
        }
        "#;

        let result = parser.parse_file(content).await.unwrap();
        // Should only have test-package, express, and lodash - URL-based versions should be skipped
        assert_eq!(result.packages.len(), 3);

        let names: Vec<&str> = result.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"test-package"));
        assert!(names.contains(&"express"));
        assert!(names.contains(&"lodash"));
        assert!(!names.contains(&"tarball-pkg"));
        assert!(!names.contains(&"git-pkg"));
        assert!(!names.contains(&"workspace-pkg"));
    }

    #[tokio::test]
    async fn test_package_lock_v1_skips_url_versions() {
        // Test lockfileVersion 1 format where URL is directly in the "version" field
        let parser = PackageLockParser::new();
        let content = r#"
        {
            "name": "test-package",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "express": {
                    "version": "4.17.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz"
                },
                "grunt-if": {
                    "version": "https://github.com/binarymist/grunt-if/tarball/master",
                    "from": "grunt-if@https://github.com/binarymist/grunt-if/tarball/master"
                },
                "lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                }
            }
        }
        "#;

        let result = parser.parse_file(content).await.unwrap();
        // Should only have express and lodash - grunt-if with URL version should be skipped
        assert_eq!(result.packages.len(), 2);

        let names: Vec<&str> = result.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"express"));
        assert!(names.contains(&"lodash"));
        assert!(!names.contains(&"grunt-if"));
    }

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
        assert_eq!(result.dependencies.len(), 3); // package.json now extracts dependency edges
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

    #[tokio::test]
    async fn test_package_lock_v3_with_root_package() {
        let parser = PackageLockParser::new();
        let content = r#"
        {
            "name": "my-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": {
                    "name": "my-app",
                    "version": "1.0.0",
                    "dependencies": {
                        "express": "^4.17.1"
                    }
                },
                "node_modules/express": {
                    "version": "4.17.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz",
                    "dependencies": {
                        "accepts": "~1.3.7"
                    }
                },
                "node_modules/accepts": {
                    "version": "1.3.7",
                    "resolved": "https://registry.npmjs.org/accepts/-/accepts-1.3.7.tgz"
                }
            }
        }
        "#;

        let result = parser.parse_file(content).await.unwrap();

        // Should have 3 packages: my-app, express, and accepts
        assert_eq!(result.packages.len(), 3);

        // Verify the root package is correctly named
        let root_pkg = result.packages.iter().find(|p| p.name == "my-app").unwrap();
        assert_eq!(root_pkg.version, Version::parse("1.0.0").unwrap());

        // Verify express package name is stripped of node_modules/ prefix
        let express_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "express")
            .unwrap();
        assert_eq!(express_pkg.version, Version::parse("4.17.1").unwrap());

        // Verify accepts package name is stripped of node_modules/ prefix
        let accepts_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "accepts")
            .unwrap();
        assert_eq!(accepts_pkg.version, Version::parse("1.3.7").unwrap());

        // Verify dependencies are correctly formed
        // Should have 2 dependency edges: my-app->express and express->accepts
        assert_eq!(result.dependencies.len(), 2);

        // Verify the root package depends on express
        let root_dep = result
            .dependencies
            .iter()
            .find(|d| d.from.name == "my-app" && d.to.name == "express")
            .expect("Root package should depend on express");
        assert_eq!(root_dep.requirement, "^4.17.1");

        // Verify express depends on accepts
        let express_dep = result
            .dependencies
            .iter()
            .find(|d| d.from.name == "express" && d.to.name == "accepts")
            .expect("Express should depend on accepts");
        assert_eq!(express_dep.requirement, "~1.3.7");
    }

    #[tokio::test]
    async fn test_package_lock_v1_prefers_requires_for_logical_edges() {
        let parser = PackageLockParser::new();
        let content = r#"
        {
            "name": "app",
            "lockfileVersion": 1,
            "dependencies": {
                "express": {
                    "version": "4.17.1",
                    "requires": {
                        "accepts": "~1.3.7"
                    },
                    "dependencies": {
                        "accepts": {
                            "version": "1.3.7"
                        }
                    }
                }
            }
        }
        "#;

        let result = parser.parse_file(content).await.unwrap();

        assert!(result
            .dependencies
            .iter()
            .any(|d| d.from.name == "express" && d.to.name == "accepts" && d.requirement == "~1.3.7"));
    }
}
