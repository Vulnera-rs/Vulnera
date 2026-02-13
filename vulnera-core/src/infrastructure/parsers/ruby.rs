//! Ruby ecosystem parsers (Gemfile, Gemfile.lock)
//!
//! Notes:
//! - Gemfile.lock parser prefers resolved versions from the `GEM -> specs:` section.
//! - Gemfile parser extracts the first version-like constraint per `gem` line and cleans it
//!   to a base semver version for querying (e.g., "~> 6.1.0" -> "6.1.0").
//!
//! Limitations:
//! - Some platform-specific versions in Gemfile.lock (e.g., "1.14.0-x86_64-linux") are
//!   normalized to the numeric base (e.g., "1.14.0") to satisfy semver parsing.
//! - Gemfile lines with only git/path constraints default to "0.0.0" for version.

use super::traits::{PackageFileParser, ParseResult};
use crate::application::errors::ParseError;
use crate::domain::vulnerability::{
    entities::{Dependency, Package},
    value_objects::{Ecosystem, Version},
};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

static RE_BASE_VERSION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(\d+(?:\.\d+){0,3})\b").unwrap());

fn is_comment_or_blank(line: &str) -> bool {
    let t = line.trim();
    t.is_empty() || t.starts_with('#')
}

/// Extract a base version like "1.2.3" (optionally 4th numeric) from a constraint or raw version.
///
/// Examples:
/// - "~> 6.1.0" -> "6.1.0"
/// - ">= 2.3.4" -> "2.3.4"
/// - "1.14.0-x86_64-linux" -> "1.14.0"
fn extract_base_version(input: &str) -> Option<String> {
    // Capture a leading numeric dotted version (1 to 4 segments).
    // Many Ruby gems use 4 segments (e.g., 4.2.11.1)
    if let Some(caps) = RE_BASE_VERSION.captures(input) {
        return Some(caps.get(1).unwrap().as_str().to_string());
    }
    None
}

/// Lenient version parser for Ruby gems:
/// - First try normal parsing.
/// - If it fails and the version has 4 numeric segments, truncate to 3 (major.minor.patch),
///   preserving a simple pre-release suffix if present.
fn parse_version_lenient(v: &str) -> Result<Version, ParseError> {
    match Version::parse(v) {
        Ok(ver) => Ok(ver),
        Err(_) => {
            let parts: Vec<&str> = v.split('-').collect();
            let core = parts[0];
            let prerelease = if parts.len() > 1 {
                Some(parts[1])
            } else {
                None
            };

            let nums: Vec<&str> = core.split('.').collect();
            if nums.len() > 3 {
                let truncated = format!("{}.{}.{}", nums[0], nums[1], nums[2]);
                let with_pre = match prerelease {
                    Some(pre) if !pre.is_empty() => format!("{}-{}", truncated, pre),
                    _ => truncated,
                };
                Version::parse(&with_pre).map_err(|_| ParseError::Version {
                    version: v.to_string(),
                })
            } else {
                Err(ParseError::Version {
                    version: v.to_string(),
                })
            }
        }
    }
}

static RE_GEM_LINE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)^\s*gem\s+["']([^"']+)["']\s*(?:,\s*(.+))?\s*$"#).unwrap());

static RE_QUOTED_STRING: Lazy<Regex> = Lazy::new(|| Regex::new(r#""([^"]+)"|'([^']+)'"#).unwrap());

static RE_SPEC_LINE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"^\s{4}([A-Za-z0-9_\-\.]+)\s+\(([^)]+)\)"#).unwrap());

static RE_DEP_LINE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"^\s{6}([A-Za-z0-9_\-\.]+)\s*(?:\(([^)]+)\))?"#).unwrap());

/// Parse a Gemfile `gem` declaration line to (name, version-like-string).
/// Returns None if the line is not a valid `gem` line.
fn parse_gem_line(line: &str) -> Option<(String, Option<String>)> {
    // Basic match for: gem 'name'[, version_or_constraints, ...]
    // We capture the gem name in group 1, and the rest of the args (if any) in group 2.
    let caps = RE_GEM_LINE.captures(line)?;
    let name = caps.get(1)?.as_str().trim().to_string();
    let args = caps.get(2).map(|m| m.as_str().trim().to_string());

    // If args exist, try to find the first quoted string that looks like a version constraint.
    if let Some(args_str) = args.as_ref() {
        for m in RE_QUOTED_STRING.captures_iter(args_str) {
            let candidate = m
                .get(1)
                .or_else(|| m.get(2))
                .map(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if candidate.is_empty() {
                continue;
            }
            // We accept the first candidate that contains a digit, then clean it later
            if candidate.chars().any(|c| c.is_ascii_digit()) {
                return Some((name, Some(candidate.to_string())));
            }
        }
    }

    Some((name, None))
}

/// Parser for Gemfile
pub struct GemfileParser;

impl Default for GemfileParser {
    fn default() -> Self {
        Self::new()
    }
}

impl GemfileParser {
    pub fn new() -> Self {
        Self
    }

    fn parse_gemfile_content(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        for line in content.lines() {
            if is_comment_or_blank(line) {
                continue;
            }

            if let Some((name, maybe_constraint)) = parse_gem_line(line) {
                let version_str = match maybe_constraint {
                    Some(c) => extract_base_version(&c).unwrap_or_else(|| "0.0.0".to_string()),
                    None => "0.0.0".to_string(),
                };

                let version = parse_version_lenient(&version_str)?;

                let package = Package::new(name, version, Ecosystem::RubyGems)
                    .map_err(|e| ParseError::MissingField { field: e })?;
                packages.push(package);
            }
        }

        Ok(packages)
    }
}

#[async_trait]
impl PackageFileParser for GemfileParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "Gemfile"
    }

    async fn parse_file(&self, content: &str) -> Result<ParseResult, ParseError> {
        let packages = self.parse_gemfile_content(content)?;
        Ok(ParseResult {
            packages,
            dependencies: Vec::new(),
        })
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::RubyGems
    }

    fn priority(&self) -> u8 {
        5 // Lower than lockfile parser
    }
}

/// Parser for Gemfile.lock
pub struct GemfileLockParser;

impl Default for GemfileLockParser {
    fn default() -> Self {
        Self::new()
    }
}

impl GemfileLockParser {
    pub fn new() -> Self {
        Self
    }

    fn parse_gemfile_lock_content(&self, content: &str) -> Result<ParseResult, ParseError> {
        let mut packages = Vec::new();
        let mut dependencies = Vec::new();
        let mut pending_dependencies: Vec<(Package, String, String)> = Vec::new();

        // We only parse the "GEM -> specs" section. Lines look like:
        // "    some_gem (1.2.3)"
        // "      dependency (>= 1.0)"
        // "    nokogiri (1.14.0-x86_64-linux)"
        let mut in_gem_section = false;
        let mut in_specs = false;
        let mut current_package: Option<Package> = None;

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed == "GEM" {
                in_gem_section = true;
                in_specs = false;
                continue;
            }

            // End of GEM block when encountering a known section or blank line after section
            if in_gem_section
                && (trimmed == "PLATFORMS"
                    || trimmed == "DEPENDENCIES"
                    || trimmed == "BUNDLED WITH")
            {
                // We are exiting specs section implicitly
                in_gem_section = false;
                in_specs = false;
                current_package = None;
            }

            if in_gem_section && trimmed == "specs:" {
                in_specs = true;
                continue;
            }

            if !in_specs {
                continue;
            }

            // A blank line typically ends the specs area (or next section header as above)
            if trimmed.is_empty() {
                in_specs = false;
                current_package = None;
                continue;
            }

            // Check for package definition (indentation 4 spaces)
            if let Some(caps) = RE_SPEC_LINE.captures(line) {
                let name = caps.get(1).map(|m| m.as_str()).unwrap_or("").trim();
                let raw_version = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();

                if name.is_empty() || raw_version.is_empty() {
                    current_package = None;
                    continue;
                }

                let version_str =
                    extract_base_version(raw_version).unwrap_or_else(|| "0.0.0".to_string());

                let version = parse_version_lenient(&version_str)?;

                let package = Package::new(name.to_string(), version, Ecosystem::RubyGems)
                    .map_err(|e| ParseError::MissingField { field: e })?;
                packages.push(package.clone());
                current_package = Some(package);
                continue;
            }

            // Check for dependency definition (indentation 6 spaces)
            if let Some(pkg) = &current_package
                && let Some(caps) = RE_DEP_LINE.captures(line)
            {
                let dep_name = caps.get(1).map(|m| m.as_str()).unwrap_or("").trim();
                let dep_req = caps.get(2).map(|m| m.as_str()).unwrap_or("*").trim();

                if !dep_name.is_empty() {
                    pending_dependencies.push((
                        pkg.clone(),
                        dep_name.to_string(),
                        dep_req.to_string(),
                    ));
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
            if let Some(target) = package_by_name.get(&dep_name) {
                dependencies.push(Dependency::new(from, target.clone(), dep_req, false));
                continue;
            }

            if let Some(base_version) = extract_base_version(&dep_req)
                && let Ok(version) = parse_version_lenient(&base_version)
                && let Ok(inferred_target) = Package::new(dep_name, version, Ecosystem::RubyGems)
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
impl PackageFileParser for GemfileLockParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "Gemfile.lock"
    }

    async fn parse_file(&self, content: &str) -> Result<ParseResult, ParseError> {
        self.parse_gemfile_lock_content(content)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::RubyGems
    }

    fn priority(&self) -> u8 {
        20 // Prefer lockfile over Gemfile
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gemfile_parser_basic() {
        let parser = GemfileParser::new();
        let content = r#"
# A sample Gemfile
source "https://rubygems.org"

gem "rails", "~> 6.1.0"
gem 'puma', '>= 5.0'
gem "dotenv-rails"
gem "octokit", "~> 5.0", ">= 5.1" # multiple constraints, we take the first
"#;

        let result = parser.parse_file(content).await.unwrap();
        // rails, puma, dotenv-rails, octokit
        assert_eq!(result.packages.len(), 4);
        let rails = result.packages.iter().find(|p| p.name == "rails").unwrap();
        assert_eq!(rails.version, Version::parse("6.1.0").unwrap());

        let puma = result.packages.iter().find(|p| p.name == "puma").unwrap();
        assert_eq!(puma.version, Version::parse("5.0.0").unwrap());

        let dotenv = result
            .packages
            .iter()
            .find(|p| p.name == "dotenv-rails")
            .unwrap();
        assert_eq!(dotenv.version, Version::parse("0.0.0").unwrap());

        let octo = result
            .packages
            .iter()
            .find(|p| p.name == "octokit")
            .unwrap();
        assert_eq!(octo.version, Version::parse("5.0.0").unwrap());
    }

    #[tokio::test]
    async fn test_gemfile_lock_parser_specs() {
        let parser = GemfileLockParser::new();
        let content = r#"
GEM
  remote: https://rubygems.org/
  specs:
    actionmailer (6.1.7.1)
      actionpack (= 6.1.7.1)
      activesupport (= 6.1.7.1)
    rake (13.0.1)
    nokogiri (1.14.0-x86_64-linux)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  rails (~> 6.1.7)
  rake
"#;

        let result = parser.parse_file(content).await.unwrap();
        // We parse specs: actionmailer, rake, nokogiri -> 3
        assert_eq!(result.packages.len(), 3);

        let rake = result.packages.iter().find(|p| p.name == "rake").unwrap();
        assert_eq!(rake.version, Version::parse("13.0.1").unwrap());

        let nok = result
            .packages
            .iter()
            .find(|p| p.name == "nokogiri")
            .unwrap();
        // Cleaned from "1.14.0-x86_64-linux" to "1.14.0"
        assert_eq!(nok.version, Version::parse("1.14.0").unwrap());

        // Check dependencies
        let deps: Vec<_> = result
            .dependencies
            .iter()
            .filter(|d| d.from.name == "actionmailer")
            .collect();
        assert_eq!(deps.len(), 2);

        let actionpack_dep = deps.iter().find(|d| d.to.name == "actionpack").unwrap();
        assert_eq!(actionpack_dep.requirement, "= 6.1.7.1");
    }

    #[test]
    fn test_extract_base_version() {
        assert_eq!(extract_base_version("~> 6.1.0").unwrap(), "6.1.0");
        assert_eq!(extract_base_version(">= 2.3.4").unwrap(), "2.3.4");
        assert_eq!(
            extract_base_version("1.14.0-x86_64-linux").unwrap(),
            "1.14.0"
        );
        assert_eq!(extract_base_version("= 4.2.11.1").unwrap(), "4.2.11.1");
        assert!(extract_base_version("no-version-here").is_none());
    }
}
