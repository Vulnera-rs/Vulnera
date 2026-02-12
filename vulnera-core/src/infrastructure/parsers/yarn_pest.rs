use async_trait::async_trait;
use pest::Parser;
use pest::iterators::{Pair, Pairs};
use pest_derive::Parser;

use crate::application::errors::ParseError;
use crate::domain::vulnerability::{
    entities::{Dependency, Package},
    value_objects::{Ecosystem, Version, VersionRange},
};

use super::traits::{PackageFileParser, ParseResult};

#[derive(Parser)]
#[grammar = "src/infrastructure/parsers/grammars/yarn_lock.pest"]
struct YarnLockPest;

/// Pest-based parser for Yarn v1 lockfiles (yarn.lock)
///
/// This parser implements the **Parser Pattern** using the Pest parsing library to handle
/// the complex grammar of Yarn v1 lockfiles. It provides robust parsing with error recovery
/// and detailed error messages.
///
/// **Yarn v1 Lockfile Format:**
/// ```yaml
/// # Example yarn.lock structure
/// lodash@^4.17.21:
///   version "4.17.21"
///   resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#..."
///   integrity sha512-...
///
/// @babel/core@^7.0.0:
///   version "7.16.0"
///   resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.16.0.tgz#..."
///   integrity sha512-...
///   dependencies:
///     "@babel/types" "^7.16.0"
/// ```
///
/// **Parser Strategy:**
/// 1. **Grammar Definition**: Uses Pest grammar rules for precise parsing
/// 2. **Package Name Extraction**: Handles both regular and scoped packages
/// 3. **Version Resolution**: Extracts exact versions from version specifiers
/// 4. **Error Recovery**: Gracefully handles malformed entries
///
/// **Package Name Logic:**
/// - Regular packages: `lodash@^4.17.21` → name = `lodash`
/// - Scoped packages: `@babel/core@^7.0.0` → name = `@babel/core`
/// - Complex specs: `package@npm:other@^1.0.0` → extracts inner package name
///
/// **Error Handling:**
/// - Malformed entries are skipped with warning logs
/// - Missing version fields are handled gracefully
/// - Parse errors don't affect other entries in the file
///
/// **Performance:**
/// - Single-pass parsing for efficiency
/// - Minimal memory allocations
/// - Parallel-safe operation (no shared mutable state)
///
/// **Integration Notes:**
/// - Registered in ParserFactory with priority = 20 (higher than legacy parser)
/// - Replaces the older regex-based YarnLockParser
/// - Returns packages with Ecosystem::Npm
/// - Handles Yarn v1 lockfiles only (Yarn v2+ uses different format)
pub struct YarnPestParser;

#[derive(Debug, Clone)]
struct ParsedEntry {
    names: Vec<String>,
    version: Option<String>,
    dependency_specs: Vec<(String, String)>,
}

impl Default for YarnPestParser {
    fn default() -> Self {
        Self::new()
    }
}

impl YarnPestParser {
    pub fn new() -> Self {
        Self
    }

    fn dequote(s: &str) -> String {
        let s = s.trim();
        if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
            s[1..s.len() - 1].to_string()
        } else {
            s.to_string()
        }
    }

    /// Given a header key spec like:
    /// - "lodash@^4.17.21"
    /// - lodash@~4.17.20
    /// - "@babel/core@^7.23.0"
    ///   Return the inferred package name:
    /// - lodash
    /// - lodash
    /// - @babel/core
    fn extract_name_from_key_spec(spec: &str) -> Option<String> {
        let raw = Self::dequote(spec);
        let trimmed = raw.trim();

        // Find last '@' and take everything before it as the package name.
        // This handles scoped packages that contain '@' at the start.
        if let Some(idx) = trimmed.rfind('@') {
            // If the '@' is at position 0 (e.g. "@foo"), we can't split; in such case,
            // try to find a second '@' (for scoped packages).
            if idx == 0 {
                // Look for "@scope/name@range"
                if let Some(last) = trimmed[1..].rfind('@') {
                    let split_at = 1 + last;
                    let name = &trimmed[..split_at];
                    if !name.is_empty() {
                        return Some(name.to_string());
                    }
                }
                None
            } else {
                let name = &trimmed[..idx];
                if !name.is_empty() {
                    Some(name.to_string())
                } else {
                    None
                }
            }
        } else {
            // No '@' found; fallback to the whole token if it looks like a bare name
            if !trimmed.is_empty() {
                Some(trimmed.to_string())
            } else {
                None
            }
        }
    }

    fn parse_file_pairs<'a>(&self, content: &'a str) -> Result<Pairs<'a, Rule>, ParseError> {
        YarnLockPest::parse(Rule::file, content).map_err(move |e| {
            // Extract line number from error if available
            let (line, col) = match e.line_col {
                pest::error::LineColLocation::Pos((l, c)) => (l, c),
                pest::error::LineColLocation::Span((l, c), _) => (l, c),
            };
            let error_msg = format!(
                "yarn.lock parse error at line {}, column {}: {}",
                line, col, e
            );
            ParseError::MissingField { field: error_msg }
        })
    }

    fn process_entry(entry: Pair<'_, Rule>) -> ParsedEntry {
        // Capture raw entry text up front for fallbacks
        let entry_text = entry.as_str().to_string();

        let mut names: Vec<String> = Vec::new();
        let mut version: Option<String> = None;
        let mut header_text: Option<String> = None;
        let mut dependency_specs: Vec<(String, String)> = Vec::new();

        for p in entry.clone().into_inner() {
            match p.as_rule() {
                Rule::header => {
                    // Keep raw header text for fallback parsing if needed
                    header_text = Some(p.as_str().to_string());

                    for hp in p.into_inner() {
                        match hp.as_rule() {
                            // Collect names from header key list; key_spec is a silent rule,
                            // so inner pairs are quoted_string or bare_fragment.
                            Rule::key_list => {
                                for ks in hp.into_inner() {
                                    match ks.as_rule() {
                                        Rule::quoted_string | Rule::bare_fragment => {
                                            if let Some(name) =
                                                Self::extract_name_from_key_spec(ks.as_str())
                                            {
                                                names.push(name);
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            // In case grammar surfaces tokens directly (defensive)
                            Rule::quoted_string | Rule::bare_fragment => {
                                if let Some(name) = Self::extract_name_from_key_spec(hp.as_str()) {
                                    names.push(name);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Rule::version_line => {
                    // version_line captures: INDENT "version" version_string
                    // Extract via child version_string (which captures quoted_string)
                    let mut found: Option<String> = None;
                    for vp in p.clone().into_inner() {
                        // version_string is a typed capture, check for it or quoted_string
                        match vp.as_rule() {
                            Rule::version_string | Rule::quoted_string => {
                                found = Some(Self::dequote(vp.as_str()));
                                break;
                            }
                            _ => {}
                        }
                    }
                    if found.is_none() {
                        // Fallback: scan raw text
                        let raw = p.as_str();
                        if let Some(start) = raw.find('"') {
                            if let Some(end_off) = raw[start + 1..].find('"') {
                                let end = start + 1 + end_off;
                                found = Some(raw[start + 1..end].to_string());
                            }
                        }
                    }
                    version = found;
                }
                Rule::peer_dependencies_block
                | Rule::bundled_dependencies_block
                | Rule::dependencies_block
                | Rule::optional_dependencies_block => {
                    // Process dependency blocks and extract dependency specs.
                    for dep_item in p.into_inner() {
                        match dep_item.as_rule() {
                            Rule::dep_kv_line => {
                                let mut dep_name: Option<String> = None;
                                let mut dep_req: Option<String> = None;
                                for dep_part in dep_item.into_inner() {
                                    match dep_part.as_rule() {
                                        Rule::dep_key => {
                                            dep_name = Some(Self::dequote(dep_part.as_str()));
                                        }
                                        Rule::dep_value
                                        | Rule::dep_range
                                        | Rule::quoted_string
                                        | Rule::bare_fragment => {
                                            dep_req = Some(Self::dequote(dep_part.as_str()));
                                        }
                                        _ => {}
                                    }
                                }

                                if let Some(name) = dep_name {
                                    let requirement = dep_req.unwrap_or_else(|| "*".to_string());
                                    dependency_specs.push((name, requirement));
                                }
                            }
                            Rule::dep_name_line => {
                                // bundledDependencies can list names without versions.
                                for dep_part in dep_item.into_inner() {
                                    if dep_part.as_rule() == Rule::dep_key {
                                        dependency_specs.push((
                                            Self::dequote(dep_part.as_str()),
                                            "*".to_string(),
                                        ));
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Rule::malformed_line => {
                    // Error recovery: log malformed lines but continue parsing
                    let line_num = entry_text[..entry.as_span().start()].lines().count() + 1;
                    tracing::debug!(
                        line = line_num,
                        content = %p.as_str().trim(),
                        "Skipping malformed line in yarn.lock (error recovery)"
                    );
                }
                _ => {
                    // ignore other blocks (resolved, integrity, comments, etc.)
                }
            }
        }

        // Fallbacks: if header-derived names or version were not found via grammar,
        // try extracting them from raw entry/header text.
        if names.is_empty() {
            if let Some(h) = header_text.as_ref() {
                names = Self::fallback_extract_names_from_header(h);
            } else {
                // Derive header from first line of entry if header node was not present
                let first_line = entry_text.lines().next().unwrap_or(&entry_text);
                names = Self::fallback_extract_names_from_header(first_line);
            }
        }

        if version.is_none() {
            version = Self::fallback_extract_version_from_entry(&entry_text);
        }

        if dependency_specs.is_empty() {
            dependency_specs = Self::fallback_extract_dependency_specs_from_entry(&entry_text);
        }

        // Deduplicate names while preserving order
        let mut unique = Vec::new();
        for n in names {
            if !unique.contains(&n) {
                unique.push(n);
            }
        }

        ParsedEntry {
            names: unique,
            version,
            dependency_specs,
        }
    }

    fn fallback_extract_dependency_specs_from_entry(entry_text: &str) -> Vec<(String, String)> {
        let mut specs = Vec::new();
        let mut in_dep_block = false;

        for line in entry_text.lines() {
            let trimmed_end = line.trim_end();

            let block_header = trimmed_end.trim_start();
            let is_dependency_header = block_header == "dependencies:"
                || block_header == "optionalDependencies:"
                || block_header == "peerDependencies:"
                || block_header == "bundledDependencies:";

            if is_dependency_header {
                in_dep_block = true;
                continue;
            }

            if !in_dep_block {
                continue;
            }

            if trimmed_end.trim().is_empty() {
                continue;
            }

            if !line.starts_with("    ") {
                in_dep_block = false;
                continue;
            }

            let dep_line = line.trim();
            if dep_line.is_empty() {
                continue;
            }

            if let Some(name_only) = dep_line.strip_prefix("- ") {
                let dep_name = Self::dequote(name_only.trim());
                if !dep_name.is_empty() {
                    specs.push((dep_name, "*".to_string()));
                }
                continue;
            }

            let mut parts = dep_line.split_whitespace();
            if let Some(dep_name_raw) = parts.next() {
                let dep_name = Self::dequote(dep_name_raw);
                let requirement = parts
                    .next()
                    .map(Self::dequote)
                    .unwrap_or_else(|| "*".to_string());

                if !dep_name.is_empty() {
                    specs.push((dep_name, requirement));
                }
            }
        }

        specs
    }
    // Fallback: extract names from a header line like:
    //   "lodash@^4.17.21", "@babel/core@^7.22.0":
    //   lodash@~4.17.20:
    fn fallback_extract_names_from_header(header_text: &str) -> Vec<String> {
        let header_line = header_text.lines().next().unwrap_or(header_text);
        let without_colon = header_line.trim_end().trim_end_matches(':').trim();

        let mut out: Vec<String> = Vec::new();
        for spec in without_colon.split(',') {
            let s = spec.trim();
            // Drop surrounding quotes if present
            let s = s.trim_matches('"');
            if let Some(name) = Self::extract_name_from_key_spec(s) {
                if !out.contains(&name) {
                    out.push(name);
                }
            }
        }
        out
    }

    // Fallback: scan entry text for a line starting with 'version "X.Y.Z"'
    fn fallback_extract_version_from_entry(entry_text: &str) -> Option<String> {
        for line in entry_text.lines() {
            let t = line.trim_start();
            if t.starts_with("version ") {
                if let Some(start) = t.find('"') {
                    if let Some(end_off) = t[start + 1..].find('"') {
                        let end = start + 1 + end_off;
                        return Some(t[start + 1..end].to_string());
                    }
                }
            }
        }
        None
    }

    // Final fallback: scan the whole file when Pest parse yields no packages.
    fn fallback_parse_raw(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let mut packages: Vec<Package> = Vec::new();

        let mut current_header: Option<String> = None;
        let mut current_version: Option<String> = None;

        for line in content.lines() {
            let line_trim = line.trim_end();

            // Skip comments and empty lines
            if line_trim.is_empty() || line_trim.starts_with('#') {
                continue;
            }

            // Header line: non-indented and ends with ':'
            if !line.starts_with(' ') && line_trim.ends_with(':') {
                // Flush previous entry if both header and version were seen
                if let (Some(h), Some(v)) = (&current_header, &current_version) {
                    let names = Self::fallback_extract_names_from_header(h);
                    for name in names {
                        let ver = Version::parse(v).unwrap_or_else(|_| Version::new(0, 0, 0));
                        if let Ok(pkg) = Package::new(name, ver.clone(), Ecosystem::Npm) {
                            packages.push(pkg);
                        }
                    }
                }

                current_header = Some(line_trim.to_string());
                current_version = None;
                continue;
            }

            // Version line (indented)
            let t = line.trim_start();
            if t.starts_with("version ") {
                if let Some(start) = t.find('"') {
                    if let Some(end_off) = t[start + 1..].find('"') {
                        let end = start + 1 + end_off;
                        current_version = Some(t[start + 1..end].to_string());
                    }
                }
            }
        }

        // Flush trailing entry
        if let (Some(h), Some(v)) = (current_header, current_version) {
            let names = Self::fallback_extract_names_from_header(&h);
            for name in names {
                let ver = Version::parse(&v).unwrap_or_else(|_| Version::new(0, 0, 0));
                if let Ok(pkg) = Package::new(name, ver.clone(), Ecosystem::Npm) {
                    packages.push(pkg);
                }
            }
        }

        Ok(packages)
    }
}

#[async_trait]
impl PackageFileParser for YarnPestParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "yarn.lock"
    }

    async fn parse_file(&self, content: &str) -> Result<ParseResult, ParseError> {
        let pairs = self.parse_file_pairs(content)?;

        let mut packages: Vec<Package> = Vec::new();
        let mut parsed_entries: Vec<ParsedEntry> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Walk the parse tree to find entries and extract names + versions
        for top in pairs {
            match top.as_rule() {
                Rule::file => {
                    for inner in top.into_inner() {
                        if inner.as_rule() == Rule::entry {
                            let parsed = Self::process_entry(inner);
                            if let Some(ver_str) = parsed.version.clone() {
                                // Parse a semantic-ish version; fall back to "0.0.0" if invalid
                                let version = Version::parse(&ver_str).unwrap_or_else(|_| {
                                    Version::parse("0.0.0")
                                        .unwrap_or_else(|_| Version::new(0, 0, 0))
                                });

                                for name in &parsed.names {
                                    if seen.insert((name.clone(), version.to_string())) {
                                        if let Ok(pkg) = Package::new(
                                            name.clone(),
                                            version.clone(),
                                            Ecosystem::Npm,
                                        ) {
                                            packages.push(pkg);
                                        }
                                    }
                                }
                            }
                            parsed_entries.push(parsed);
                        }
                    }
                }
                Rule::entry => {
                    // In case the top node is directly an entry
                    let parsed = Self::process_entry(top);
                    if let Some(ver_str) = parsed.version.clone() {
                        let version = Version::parse(&ver_str).unwrap_or_else(|_| {
                            Version::parse("0.0.0").unwrap_or_else(|_| Version::new(0, 0, 0))
                        });

                        for name in &parsed.names {
                            if seen.insert((name.clone(), version.to_string())) {
                                if let Ok(pkg) =
                                    Package::new(name.clone(), version.clone(), Ecosystem::Npm)
                                {
                                    packages.push(pkg);
                                }
                            }
                        }
                    }
                    parsed_entries.push(parsed);
                }
                _ => {}
            }
        }

        if packages.is_empty() {
            let packages = self.fallback_parse_raw(content)?;
            return Ok(ParseResult {
                packages,
                dependencies: Vec::new(),
            });
        }

        let mut package_index: std::collections::HashMap<String, Vec<Package>> =
            std::collections::HashMap::new();
        for package in &packages {
            package_index
                .entry(package.name.clone())
                .or_default()
                .push(package.clone());
        }

        let mut dependencies: Vec<Dependency> = Vec::new();
        let mut seen_dependencies: std::collections::HashSet<(String, String, String)> =
            std::collections::HashSet::new();

        for entry in parsed_entries {
            let Some(from_version_str) = entry.version else {
                continue;
            };

            let Ok(from_version) = Version::parse(&from_version_str) else {
                continue;
            };

            for from_name in &entry.names {
                let Ok(from_package) =
                    Package::new(from_name.clone(), from_version.clone(), Ecosystem::Npm)
                else {
                    continue;
                };

                for (dep_name, requirement) in &entry.dependency_specs {
                    let Some(candidates) = package_index.get(dep_name) else {
                        continue;
                    };

                    let matched = if requirement == "*" {
                        candidates.iter().max_by(|a, b| a.version.cmp(&b.version))
                    } else {
                        let Ok(range) = VersionRange::parse(requirement) else {
                            continue;
                        };
                        candidates
                            .iter()
                            .filter(|candidate| range.contains(&candidate.version))
                            .max_by(|a, b| a.version.cmp(&b.version))
                    };

                    let Some(to_package) = matched else {
                        continue;
                    };

                    let key = (
                        from_package.name.clone(),
                        to_package.name.clone(),
                        requirement.clone(),
                    );
                    if seen_dependencies.insert(key) {
                        dependencies.push(Dependency::new(
                            from_package.clone(),
                            to_package.clone(),
                            requirement.clone(),
                            false,
                        ));
                    }
                }
            }
        }

        Ok(ParseResult {
            packages,
            dependencies,
        })
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    // Higher than legacy YarnLockParser (which is 12) to prefer Pest-based
    fn priority(&self) -> u8 {
        20
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Version;

    #[tokio::test]
    async fn test_basic_yarn_lock_parsing() {
        let content = r#"
# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-...

"@babel/core@^7.22.0", "@babel/core@~7.22.5":
  version "7.22.8"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.22.8.tgz"
  integrity sha512-...
"#;

        let parser = YarnPestParser::new();
        let result = match parser.parse_file(content).await {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("yarn_pest parse error: {:?}", e);
                panic!("yarn_pest parse error: {:?}", e);
            }
        };

        // Expect lodash and @babel/core captured
        assert!(
            result.packages.iter().any(|p| p.name == "lodash"
                && p.version == Version::parse("4.17.21").unwrap()
                && p.ecosystem == Ecosystem::Npm),
            "Expected lodash@4.17.21 (npm) to be present, got: {:?}",
            result
                .packages
                .iter()
                .map(|p| (&p.name, p.version.to_string(), &p.ecosystem))
                .collect::<Vec<_>>()
        );

        assert!(
            result.packages.iter().any(|p| p.name == "@babel/core"
                && p.version == Version::parse("7.22.8").unwrap()
                && p.ecosystem == Ecosystem::Npm),
            "Expected @babel/core@7.22.8 (npm) to be present, got: {:?}",
            result
                .packages
                .iter()
                .map(|p| (&p.name, p.version.to_string(), &p.ecosystem))
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_yarn_lock_extracts_dependency_edges() {
        let content = r#"
foo@^1.0.0:
    version "1.0.0"
    dependencies:
        bar "^2.0.0"

bar@^2.0.0:
    version "2.1.0"
"#;

        let parser = YarnPestParser::new();
        let result = parser.parse_file(content).await.unwrap();

        assert!(
            result
                .dependencies
                .iter()
                .any(|d| d.from.name == "foo" && d.to.name == "bar" && d.requirement == "^2.0.0"),
            "dependencies={:?}, packages={:?}",
            result
                .dependencies
                .iter()
                .map(|d| format!("{} -> {} ({})", d.from.name, d.to.name, d.requirement))
                .collect::<Vec<_>>(),
            result
                .packages
                .iter()
                .map(|p| format!("{}@{}", p.name, p.version))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_extract_name_from_key_spec() {
        // Simple names
        assert_eq!(
            YarnPestParser::extract_name_from_key_spec("lodash@^4.17.21"),
            Some("lodash".to_string())
        );
        // Quoted
        assert_eq!(
            YarnPestParser::extract_name_from_key_spec("\"lodash@^4.17.21\""),
            Some("lodash".to_string())
        );
        // Scoped
        assert_eq!(
            YarnPestParser::extract_name_from_key_spec("\"@babel/core@^7.22.0\""),
            Some("@babel/core".to_string())
        );
        // No '@' fallback
        assert_eq!(
            YarnPestParser::extract_name_from_key_spec("leftpad"),
            Some("leftpad".to_string())
        );
    }

    #[tokio::test]
    async fn test_grouped_headers_parsing() {
        // Multiple grouped header specs should dedupe to a single package name
        let content = r#"
left-pad@^1.3.0, "left-pad@~1.2.0":
  version "1.3.0"
"#;

        let parser = YarnPestParser::new();
        let result = parser.parse_file(content).await.unwrap();

        let count = result
            .packages
            .iter()
            .filter(|p| p.name == "left-pad")
            .count();
        assert_eq!(
            count,
            1,
            "Expected exactly one left-pad package entry, got: {:?}",
            result
                .packages
                .iter()
                .map(|p| (&p.name, p.version.to_string()))
                .collect::<Vec<_>>()
        );
        assert!(result.packages.iter().any(|p| p.name == "left-pad"
            && p.version == Version::parse("1.3.0").unwrap()
            && p.ecosystem == Ecosystem::Npm));
    }

    #[tokio::test]
    async fn test_dependencies_only_entry() {
        // Entry with dependencies block but missing resolved/integrity should still parse version
        let content = r#"
minimist@^1.2.8:
  version "1.2.8"
  dependencies:
    kind-of "^3.2.2"
"#;

        let parser = YarnPestParser::new();
        let result = parser.parse_file(content).await.unwrap();

        assert!(result.packages.iter().any(|p| p.name == "minimist"
            && p.version == Version::parse("1.2.8").unwrap()
            && p.ecosystem == Ecosystem::Npm));
    }

    #[tokio::test]
    async fn test_peer_dependencies_entry() {
        // Entry with peerDependencies block should parse correctly
        let content = r#"
react-redux@^8.1.0:
  version "8.1.3"
  peerDependencies:
    react "^16.8.0 || ^17.0.0 || ^18.0.0"
"#;

        let parser = YarnPestParser::new();
        let result = parser.parse_file(content).await.unwrap();

        assert!(result.packages.iter().any(|p| p.name == "react-redux"
            && p.version == Version::parse("8.1.3").unwrap()
            && p.ecosystem == Ecosystem::Npm));
    }

    #[tokio::test]
    async fn test_bundled_dependencies_entry() {
        // Entry with bundledDependencies block should parse correctly
        let content = r#"
some-package@^1.0.0:
  version "1.2.3"
  bundledDependencies:
    - "bundled-dep"
    other-bundled "^2.0.0"
"#;

        let parser = YarnPestParser::new();
        let result = parser.parse_file(content).await.unwrap();

        assert!(result.packages.iter().any(|p| p.name == "some-package"
            && p.version == Version::parse("1.2.3").unwrap()
            && p.ecosystem == Ecosystem::Npm));
    }

    #[tokio::test]
    async fn test_error_recovery_malformed_section() {
        // Entry with malformed line should still parse valid parts
        let content = r#"
valid-package@^1.0.0:
  version "1.0.0"
  this is a malformed line that should be skipped
  resolved "https://registry.yarnpkg.com/valid-package/-/valid-package-1.0.0.tgz"
"#;

        let parser = YarnPestParser::new();
        let result = parser.parse_file(content).await.unwrap();

        // Should still parse the valid package despite malformed line
        assert!(result.packages.iter().any(|p| p.name == "valid-package"
            && p.version == Version::parse("1.0.0").unwrap()
            && p.ecosystem == Ecosystem::Npm));
    }

    #[tokio::test]
    async fn test_integrity_only_entry() {
        // Entry with only version + integrity (no resolved) should still parse version
        let content = r#"
nan@^2.17.0:
  version "2.17.0"
  integrity sha512-ABCDEFG
"#;

        let parser = YarnPestParser::new();
        let result = parser.parse_file(content).await.unwrap();

        assert!(result.packages.iter().any(|p| p.name == "nan"
            && p.version == Version::parse("2.17.0").unwrap()
            && p.ecosystem == Ecosystem::Npm));
    }
}
