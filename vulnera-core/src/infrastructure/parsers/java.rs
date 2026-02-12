//! Java ecosystem parsers

use super::traits::{PackageFileParser, ParseResult};
use crate::application::errors::ParseError;
use crate::domain::vulnerability::{
    entities::Package,
    value_objects::{Ecosystem, Version},
};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use quick_xml::Reader;
use quick_xml::events::Event;
use regex::Regex;

/// Parser for Maven pom.xml files
pub struct MavenParser;

impl Default for MavenParser {
    fn default() -> Self {
        Self::new()
    }
}

impl MavenParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract dependencies from XML content using quick-xml
    fn extract_maven_dependencies(
        &self,
        content: &str,
        root_package: &Package,
    ) -> Result<ParseResult, ParseError> {
        let mut packages = Vec::new();
        let mut dependencies = Vec::new();

        let mut reader = Reader::from_str(content);

        let mut buf = Vec::new();
        let mut in_dependency = false;
        let mut current_tag: Option<String> = None;

        let mut group_id: Option<String> = None;
        let mut artifact_id: Option<String> = None;
        let mut version_str: Option<String> = None;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if name == "dependency" {
                        in_dependency = true;
                        group_id = None;
                        artifact_id = None;
                        version_str = None;
                        current_tag = None;
                    } else if in_dependency {
                        current_tag = Some(name);
                    }
                }
                Ok(Event::End(e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if name == "dependency" && in_dependency {
                        // finalize this dependency
                        if let (Some(g), Some(a)) = (group_id.as_ref(), artifact_id.as_ref()) {
                            let pkg_name = format!("{}:{}", g, a);
                            // Clean version
                            let cleaned = self
                                .clean_maven_version(version_str.as_deref().unwrap_or("0.0.0"))?;
                            let version =
                                Version::parse(&cleaned).map_err(|_| ParseError::Version {
                                    version: version_str.clone().unwrap_or_default(),
                                })?;
                            let package = Package::new(pkg_name, version, Ecosystem::Maven)
                                .map_err(|e| ParseError::MissingField { field: e })?;
                            packages.push(package.clone());

                            // Create dependency edge from root
                            dependencies.push(
                                crate::domain::vulnerability::entities::Dependency::new(
                                    root_package.clone(),
                                    package,
                                    version_str.clone().unwrap_or_else(|| "0.0.0".to_string()),
                                    false, // Direct dependency from manifest
                                ),
                            );
                        }
                        in_dependency = false;
                        current_tag = None;
                    } else if in_dependency {
                        current_tag = None;
                    }
                }
                Ok(Event::Text(t)) => {
                    if in_dependency {
                        if let Some(tag) = current_tag.as_deref() {
                            let txt = reader
                                .decoder()
                                .decode(t.as_ref())
                                .unwrap_or_default()
                                .trim()
                                .to_string();
                            match tag {
                                "groupId" => group_id = Some(txt.trim().to_string()),
                                "artifactId" => artifact_id = Some(txt.trim().to_string()),
                                "version" => version_str = Some(txt.trim().to_string()),
                                _ => {}
                            }
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(ParseError::MissingField {
                        field: format!("XML parse error: {}", e),
                    });
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(ParseResult {
            packages,
            dependencies,
        })
    }

    /// Extract root package information from pom.xml
    fn extract_root_package(&self, content: &str) -> Result<Package, ParseError> {
        let mut reader = Reader::from_str(content);
        let mut buf = Vec::new();
        let mut depth = 0;

        let mut group_id: Option<String> = None;
        let mut artifact_id: Option<String> = None;
        let mut version: Option<String> = None;

        let mut parent_group_id: Option<String> = None;
        let mut parent_version: Option<String> = None;

        let mut current_tag: Option<String> = None;
        let mut in_parent = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    depth += 1;
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if depth == 2 {
                        if name == "parent" {
                            in_parent = true;
                        }
                        current_tag = Some(name);
                    } else if depth == 3 && in_parent {
                        current_tag = Some(name);
                    }
                }
                Ok(Event::End(_)) => {
                    depth -= 1;
                    current_tag = None;
                    if depth == 1 {
                        in_parent = false;
                    }
                }
                Ok(Event::Text(t)) => {
                    if let Some(tag) = current_tag.as_deref() {
                        let txt = reader
                            .decoder()
                            .decode(t.as_ref())
                            .unwrap_or_default()
                            .trim()
                            .to_string();
                        if !txt.is_empty() {
                            match tag {
                                "groupId" if !in_parent => group_id = Some(txt),
                                "artifactId" if !in_parent => artifact_id = Some(txt),
                                "version" if !in_parent => version = Some(txt),
                                "groupId" if in_parent => parent_group_id = Some(txt),
                                "version" if in_parent => parent_version = Some(txt),
                                _ => {}
                            }
                        }
                    }
                }
                Ok(Event::Eof) => break,
                _ => {}
            }
            buf.clear();
            if depth > 3 {
                continue;
            }
        }

        let g = group_id
            .or(parent_group_id)
            .unwrap_or_else(|| "unknown".to_string());
        let a = artifact_id.unwrap_or_else(|| "root".to_string());
        let v_str = version
            .or(parent_version)
            .unwrap_or_else(|| "0.0.0".to_string());
        let cleaned_v = self.clean_maven_version(&v_str)?;
        let v = Version::parse(&cleaned_v).unwrap_or_else(|_| Version::new(0, 0, 0));

        Package::new(format!("{}:{}", g, a), v, Ecosystem::Maven)
            .map_err(|e| ParseError::MissingField { field: e })
    }

    /// Clean Maven version string
    fn clean_maven_version(&self, version_str: &str) -> Result<String, ParseError> {
        let version_str = version_str.trim();

        if version_str.is_empty() {
            return Ok("0.0.0".to_string());
        }

        // Handle Maven property placeholders with common defaults
        if version_str.starts_with("${") && version_str.ends_with('}') {
            let property = &version_str[2..version_str.len() - 1];
            return Ok(match property {
                "project.version" | "version" => "1.0.0".to_string(),
                "java.version" => "11".to_string(),
                "maven.compiler.source" | "maven.compiler.target" => "11".to_string(),
                "spring.version" => "5.3.0".to_string(),
                "junit.version" => "5.8.0".to_string(),
                "slf4j.version" => "1.7.36".to_string(),
                "jackson.version" => "2.13.0".to_string(),
                _ => {
                    tracing::debug!(
                        "Unresolved Maven property: {}, using default 1.0.0",
                        property
                    );
                    "1.0.0".to_string()
                }
            });
        }

        // Handle version ranges (take the first version)
        if version_str.starts_with('[') || version_str.starts_with('(') {
            // Extract first version from range like "[1.0,2.0)" or "(1.0,2.0]"
            let range_content = &version_str[1..version_str.len() - 1];
            if let Some(comma_pos) = range_content.find(',') {
                let first_version = range_content[..comma_pos].trim();
                return Ok(first_version.to_string());
            }
        }

        Ok(version_str.to_string())
    }
}

#[async_trait]
impl PackageFileParser for MavenParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "pom.xml"
    }

    async fn parse_file(&self, content: &str) -> Result<ParseResult, ParseError> {
        let root_package = self.extract_root_package(content)?;
        self.extract_maven_dependencies(content, &root_package)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Maven
    }

    fn priority(&self) -> u8 {
        10 // High priority for pom.xml
    }
}

/// Parser for Gradle build files
pub struct GradleParser;

impl Default for GradleParser {
    fn default() -> Self {
        Self::new()
    }
}

impl GradleParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract dependencies from Gradle build file
    fn extract_gradle_dependencies(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        // Regex patterns for different Gradle dependency formats
        static RE_GRADLE_COORD: Lazy<Regex> = Lazy::new(|| {
            // implementation 'group:artifact:version'
            Regex::new(r#"(?:implementation|compile|api|testImplementation|testCompile)\s+['"]([^:]+):([^:]+):([^'"]+)['"]"#).unwrap()
        });

        static RE_GRADLE_NAMED: Lazy<Regex> = Lazy::new(|| {
            // implementation group: 'group', name: 'artifact', version: 'version'
            Regex::new(r#"(?:implementation|compile|api|testImplementation|testCompile)\s+group:\s*['"]([^'"]+)['"],\s*name:\s*['"]([^'"]+)['"],\s*version:\s*['"]([^'"]+)['"]"#).unwrap()
        });

        let dependency_patterns = [&*RE_GRADLE_COORD, &*RE_GRADLE_NAMED];

        for pattern in dependency_patterns {
            for captures in pattern.captures_iter(content) {
                let group_id = captures.get(1).map(|m| m.as_str().trim()).unwrap_or("");
                let artifact_id = captures.get(2).map(|m| m.as_str().trim()).unwrap_or("");
                let version_str = captures
                    .get(3)
                    .map(|m| m.as_str().trim())
                    .unwrap_or("0.0.0");

                if !group_id.is_empty() && !artifact_id.is_empty() {
                    let package_name = format!("{}:{}", group_id, artifact_id);

                    // Clean version string
                    let clean_version = self.clean_gradle_version(version_str)?;

                    let version =
                        Version::parse(&clean_version).map_err(|_| ParseError::Version {
                            version: version_str.to_string(),
                        })?;

                    let package = Package::new(package_name, version, Ecosystem::Maven)
                        .map_err(|e| ParseError::MissingField { field: e })?;

                    packages.push(package);
                }
            }
        }

        Ok(packages)
    }

    /// Clean Gradle version string
    fn clean_gradle_version(&self, version_str: &str) -> Result<String, ParseError> {
        let version_str = version_str.trim();

        if version_str.is_empty() {
            return Ok("0.0.0".to_string());
        }

        // Handle Gradle version catalogs and property references
        if version_str.starts_with("$") || version_str.contains("${") {
            return Ok("1.0.0".to_string());
        }

        // Handle dynamic selectors used by Gradle/Maven metadata
        if matches!(
            version_str.to_ascii_lowercase().as_str(),
            "latest.release" | "latest.integration" | "release" | "latest"
        ) {
            return Ok("1.0.0".to_string());
        }

        // Handle version ranges like [1.2,2.0), (1.0,], [1.0,)
        if (version_str.starts_with('[') || version_str.starts_with('('))
            && (version_str.ends_with(']') || version_str.ends_with(')'))
            && version_str.contains(',')
        {
            let inner = &version_str[1..version_str.len() - 1];
            let mut parts = inner.split(',').map(str::trim);
            let lower = parts.next().unwrap_or_default();
            let upper = parts.next().unwrap_or_default();

            let chosen = if !lower.is_empty() { lower } else { upper };
            if !chosen.is_empty() {
                return Ok(chosen.to_string());
            }
        }

        // Handle dynamic versions like "1.+", "1.2.+"
        if version_str.ends_with('+') {
            let mut parts: Vec<&str> = version_str.trim_end_matches('+').split('.').collect();
            if matches!(parts.last(), Some(last) if last.is_empty()) {
                parts.pop();
            }

            while parts.len() < 3 {
                parts.push("0");
            }

            return Ok(parts[..3].join("."));
        }

        // Handle classifier suffixes like "-jre", "-android", etc.
        if let Some(dash_pos) = version_str.find('-') {
            let base_version = &version_str[..dash_pos];
            // Only keep the base if it looks like a version
            if base_version.matches('.').count() >= 1 {
                return Ok(base_version.to_string());
            }
        }

        Ok(version_str.to_string())
    }
}

#[async_trait]
impl PackageFileParser for GradleParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == "build.gradle" || filename == "build.gradle.kts"
    }

    async fn parse_file(&self, content: &str) -> Result<ParseResult, ParseError> {
        let packages = self.extract_gradle_dependencies(content)?;
        Ok(ParseResult {
            packages,
            dependencies: Vec::new(),
        })
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Maven
    }

    fn priority(&self) -> u8 {
        8 // Medium priority for Gradle files
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_maven_parser() {
        let parser = MavenParser::new();
        let content = r#"
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.21</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
        "#;

        let result = parser.parse_file(content).await.unwrap();
        assert_eq!(result.packages.len(), 2);

        let spring_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "org.springframework:spring-core")
            .unwrap();
        assert_eq!(spring_pkg.version, Version::parse("5.3.21").unwrap());
        assert_eq!(spring_pkg.ecosystem, Ecosystem::Maven);
    }

    #[tokio::test]
    async fn test_gradle_parser() {
        let parser = GradleParser::new();
        let content = r#"
dependencies {
    implementation 'org.springframework:spring-core:5.3.21'
    testImplementation 'junit:junit:4.13.2'
    api group: 'com.google.guava', name: 'guava', version: '31.1-jre'
    compile 'org.apache.commons:commons-lang3:3.12.0'
}
        "#;

        let result = parser.parse_file(content).await.unwrap();
        assert_eq!(result.packages.len(), 4);

        let spring_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "org.springframework:spring-core")
            .unwrap();
        assert_eq!(spring_pkg.version, Version::parse("5.3.21").unwrap());

        let guava_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "com.google.guava:guava")
            .unwrap();
        assert_eq!(guava_pkg.version, Version::parse("31.1").unwrap()); // -jre suffix handled
    }

    #[test]
    fn test_clean_maven_version() {
        let parser = MavenParser::new();

        assert_eq!(parser.clean_maven_version("5.3.21").unwrap(), "5.3.21");
        // Updated expectation: ${spring.version} now returns "5.3.0" as a reasonable default
        assert_eq!(
            parser.clean_maven_version("${spring.version}").unwrap(),
            "5.3.0"
        );
        assert_eq!(parser.clean_maven_version("[1.0,2.0)").unwrap(), "1.0");
        assert_eq!(parser.clean_maven_version("(1.0,2.0]").unwrap(), "1.0");
        // Test that unknown properties default to "1.0.0" instead of "0.0.0"
        assert_eq!(
            parser.clean_maven_version("${unknown.property}").unwrap(),
            "1.0.0"
        );
    }

    #[test]
    fn test_clean_gradle_version() {
        let parser = GradleParser::new();

        assert_eq!(parser.clean_gradle_version("5.3.21").unwrap(), "5.3.21");
        assert_eq!(
            parser.clean_gradle_version("$springVersion").unwrap(),
            "1.0.0"
        );
        assert_eq!(parser.clean_gradle_version("1.+").unwrap(), "1.0.0");
        assert_eq!(parser.clean_gradle_version("1.2.+").unwrap(), "1.2.0");
        assert_eq!(parser.clean_gradle_version("[1.2,2.0)").unwrap(), "1.2");
        assert_eq!(parser.clean_gradle_version("(,2.0]").unwrap(), "2.0");
        assert_eq!(parser.clean_gradle_version("latest.release").unwrap(), "1.0.0");
    }

    #[test]
    fn test_parser_supports_file() {
        let maven_parser = MavenParser::new();
        let gradle_parser = GradleParser::new();

        assert!(maven_parser.supports_file("pom.xml"));
        assert!(!maven_parser.supports_file("build.gradle"));

        assert!(gradle_parser.supports_file("build.gradle"));
        assert!(gradle_parser.supports_file("build.gradle.kts"));
        assert!(!gradle_parser.supports_file("pom.xml"));
    }
}
