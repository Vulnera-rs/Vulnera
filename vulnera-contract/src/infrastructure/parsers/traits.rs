//! Traits for package file parsers

use crate::application::errors::ParseError;
use crate::domain::vulnerability::{
    entities::{Dependency, Package},
    value_objects::Ecosystem,
};
use async_trait::async_trait;

/// Result of parsing a package file
#[derive(Debug, Clone, Default)]
pub struct ParseResult {
    pub packages: Vec<Package>,
    pub dependencies: Vec<Dependency>,
}

/// Trait for parsing dependency files
#[async_trait]
pub trait PackageFileParser: Send + Sync {
    /// Check if this parser supports the given filename
    fn supports_file(&self, filename: &str) -> bool;

    /// Parse the file content and extract packages and dependencies
    async fn parse_file(&self, content: &str) -> Result<ParseResult, ParseError>;

    /// Get the ecosystem this parser handles
    fn ecosystem(&self) -> Ecosystem;

    /// Get the priority of this parser (higher numbers = higher priority)
    fn priority(&self) -> u8 {
        0
    }
}

/// Factory for creating appropriate parsers based on filename
pub struct ParserFactory {
    parsers: Vec<Box<dyn PackageFileParser>>,
    // Index for fast O(1) lookup of common filenames
    parser_index: std::collections::HashMap<String, usize>,
}

impl ParserFactory {
    /// Create a new parser factory with all available parsers
    pub fn new() -> Self {
        let mut parsers: Vec<Box<dyn PackageFileParser>> = vec![
            Box::new(crate::infrastructure::parsers::npm::NpmParser::new()),
            Box::new(crate::infrastructure::parsers::npm::PackageLockParser::new()),
            Box::new(crate::infrastructure::parsers::yarn_pest::YarnPestParser::new()),
            Box::new(crate::infrastructure::parsers::npm::YarnLockParser::new()),
            Box::new(crate::infrastructure::parsers::python::RequirementsTxtParser::new()),
            Box::new(crate::infrastructure::parsers::python::PipfileParser::new()),
            Box::new(crate::infrastructure::parsers::python::PyProjectTomlParser::new()),
            Box::new(crate::infrastructure::parsers::python_uv::UvLockParser::new()),
            Box::new(crate::infrastructure::parsers::java::MavenParser::new()),
            Box::new(crate::infrastructure::parsers::gradle_pest::GradlePestParser::new()),
            Box::new(crate::infrastructure::parsers::rust::CargoParser::new()),
            Box::new(crate::infrastructure::parsers::rust::CargoLockParser::new()),
            Box::new(crate::infrastructure::parsers::go::GoModParser::new()),
            Box::new(crate::infrastructure::parsers::go::GoSumParser::new()),
            Box::new(crate::infrastructure::parsers::php::ComposerParser::new()),
            Box::new(crate::infrastructure::parsers::php::ComposerLockParser::new()),
            Box::new(crate::infrastructure::parsers::nuget::NuGetPackagesConfigParser::new()),
            Box::new(crate::infrastructure::parsers::nuget::NuGetProjectXmlParser::new()),
            Box::new(crate::infrastructure::parsers::ruby::GemfileLockParser::new()),
            Box::new(crate::infrastructure::parsers::ruby::GemfileParser::new()),
        ];

        // Note: XML parsing uses the existing MavenParser (quick-xml based) which is more robust

        // Tree-sitter parsers (Lowered priority to prefer fallback parsers with edge extraction)
        // JSON parsers
        if let Ok(parser) =
            crate::infrastructure::parsers::tree_sitter::TreeSitterJsonPackageParser::new(
                crate::domain::vulnerability::value_objects::Ecosystem::Npm,
                "package.json".to_string(),
                0,
            )
        {
            parsers.push(Box::new(parser));
        }
        // Go parsers
        if let Ok(parser) =
            crate::infrastructure::parsers::tree_sitter::TreeSitterGoPackageParser::new(
                crate::domain::vulnerability::value_objects::Ecosystem::Go,
                "go.mod".to_string(),
                0,
            )
        {
            parsers.push(Box::new(parser));
        }

        // Build index for fast lookups of common exact filename matches
        let mut parser_index = std::collections::HashMap::new();
        let common_filenames = vec![
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "requirements.txt",
            "Pipfile",
            "pyproject.toml",
            "uv.lock",
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "Cargo.toml",
            "Cargo.lock",
            "go.mod",
            "go.sum",
            "composer.json",
            "composer.lock",
            "packages.config",
            "Gemfile",
            "Gemfile.lock",
        ];

        for filename in common_filenames {
            // Find the highest priority parser for this filename
            let mut best_parser_idx = None;
            let mut best_priority = 0u8;
            for (idx, parser) in parsers.iter().enumerate() {
                if parser.supports_file(filename) {
                    let priority = parser.priority();
                    if best_parser_idx.is_none() || priority > best_priority {
                        best_parser_idx = Some(idx);
                        best_priority = priority;
                    }
                }
            }
            if let Some(idx) = best_parser_idx {
                parser_index.insert(filename.to_string(), idx);
            }
        }

        Self {
            parsers,
            parser_index,
        }
    }

    /// Create a parser for the given filename
    /// Optimized with HashMap lookup for common filenames (O(1)), falls back to iteration for edge cases
    pub fn create_parser(&self, filename: &str) -> Option<&dyn PackageFileParser> {
        // Fast path: exact match in index
        if let Some(&idx) = self.parser_index.get(filename) {
            return Some(self.parsers[idx].as_ref());
        }

        // Fallback: iterate through all parsers (for less common filenames or path-based matching)
        let mut supporting_parsers: Vec<&dyn PackageFileParser> = self
            .parsers
            .iter()
            .filter(|parser| parser.supports_file(filename))
            .map(|parser| parser.as_ref())
            .collect();

        if supporting_parsers.is_empty() {
            return None;
        }

        // Sort by priority (highest first)
        supporting_parsers.sort_by_key(|p| std::cmp::Reverse(p.priority()));

        // Return the highest priority parser
        supporting_parsers.into_iter().next()
    }

    /// Detect ecosystem from filename
    pub fn detect_ecosystem(&self, filename: &str) -> Option<Ecosystem> {
        self.create_parser(filename)
            .map(|parser| parser.ecosystem())
    }

    /// Get all supported file extensions
    pub fn supported_extensions(&self) -> Vec<String> {
        let mut extensions = Vec::new();

        for ecosystem in Ecosystem::all() {
            extensions.extend(
                ecosystem
                    .file_extensions()
                    .iter()
                    .map(|ext| ext.to_string()),
            );
        }

        extensions.sort();
        extensions.dedup();
        extensions
    }

    /// Check if a filename is supported by any parser
    pub fn is_supported(&self, filename: &str) -> bool {
        self.parsers
            .iter()
            .any(|parser| parser.supports_file(filename))
    }
}

impl Default for ParserFactory {
    fn default() -> Self {
        Self::new()
    }
}
