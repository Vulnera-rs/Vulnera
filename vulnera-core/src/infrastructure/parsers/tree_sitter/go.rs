//! Tree-sitter based Go parser
//!
//! Used for parsing go.mod and go.sum files with precise source location tracking.

use crate::application::errors::ParseError;
use crate::domain::vulnerability::{entities::Package, value_objects::Ecosystem};
use crate::infrastructure::parsers::traits::PackageFileParser;
use async_trait::async_trait;
use tree_sitter::{Node, Tree};

use super::traits::{TreeSitterParser, create_parser_with_recovery, parse_with_error_recovery};

/// Tree-sitter based Go parser for go.mod files
pub struct TreeSitterGoParser {
    ecosystem: Ecosystem,
}

impl TreeSitterGoParser {
    pub fn new(ecosystem: Ecosystem) -> Result<Self, ParseError> {
        Ok(Self { ecosystem })
    }

    /// Extract dependencies from go.mod using tree-sitter AST
    fn extract_dependencies_from_ast(
        &self,
        tree: &Tree,
        content: &str,
    ) -> Result<Vec<Package>, ParseError> {
        let root = tree.root_node();
        let mut packages = Vec::new();

        // Find require blocks and require directives
        self.find_require_nodes(&root, content, &mut packages)?;

        Ok(packages)
    }

    /// Recursively find require nodes in the AST
    fn find_require_nodes<'a>(
        &self,
        node: &'a Node,
        content: &str,
        packages: &mut Vec<Package>,
    ) -> Result<(), ParseError> {
        let mut cursor = node.walk();

        for child in node.children(&mut cursor) {
            match child.kind() {
                "require_block" => {
                    // Multi-line require block: require ( ... )
                    packages.extend(self.parse_require_block(&child, content)?);
                }
                "require_directive" => {
                    // Single-line require: require module/path v1.2.3
                    if let Some(package) = self.parse_require_directive(&child, content)? {
                        packages.push(package);
                    }
                }
                _ => {
                    // Recursively search in other nodes
                    self.find_require_nodes(&child, content, packages)?;
                }
            }
        }

        Ok(())
    }

    /// Parse a require block (multi-line format)
    fn parse_require_block<'a>(
        &self,
        block_node: &'a Node,
        content: &str,
    ) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();
        let mut cursor = block_node.walk();

        for child in block_node.children(&mut cursor) {
            if child.kind() == "require_directive" {
                if let Some(package) = self.parse_require_directive(&child, content)? {
                    packages.push(package);
                }
            }
        }

        Ok(packages)
    }

    /// Parse a single require directive
    /// Format: require module/path v1.2.3 [// indirect]
    fn parse_require_directive<'a>(
        &self,
        directive_node: &'a Node,
        content: &str,
    ) -> Result<Option<Package>, ParseError> {
        // Tree-sitter-go structure:
        // require_directive -> module_path, version (optional), comment (optional)
        let mut module_path: Option<String> = None;
        let mut version: Option<String> = None;

        let mut cursor = directive_node.walk();
        for child in directive_node.children(&mut cursor) {
            match child.kind() {
                "module_path" => {
                    module_path = Some(content[child.byte_range()].trim().to_string());
                }
                "version" => {
                    version = Some(content[child.byte_range()].trim().to_string());
                }
                _ => {
                    // Skip comments and other nodes
                }
            }
        }

        // If we have a module_path, try to extract version from the directive text
        if let Some(name) = module_path {
            let version_str = if let Some(ver) = version {
                ver
            } else {
                // Fallback: try to extract version from the full directive text
                let directive_text = content[directive_node.byte_range()].trim();
                let parts: Vec<&str> = directive_text.split_whitespace().collect();
                if parts.len() >= 2 {
                    parts[1].to_string()
                } else {
                    return Ok(None); // No version found
                }
            };

            let clean_version = self.clean_go_version(&version_str);
            let version =
                crate::domain::vulnerability::value_objects::Version::parse(&clean_version)
                    .map_err(|_| ParseError::Version {
                        version: version_str.clone(),
                    })?;

            let package = Package::new(name, version, self.ecosystem.clone())
                .map_err(|e| ParseError::MissingField { field: e })?;

            Ok(Some(package))
        } else {
            Ok(None)
        }
    }

    /// Clean Go version string (remove 'v' prefix, handle pseudo-versions)
    fn clean_go_version(&self, version_str: &str) -> String {
        let version_str = version_str.trim();

        if version_str.is_empty() {
            return "0.0.0".to_string();
        }

        // Remove 'v' prefix if present
        let cleaned = if let Some(stripped) = version_str.strip_prefix('v') {
            stripped
        } else {
            version_str
        };

        // Handle pseudo-versions (e.g., v0.0.0-20210101000000-abcdef123456)
        if let Some(dash_pos) = cleaned.find('-') {
            let base_version = &cleaned[..dash_pos];
            // If it's a pseudo-version, use the base version
            if base_version.matches('.').count() >= 2 {
                return base_version.to_string();
            }
        }

        // Handle +incompatible suffix
        let cleaned = if let Some(stripped) = cleaned.strip_suffix("+incompatible") {
            stripped
        } else {
            cleaned
        };

        cleaned.to_string()
    }
}

impl TreeSitterParser for TreeSitterGoParser {
    fn language(&self) -> tree_sitter::Language {
        unsafe { std::mem::transmute(tree_sitter_go::LANGUAGE) }
    }

    fn parse_with_tree_sitter(
        &self,
        content: &str,
        tree: &Tree,
    ) -> Result<Vec<Package>, ParseError> {
        self.extract_dependencies_from_ast(tree, content)
    }
}

/// Wrapper that implements PackageFileParser for tree-sitter Go parser
pub struct TreeSitterGoPackageParser {
    inner: TreeSitterGoParser,
    filename: String,
    priority: u8,
}

impl TreeSitterGoPackageParser {
    pub fn new(ecosystem: Ecosystem, filename: String, priority: u8) -> Result<Self, ParseError> {
        Ok(Self {
            inner: TreeSitterGoParser::new(ecosystem)?,
            filename,
            priority,
        })
    }
}

#[async_trait]
impl PackageFileParser for TreeSitterGoPackageParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == self.filename
    }

    async fn parse_file(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        // Create a new parser for this parse (Parser doesn't implement Clone)
        // Note: This may fail due to version incompatibility between tree-sitter-go and tree-sitter
        // If it fails, the ParserFactory will fall back to the existing GoModParser
        let mut parser = match create_parser_with_recovery(self.inner.language()) {
            Ok(p) => p,
            Err(e) => {
                // Log the error but don't fail - let the fallback parser handle it
                tracing::debug!(
                    "Tree-sitter Go parser failed: {:?}, falling back to GoModParser",
                    e
                );
                return Err(e);
            }
        };
        let tree = parse_with_error_recovery(&mut parser, content, None)?;
        self.inner.parse_with_tree_sitter(content, &tree)
    }

    fn ecosystem(&self) -> Ecosystem {
        self.inner.ecosystem.clone()
    }

    fn priority(&self) -> u8 {
        self.priority
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_go_mod_parser() {
        let parser =
            TreeSitterGoPackageParser::new(Ecosystem::Go, "go.mod".to_string(), 15).unwrap();

        let content = r#"
module example.com/myproject

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/crypto v0.9.0
)

require github.com/stretchr/testify v1.7.1
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        assert_eq!(packages.len(), 3);

        let gin_pkg = packages
            .iter()
            .find(|p| p.name == "github.com/gin-gonic/gin")
            .expect("Should find gin package");
        assert_eq!(
            gin_pkg.version,
            crate::domain::vulnerability::value_objects::Version::parse("1.9.1").unwrap()
        );

        let crypto_pkg = packages
            .iter()
            .find(|p| p.name == "golang.org/x/crypto")
            .expect("Should find crypto package");
        assert_eq!(
            crypto_pkg.version,
            crate::domain::vulnerability::value_objects::Version::parse("0.9.0").unwrap()
        );

        let testify_pkg = packages
            .iter()
            .find(|p| p.name == "github.com/stretchr/testify")
            .expect("Should find testify package");
        assert_eq!(
            testify_pkg.version,
            crate::domain::vulnerability::value_objects::Version::parse("1.7.1").unwrap()
        );
    }

    #[tokio::test]
    async fn test_go_mod_parser_pseudo_versions() {
        let parser =
            TreeSitterGoPackageParser::new(Ecosystem::Go, "go.mod".to_string(), 15).unwrap();

        let content = r#"
module example.com/myproject

go 1.21

require (
    golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d
    github.com/example/pkg v2.0.0+incompatible
)
        "#;

        let packages = parser.parse_file(content).await.unwrap();
        assert_eq!(packages.len(), 2);

        let crypto_pkg = packages
            .iter()
            .find(|p| p.name == "golang.org/x/crypto")
            .expect("Should find crypto package");
        // Pseudo-versions should be cleaned to base version
        assert_eq!(
            crypto_pkg.version,
            crate::domain::vulnerability::value_objects::Version::parse("0.0.0").unwrap()
        );

        let pkg = packages
            .iter()
            .find(|p| p.name == "github.com/example/pkg")
            .expect("Should find example package");
        // +incompatible should be removed
        assert_eq!(
            pkg.version,
            crate::domain::vulnerability::value_objects::Version::parse("2.0.0").unwrap()
        );
    }
}
