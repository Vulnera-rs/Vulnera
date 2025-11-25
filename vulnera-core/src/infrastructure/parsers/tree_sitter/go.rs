//! Tree-sitter based Go parser
//!
//! Used for parsing go.mod and go.sum files with precise source location tracking.

use crate::application::errors::ParseError;
use crate::domain::vulnerability::{entities::Package, value_objects::Ecosystem};
use crate::infrastructure::parsers::traits::{PackageFileParser, ParseResult};
use async_trait::async_trait;
use tree_sitter::{Node, Tree};

use super::traits::TreeSitterParser;

/// Tree-sitter based Go parser for go.mod files
pub struct TreeSitterGoParser {
    ecosystem: Ecosystem,
}

impl TreeSitterGoParser {
    pub fn new(ecosystem: Ecosystem) -> Result<Self, ParseError> {
        Ok(Self { ecosystem })
    }

    /// Parse go.mod file using text-based parsing (fallback since tree-sitter-go is for Go source, not go.mod)
    fn parse_go_mod_text(&self, content: &str) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();
        let mut in_require_block = false;

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with("//") {
                continue;
            }

            // Handle require block
            if line.starts_with("require (") {
                in_require_block = true;
                continue;
            } else if line == ")" && in_require_block {
                in_require_block = false;
                continue;
            }

            // Parse require statements
            if line.starts_with("require ") || in_require_block {
                if let Some(package) = self.parse_require_line(line)? {
                    packages.push(package);
                }
            }
        }

        Ok(packages)
    }

    /// Parse a single require line
    fn parse_require_line(&self, line: &str) -> Result<Option<Package>, ParseError> {
        let line = line.trim();

        // Remove "require " prefix if present
        let line = if let Some(stripped) = line.strip_prefix("require ") {
            stripped
        } else {
            line
        };

        // Skip lines that don't look like dependencies
        if line.is_empty() || line.starts_with("//") || line == "(" || line == ")" {
            return Ok(None);
        }

        // Parse module path and version
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return Ok(None);
        }

        let module_path = parts[0];
        let version_str = parts[1];

        // Clean version string
        let clean_version = self.clean_go_version(version_str);

        let version = crate::domain::vulnerability::value_objects::Version::parse(&clean_version)
            .map_err(|_| ParseError::Version {
            version: version_str.to_string(),
        })?;

        let package = Package::new(module_path.to_string(), version, self.ecosystem.clone())
            .map_err(|e| ParseError::MissingField { field: e })?;

        Ok(Some(package))
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
    fn find_require_nodes(
        &self,
        node: &Node,
        content: &str,
        packages: &mut Vec<Package>,
    ) -> Result<(), ParseError> {
        let mut cursor = node.walk();

        for child in node.children(&mut cursor) {
            let kind = child.kind();
            match kind {
                "require_block" | "require" if child.child_count() > 1 => {
                    // Multi-line require block: require ( ... )
                    // Also handle "require" nodes that contain multiple children
                    packages.extend(self.parse_require_block(&child, content)?);
                }
                "require_directive" | "require" => {
                    // Single-line require: require module/path v1.2.3
                    // tree-sitter-go uses "require" as the node type
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
    fn parse_require_block(
        &self,
        block_node: &Node,
        content: &str,
    ) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();
        let mut cursor = block_node.walk();

        for child in block_node.children(&mut cursor) {
            let kind = child.kind();
            // tree-sitter-go uses "require" for both single and multi-line requires
            // In a block, each line is a "require" node
            if kind == "require_directive" || kind == "require" {
                if let Some(package) = self.parse_require_directive(&child, content)? {
                    packages.push(package);
                }
            } else {
                // Also recursively search in case the structure is nested
                self.find_require_nodes(&child, content, &mut packages)?;
            }
        }

        Ok(packages)
    }

    /// Parse a single require directive
    /// Format: require module/path v1.2.3 [// indirect]
    fn parse_require_directive(
        &self,
        directive_node: &Node,
        content: &str,
    ) -> Result<Option<Package>, ParseError> {
        // Tree-sitter-go structure can vary:
        // - require_directive -> module_path, version (optional), comment (optional)
        // - require -> module_path, version (optional)
        // - Or the module_path and version might be direct children or in a different structure
        let mut module_path: Option<String> = None;
        let mut version: Option<String> = None;

        let mut cursor = directive_node.walk();
        for child in directive_node.children(&mut cursor) {
            match child.kind() {
                "module_path" | "module_identifier" => {
                    module_path = Some(content[child.byte_range()].trim().to_string());
                }
                "version" | "string" => {
                    // Version might be a string node or version node
                    let text = content[child.byte_range()].trim();
                    // Check if it looks like a version (starts with v or is a version number)
                    if text.starts_with('v')
                        || text.chars().next().is_some_and(|c| c.is_ascii_digit())
                    {
                        version = Some(text.to_string());
                    }
                }
                _ => {
                    // Skip comments and other nodes, but also check if it's a module path or version
                    // by examining the text content
                    let text = content[child.byte_range()].trim();
                    if !text.is_empty() && !text.starts_with("//") {
                        // If it looks like a module path (contains / or .)
                        if (text.contains('/') || text.contains('.')) && module_path.is_none() {
                            module_path = Some(text.to_string());
                        }
                        // If it looks like a version (starts with v or is a version number)
                        else if (text.starts_with('v')
                            || text.chars().next().is_some_and(|c| c.is_ascii_digit()))
                            && version.is_none()
                        {
                            version = Some(text.to_string());
                        }
                    }
                }
            }
        }

        // Fallback: if we don't have module_path or version, try parsing the full directive text
        if module_path.is_none() || version.is_none() {
            let directive_text = content[directive_node.byte_range()].trim();
            // Remove "require" keyword if present
            let text = directive_text
                .strip_prefix("require")
                .unwrap_or(directive_text)
                .trim();
            let parts: Vec<&str> = text.split_whitespace().collect();

            if parts.len() >= 2 {
                if module_path.is_none() {
                    module_path = Some(parts[0].to_string());
                }
                if version.is_none() {
                    version = Some(parts[1].to_string());
                }
            } else if parts.len() == 1 && module_path.is_none() {
                // Single part might be the module path
                module_path = Some(parts[0].to_string());
            }
        }

        // If we have a module_path, try to extract version
        if let Some(name) = module_path {
            let version_str = if let Some(ver) = version {
                ver
            } else {
                return Ok(None); // No version found
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
        tree_sitter_go::LANGUAGE.into()
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

    async fn parse_file(&self, content: &str) -> Result<ParseResult, ParseError> {
        // Note: tree-sitter-go is for parsing Go source code, not go.mod files.
        // Since go.mod files have a different syntax, we fall back to text-based parsing.
        // This parser exists for potential future use with a go.mod-specific tree-sitter grammar.
        let packages = self.inner.parse_go_mod_text(content)?;
        Ok(ParseResult {
            packages,
            dependencies: Vec::new(),
        })
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

        let result = parser.parse_file(content).await.unwrap();
        assert_eq!(result.packages.len(), 3);

        let gin_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "github.com/gin-gonic/gin")
            .expect("Should find gin package");
        assert_eq!(
            gin_pkg.version,
            crate::domain::vulnerability::value_objects::Version::parse("1.9.1").unwrap()
        );

        let crypto_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "golang.org/x/crypto")
            .expect("Should find crypto package");
        assert_eq!(
            crypto_pkg.version,
            crate::domain::vulnerability::value_objects::Version::parse("0.9.0").unwrap()
        );

        let testify_pkg = result
            .packages
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

        let result = parser.parse_file(content).await.unwrap();
        assert_eq!(result.packages.len(), 2);

        let crypto_pkg = result
            .packages
            .iter()
            .find(|p| p.name == "golang.org/x/crypto")
            .expect("Should find crypto package");
        // Pseudo-versions should be cleaned to base version
        assert_eq!(
            crypto_pkg.version,
            crate::domain::vulnerability::value_objects::Version::parse("0.0.0").unwrap()
        );

        let pkg = result
            .packages
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
