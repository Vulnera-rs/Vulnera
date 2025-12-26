//! Tree-sitter based JSON parser
//!
//! Used for parsing package.json, composer.json, and other JSON-based dependency files.

use crate::application::errors::ParseError;
use crate::domain::vulnerability::{entities::Package, value_objects::Ecosystem};
use crate::infrastructure::parsers::traits::{PackageFileParser, ParseResult};
use async_trait::async_trait;
use tree_sitter::{Node, Tree};

use super::traits::{TreeSitterParser, create_parser_with_recovery, parse_with_error_recovery};

/// Tree-sitter based JSON parser for package.json files
pub struct TreeSitterJsonParser {
    ecosystem: Ecosystem,
}

impl TreeSitterJsonParser {
    pub fn new(ecosystem: Ecosystem) -> Result<Self, ParseError> {
        Ok(Self { ecosystem })
    }

    /// Extract dependencies from JSON object using tree-sitter AST
    fn extract_dependencies_from_ast(
        &self,
        tree: &Tree,
        content: &str,
        dep_type: &str,
    ) -> Result<Vec<Package>, ParseError> {
        let root = tree.root_node();
        let mut packages = Vec::new();

        // Navigate to the dependencies object using iterative search
        if let Some(deps_node) = self.find_dependencies_node_iterative(&root, content, dep_type) {
            packages.extend(self.parse_dependencies_object(&deps_node, content)?);
        }

        Ok(packages)
    }

    /// Find the dependencies node in the AST using iterative search (avoids lifetime issues)
    fn find_dependencies_node_iterative<'a>(
        &self,
        root: &'a Node,
        content: &str,
        dep_type: &str,
    ) -> Option<Node<'a>> {
        // Use a stack-based iterative approach to avoid lifetime issues with recursion
        let mut stack = vec![*root];

        while let Some(node) = stack.pop() {
            // Check if this is a pair node with the target key
            if node.kind() == "pair" {
                if let Some(key_node) = node.child_by_field_name("key") {
                    let key_text = &content[key_node.byte_range()];
                    if key_text.trim_matches('"') == dep_type {
                        if let Some(value_node) = node.child_by_field_name("value") {
                            if value_node.kind() == "object" {
                                return Some(value_node);
                            }
                        }
                    }
                }
            }

            // Add children to stack for processing
            let child_count = node.child_count();
            for i in 0..child_count {
                if let Some(child) = node.child(i as u32) {
                    stack.push(child);
                }
            }
        }

        None
    }

    /// Parse a dependencies object node
    fn parse_dependencies_object(
        &self,
        object_node: &Node,
        content: &str,
    ) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();
        let mut cursor = object_node.walk();

        for child in object_node.children(&mut cursor) {
            if child.kind() == "pair" {
                if let Some(package) = self.parse_dependency_pair(&child, content)? {
                    packages.push(package);
                }
            }
        }

        Ok(packages)
    }

    /// Parse a single dependency pair (name: version)
    fn parse_dependency_pair(
        &self,
        pair_node: &Node,
        content: &str,
    ) -> Result<Option<Package>, ParseError> {
        let key_node =
            pair_node
                .child_by_field_name("key")
                .ok_or_else(|| ParseError::MissingField {
                    field: "dependency key".to_string(),
                })?;

        let value_node =
            pair_node
                .child_by_field_name("value")
                .ok_or_else(|| ParseError::MissingField {
                    field: "dependency value".to_string(),
                })?;

        // Extract name from key node (handle both string and identifier)
        let name = match key_node.kind() {
            "string" => content[key_node.byte_range()].trim_matches('"').to_string(),
            _ => content[key_node.byte_range()].trim().to_string(),
        };

        // Extract version from value node
        let version_str = match value_node.kind() {
            "string" => {
                let raw = &content[value_node.byte_range()];
                // Remove quotes, handling escaped quotes
                raw.trim_matches('"').to_string()
            }
            _ => {
                // For non-string values, try to extract as-is
                content[value_node.byte_range()].trim().to_string()
            }
        };

        // Skip empty names or versions
        if name.is_empty() || version_str.is_empty() {
            return Ok(None);
        }

        // Clean version string (remove npm-specific prefixes)
        let clean_version = self.clean_version_string(&version_str)?;

        let version = crate::domain::vulnerability::value_objects::Version::parse(&clean_version)
            .map_err(|_| ParseError::Version {
            version: version_str.clone(),
        })?;

        let package = Package::new(name, version, self.ecosystem.clone())
            .map_err(|e| ParseError::MissingField { field: e })?;

        Ok(Some(package))
    }

    /// Clean version string by removing prefixes
    fn clean_version_string(&self, version_str: &str) -> Result<String, ParseError> {
        let version_str = version_str.trim();

        if version_str.is_empty() || version_str == "*" || version_str == "latest" {
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

        Ok(cleaned.trim().to_string())
    }
}

impl TreeSitterParser for TreeSitterJsonParser {
    fn language(&self) -> tree_sitter::Language {
        tree_sitter_json::LANGUAGE.into()
    }

    fn parse_with_tree_sitter(
        &self,
        content: &str,
        tree: &Tree,
    ) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();

        // Extract from different dependency types
        for dep_type in &[
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ] {
            packages.extend(self.extract_dependencies_from_ast(tree, content, dep_type)?);
        }

        Ok(packages)
    }
}

/// Wrapper that implements PackageFileParser for tree-sitter JSON parser
pub struct TreeSitterJsonPackageParser {
    inner: TreeSitterJsonParser,
    filename: String,
    priority: u8,
}

impl TreeSitterJsonPackageParser {
    pub fn new(ecosystem: Ecosystem, filename: String, priority: u8) -> Result<Self, ParseError> {
        Ok(Self {
            inner: TreeSitterJsonParser::new(ecosystem)?,
            filename,
            priority,
        })
    }
}

#[async_trait]
impl PackageFileParser for TreeSitterJsonPackageParser {
    fn supports_file(&self, filename: &str) -> bool {
        filename == self.filename
    }

    async fn parse_file(&self, content: &str) -> Result<ParseResult, ParseError> {
        // Create a new parser for this parse (Parser doesn't implement Clone)
        let mut parser = create_parser_with_recovery(self.inner.language())?;
        let tree = parse_with_error_recovery(&mut parser, content, None)?;
        let packages = self.inner.parse_with_tree_sitter(content, &tree)?;
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
    async fn test_package_json_parser() {
        let parser =
            TreeSitterJsonPackageParser::new(Ecosystem::Npm, "package.json".to_string(), 25)
                .unwrap();

        let content = r#"
{
  "name": "test-package",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "~4.17.21",
    "axios": "1.0.0"
  },
  "devDependencies": {
    "typescript": ">=4.9.0",
    "jest": "latest"
  },
  "peerDependencies": {
    "react": "18.0.0"
  }
}
        "#;

        let result = parser.parse_file(content).await.unwrap();
        assert_eq!(result.packages.len(), 6);

        // Check dependencies
        let express = result
            .packages
            .iter()
            .find(|p| p.name == "express")
            .expect("Should find express");
        assert_eq!(
            express.version,
            crate::domain::vulnerability::value_objects::Version::parse("4.18.0").unwrap()
        );

        let lodash = result
            .packages
            .iter()
            .find(|p| p.name == "lodash")
            .expect("Should find lodash");
        assert_eq!(
            lodash.version,
            crate::domain::vulnerability::value_objects::Version::parse("4.17.21").unwrap()
        );

        let axios = result
            .packages
            .iter()
            .find(|p| p.name == "axios")
            .expect("Should find axios");
        assert_eq!(
            axios.version,
            crate::domain::vulnerability::value_objects::Version::parse("1.0.0").unwrap()
        );

        // Check devDependencies
        let typescript = result
            .packages
            .iter()
            .find(|p| p.name == "typescript")
            .expect("Should find typescript");
        assert_eq!(
            typescript.version,
            crate::domain::vulnerability::value_objects::Version::parse("4.9.0").unwrap()
        );

        // Check peerDependencies
        let react = result
            .packages
            .iter()
            .find(|p| p.name == "react")
            .expect("Should find react");
        assert_eq!(
            react.version,
            crate::domain::vulnerability::value_objects::Version::parse("18.0.0").unwrap()
        );
    }

    #[tokio::test]
    async fn test_package_json_parser_empty() {
        let parser =
            TreeSitterJsonPackageParser::new(Ecosystem::Npm, "package.json".to_string(), 25)
                .unwrap();

        let content = r#"
{
  "name": "test-package",
  "version": "1.0.0"
}
        "#;

        let result = parser.parse_file(content).await.unwrap();
        assert_eq!(result.packages.len(), 0);
    }

    #[tokio::test]
    async fn test_package_json_parser_with_special_versions() {
        let parser =
            TreeSitterJsonPackageParser::new(Ecosystem::Npm, "package.json".to_string(), 25)
                .unwrap();

        let content = r#"
{
  "dependencies": {
    "pkg1": "*",
    "pkg2": "latest",
    "pkg3": "",
    "pkg4": "^1.2.3",
    "pkg5": "~2.0.0"
  }
}
        "#;

        let result = parser.parse_file(content).await.unwrap();
        // * and latest should be converted to 0.0.0, empty should be skipped
        assert!(result.packages.len() >= 3);

        let pkg4 = result
            .packages
            .iter()
            .find(|p| p.name == "pkg4")
            .expect("Should find pkg4");
        assert_eq!(
            pkg4.version,
            crate::domain::vulnerability::value_objects::Version::parse("1.2.3").unwrap()
        );
    }
}
