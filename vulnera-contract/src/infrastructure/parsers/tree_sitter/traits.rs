//! Traits for tree-sitter based parsers

use crate::application::errors::ParseError;
use crate::domain::vulnerability::entities::Package;
use tree_sitter::{Parser, Tree};

/// Trait for tree-sitter based parsers
/// Extends PackageFileParser with tree-sitter specific capabilities
pub trait TreeSitterParser: Send + Sync {
    /// Get the tree-sitter language for this parser
    fn language(&self) -> tree_sitter::Language;

    /// Parse content using tree-sitter and extract packages
    fn parse_with_tree_sitter(
        &self,
        content: &str,
        tree: &Tree,
    ) -> Result<Vec<Package>, ParseError>;

    /// Check if this parser supports incremental parsing
    fn supports_incremental(&self) -> bool {
        true
    }

    /// Check if this parser supports partial parsing (error recovery)
    fn supports_partial(&self) -> bool {
        true
    }

    /// Get source location for a node (line, column)
    fn get_source_location(
        &self,
        node: &tree_sitter::Node,
        _content: &str,
    ) -> (u32, u32, u32, u32) {
        let start = node.start_position();
        let end = node.end_position();
        (
            start.row as u32 + 1,    // 1-indexed line
            start.column as u32 + 1, // 1-indexed column
            end.row as u32 + 1,      // 1-indexed end line
            end.column as u32 + 1,   // 1-indexed end column
        )
    }
}

/// Helper to create a tree-sitter parser with error recovery
pub fn create_parser_with_recovery(language: tree_sitter::Language) -> Result<Parser, ParseError> {
    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .map_err(|e| ParseError::MissingField {
            field: format!("Failed to load tree-sitter language: {}", e),
        })?;
    Ok(parser)
}

/// Parse content with tree-sitter, handling errors gracefully
pub fn parse_with_error_recovery(
    parser: &mut Parser,
    content: &str,
    old_tree: Option<&Tree>,
) -> Result<Tree, ParseError> {
    parser
        .parse(content, old_tree)
        .ok_or_else(|| ParseError::MissingField {
            field: "Tree-sitter parsing failed".to_string(),
        })
}
