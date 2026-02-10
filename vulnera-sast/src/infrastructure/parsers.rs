//! AST parsers for different languages
//!
//! Uses a single generic `TreeSitterParser` parameterized by `Language` instead
//! of per-language structs. The grammar is resolved via `Language::grammar()`.

use crate::domain::value_objects::Language;
use tracing::{debug, error, instrument, warn};

/// AST node
#[derive(Debug, Clone)]
pub struct AstNode {
    pub node_type: String,
    pub field_name: Option<String>,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_point: (u32, u32), // (row, column)
    pub end_point: (u32, u32),
    pub children: Vec<AstNode>,
    pub source: String,
}

/// Parser trait for language-specific AST parsing
pub trait Parser: Send + Sync {
    fn language(&self) -> Language;
    fn parse(&mut self, source: &str) -> Result<AstNode, ParseError>;
}

/// Parse error
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Parse error: {0}")]
    ParseFailed(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Generic tree-sitter parser for any supported language.
///
/// Replaces the previous per-language parser structs (`PythonParser`,
/// `JavaScriptParser`, etc.) with a single parameterized implementation.
pub struct TreeSitterParser {
    parser: tree_sitter::Parser,
    lang: Language,
    /// Tracks whether this is a TSX parser (TypeScript + JSX)
    is_tsx: bool,
}

impl TreeSitterParser {
    /// Create a parser for the given language.
    pub fn new(lang: Language) -> Result<Self, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        let grammar = lang.grammar();
        parser.set_language(&grammar).map_err(|e| {
            error!(language = %lang, error = %e, "Failed to load grammar");
            ParseError::ParseFailed(format!("Failed to load {} grammar: {}", lang, e))
        })?;

        debug!(language = %lang, "Parser initialized");
        Ok(Self {
            parser,
            lang,
            is_tsx: false,
        })
    }

    /// Parse source code and return the raw tree-sitter Tree.
    /// This is useful for executing queries directly against the AST.
    pub fn parse_tree(&mut self, source: &str) -> Result<tree_sitter::Tree, ParseError> {
        self.parser.parse(source, None).ok_or_else(|| {
            let label = if self.is_tsx {
                "TSX"
            } else {
                self.lang.to_tree_sitter_name()
            };
            warn!(language = label, "Failed to parse code");
            ParseError::ParseFailed(format!("Failed to parse {} code", label))
        })
    }

    /// Create a TSX parser for React/JSX files.
    pub fn new_tsx() -> Result<Self, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        let grammar = Language::tsx_grammar();
        parser.set_language(&grammar).map_err(|e| {
            error!(error = %e, "Failed to load TSX grammar");
            ParseError::ParseFailed(format!("Failed to load TSX grammar: {}", e))
        })?;

        debug!("TSX parser initialized");
        Ok(Self {
            parser,
            lang: Language::TypeScript,
            is_tsx: true,
        })
    }
}

impl Parser for TreeSitterParser {
    fn language(&self) -> Language {
        self.lang
    }

    #[instrument(skip(self, source), fields(language = %self.lang, source_len = source.len()))]
    fn parse(&mut self, source: &str) -> Result<AstNode, ParseError> {
        let label = if self.is_tsx {
            "TSX"
        } else {
            self.lang.to_tree_sitter_name()
        };

        let tree = self.parser.parse(source, None).ok_or_else(|| {
            warn!(language = label, "Failed to parse code");
            ParseError::ParseFailed(format!("Failed to parse {} code", label))
        })?;

        let root_node = tree.root_node();
        debug!(
            node_count = root_node.child_count(),
            "{} AST parsed successfully", label
        );
        Ok(convert_tree_sitter_node(root_node, source, None))
    }
}

/// Parser factory
pub struct ParserFactory;

impl ParserFactory {
    pub fn create_parser(&self, language: &Language) -> Result<Box<dyn Parser>, ParseError> {
        Ok(Box::new(TreeSitterParser::new(*language)?))
    }

    /// Create a TSX parser specifically for React/JSX files
    pub fn create_tsx_parser(&self) -> Result<Box<dyn Parser>, ParseError> {
        Ok(Box::new(TreeSitterParser::new_tsx()?))
    }
}

/// Convert tree-sitter node to our AST representation
pub(crate) fn convert_tree_sitter_node(
    node: tree_sitter::Node,
    source: &str,
    field_name: Option<String>,
) -> AstNode {
    let mut children = Vec::new();
    let mut cursor = node.walk();

    // Iterate children manually to capture field names
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            let child_field_name = cursor.field_name().map(|s| s.to_string());
            children.push(convert_tree_sitter_node(child, source, child_field_name));

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    let start_byte = node.start_byte();
    let end_byte = node.end_byte();
    let start_point = node.start_position();
    let end_point = node.end_position();

    AstNode {
        node_type: node.kind().to_string(),
        field_name,
        start_byte,
        end_byte,
        start_point: (start_point.row as u32, start_point.column as u32),
        end_point: (end_point.row as u32, end_point.column as u32),
        children,
        source: source[start_byte..end_byte].to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_field_names() {
        if let Ok(mut parser) = TreeSitterParser::new(Language::Python) {
            let code = "def foo(x): pass";
            let ast = parser.parse(code).expect("Should parse");

            // Find function_definition anywhere in the tree
            // Since structure is module -> function_definition
            let func_def = ast
                .children
                .iter()
                .find(|n| n.node_type == "function_definition")
                .expect("Should match function_definition");

            // Check that 'name' field is associated with identifier 'foo'
            let name_node = func_def
                .children
                .iter()
                .find(|n| n.node_type == "identifier")
                .expect("Should find identifier");

            assert_eq!(
                name_node.field_name.as_deref(),
                Some("name"),
                "Identifier should be 'name' field"
            );
            assert_eq!(name_node.source, "foo");

            // Check parameters field
            let params_node = func_def
                .children
                .iter()
                .find(|n| n.node_type == "parameters")
                .expect("Should find parameters");
            assert_eq!(
                params_node.field_name.as_deref(),
                Some("parameters"),
                "Params should be 'parameters' field"
            );
        }
    }
}
