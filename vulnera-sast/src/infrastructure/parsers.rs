//! AST parsers for different languages

use crate::domain::value_objects::Language;
use tracing::{debug, error, instrument, warn};

/// AST node (simplified representation)
#[derive(Debug, Clone)]
pub struct AstNode {
    pub node_type: String,
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

/// Python parser using tree-sitter
pub struct PythonParser {
    parser: tree_sitter::Parser,
}

impl PythonParser {
    pub fn new() -> Result<Self, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        // LANGUAGE is a LanguageFn (function pointer), we need to call it to get Language
        // Using unsafe because LanguageFn is a raw function pointer
        let language_fn: tree_sitter::Language =
            unsafe { std::mem::transmute(tree_sitter_python::LANGUAGE) };
        parser.set_language(&language_fn).map_err(|e| {
            error!(error = %e, "Failed to load Python grammar");
            ParseError::ParseFailed(format!("Failed to load Python grammar: {}", e))
        })?;

        debug!("Python parser initialized");
        Ok(Self { parser })
    }
}

impl Parser for PythonParser {
    fn language(&self) -> Language {
        Language::Python
    }

    #[instrument(skip(self, source), fields(source_len = source.len()))]
    fn parse(&mut self, source: &str) -> Result<AstNode, ParseError> {
        let tree = self.parser.parse(source, None).ok_or_else(|| {
            warn!("Failed to parse Python code");
            ParseError::ParseFailed("Failed to parse Python code".to_string())
        })?;

        let root_node = tree.root_node();
        debug!(
            node_count = root_node.child_count(),
            "Python AST parsed successfully"
        );
        Ok(convert_tree_sitter_node(root_node, source))
    }
}

/// JavaScript parser using tree-sitter
pub struct JavaScriptParser {
    parser: tree_sitter::Parser,
}

impl JavaScriptParser {
    pub fn new() -> Result<Self, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        // LANGUAGE is a LanguageFn (function pointer), we need to call it to get Language
        // Using unsafe because LanguageFn is a raw function pointer
        let language_fn: tree_sitter::Language =
            unsafe { std::mem::transmute(tree_sitter_javascript::LANGUAGE) };
        parser.set_language(&language_fn).map_err(|e| {
            error!(error = %e, "Failed to load JavaScript grammar");
            ParseError::ParseFailed(format!("Failed to load JavaScript grammar: {}", e))
        })?;

        debug!("JavaScript parser initialized");
        Ok(Self { parser })
    }
}

impl Parser for JavaScriptParser {
    fn language(&self) -> Language {
        Language::JavaScript
    }

    #[instrument(skip(self, source), fields(source_len = source.len()))]
    fn parse(&mut self, source: &str) -> Result<AstNode, ParseError> {
        let tree = self.parser.parse(source, None).ok_or_else(|| {
            warn!("Failed to parse JavaScript code");
            ParseError::ParseFailed("Failed to parse JavaScript code".to_string())
        })?;

        let root_node = tree.root_node();
        debug!(
            node_count = root_node.child_count(),
            "JavaScript AST parsed successfully"
        );
        Ok(convert_tree_sitter_node(root_node, source))
    }
}

/// Rust parser using syn
pub struct RustParser;

impl RustParser {
    pub fn new() -> Self {
        Self
    }
}

impl Parser for RustParser {
    fn language(&self) -> Language {
        Language::Rust
    }

    #[instrument(skip(self, source), fields(source_len = source.len()))]
    fn parse(&mut self, source: &str) -> Result<AstNode, ParseError> {
        // Use syn to parse Rust code
        let _syntax_tree = syn::parse_file(source).map_err(|e| {
            warn!(error = %e, "Failed to parse Rust code");
            ParseError::ParseFailed(format!("Failed to parse Rust code: {}", e))
        })?;

        debug!("Rust AST parsed successfully");
        // Convert syn AST to our simplified AST representation
        // This is a simplified conversion - in production, you'd want more detail
        Ok(AstNode {
            node_type: "source_file".to_string(),
            start_byte: 0,
            end_byte: source.len(),
            start_point: (0, 0),
            end_point: (0, 0),
            children: vec![],
            source: source.to_string(),
        })
    }
}

/// Parser factory
pub struct ParserFactory;

impl ParserFactory {
    pub fn create_parser(&self, language: &Language) -> Result<Box<dyn Parser>, ParseError> {
        match language {
            Language::Python => Ok(Box::new(PythonParser::new()?)),
            Language::JavaScript => Ok(Box::new(JavaScriptParser::new()?)),
            Language::Rust => Ok(Box::new(RustParser::new())),
        }
    }
}

/// Convert tree-sitter node to our AST representation
fn convert_tree_sitter_node(node: tree_sitter::Node, source: &str) -> AstNode {
    let mut children = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        children.push(convert_tree_sitter_node(child, source));
    }

    let start_byte = node.start_byte();
    let end_byte = node.end_byte();
    let start_point = node.start_position();
    let end_point = node.end_position();

    AstNode {
        node_type: node.kind().to_string(),
        start_byte,
        end_byte,
        start_point: (start_point.row as u32, start_point.column as u32),
        end_point: (end_point.row as u32, end_point.column as u32),
        children,
        source: source[start_byte..end_byte].to_string(),
    }
}
