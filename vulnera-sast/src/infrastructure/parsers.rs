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
        let language = tree_sitter_python::LANGUAGE.into();
        parser.set_language(&language).map_err(|e| {
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
        let language = tree_sitter_javascript::LANGUAGE.into();
        parser.set_language(&language).map_err(|e| {
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

/// Rust parser using tree-sitter-rust (consistent with other language parsers)
pub struct RustParser {
    parser: tree_sitter::Parser,
}

impl Default for RustParser {
    fn default() -> Self {
        Self::new().expect("Failed to initialize Rust parser")
    }
}

impl RustParser {
    pub fn new() -> Result<Self, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        let language = tree_sitter_rust::LANGUAGE.into();
        parser.set_language(&language).map_err(|e| {
            error!(error = %e, "Failed to load Rust grammar");
            ParseError::ParseFailed(format!("Failed to load Rust grammar: {}", e))
        })?;

        debug!("Rust parser initialized with tree-sitter-rust");
        Ok(Self { parser })
    }
}

impl Parser for RustParser {
    fn language(&self) -> Language {
        Language::Rust
    }

    #[instrument(skip(self, source), fields(source_len = source.len()))]
    fn parse(&mut self, source: &str) -> Result<AstNode, ParseError> {
        let tree = self.parser.parse(source, None).ok_or_else(|| {
            warn!("Failed to parse Rust code");
            ParseError::ParseFailed("Failed to parse Rust code".to_string())
        })?;

        let root_node = tree.root_node();
        debug!(
            node_count = root_node.child_count(),
            "Rust AST parsed successfully"
        );
        Ok(convert_tree_sitter_node(root_node, source))
    }
}

/// Parser factory
pub struct ParserFactory;

impl ParserFactory {
    pub fn create_parser(&self, language: &Language) -> Result<Box<dyn Parser>, ParseError> {
        match language {
            Language::Python => Ok(Box::new(PythonParser::new()?)),
            Language::JavaScript => Ok(Box::new(JavaScriptParser::new()?)),
            Language::Rust => Ok(Box::new(RustParser::new()?)),
            Language::Go => Ok(Box::new(GoParser::new()?)),
            Language::C => Ok(Box::new(CParser::new()?)),
            Language::Cpp => Ok(Box::new(CppParser::new()?)),
        }
    }
}

/// Go parser using tree-sitter
pub struct GoParser {
    parser: tree_sitter::Parser,
}

impl GoParser {
    pub fn new() -> Result<Self, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        let language = tree_sitter_go::LANGUAGE.into();
        parser.set_language(&language).map_err(|e| {
            error!(error = %e, "Failed to load Go grammar");
            ParseError::ParseFailed(format!("Failed to load Go grammar: {}", e))
        })?;

        debug!("Go parser initialized");
        Ok(Self { parser })
    }
}

impl Parser for GoParser {
    fn language(&self) -> Language {
        Language::Go
    }

    #[instrument(skip(self, source), fields(source_len = source.len()))]
    fn parse(&mut self, source: &str) -> Result<AstNode, ParseError> {
        let tree = self.parser.parse(source, None).ok_or_else(|| {
            warn!("Failed to parse Go code");
            ParseError::ParseFailed("Failed to parse Go code".to_string())
        })?;

        let root_node = tree.root_node();
        debug!(
            node_count = root_node.child_count(),
            "Go AST parsed successfully"
        );
        Ok(convert_tree_sitter_node(root_node, source))
    }
}

/// C parser using tree-sitter
pub struct CParser {
    parser: tree_sitter::Parser,
}

impl CParser {
    pub fn new() -> Result<Self, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        let language = tree_sitter_c::LANGUAGE.into();
        parser.set_language(&language).map_err(|e| {
            error!(error = %e, "Failed to load C grammar");
            ParseError::ParseFailed(format!("Failed to load C grammar: {}", e))
        })?;

        debug!("C parser initialized");
        Ok(Self { parser })
    }
}

impl Parser for CParser {
    fn language(&self) -> Language {
        Language::C
    }

    #[instrument(skip(self, source), fields(source_len = source.len()))]
    fn parse(&mut self, source: &str) -> Result<AstNode, ParseError> {
        let tree = self.parser.parse(source, None).ok_or_else(|| {
            warn!("Failed to parse C code");
            ParseError::ParseFailed("Failed to parse C code".to_string())
        })?;

        let root_node = tree.root_node();
        debug!(
            node_count = root_node.child_count(),
            "C AST parsed successfully"
        );
        Ok(convert_tree_sitter_node(root_node, source))
    }
}

/// C++ parser using tree-sitter
pub struct CppParser {
    parser: tree_sitter::Parser,
}

impl CppParser {
    pub fn new() -> Result<Self, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        let language = tree_sitter_cpp::LANGUAGE.into();
        parser.set_language(&language).map_err(|e| {
            error!(error = %e, "Failed to load C++ grammar");
            ParseError::ParseFailed(format!("Failed to load C++ grammar: {}", e))
        })?;

        debug!("C++ parser initialized");
        Ok(Self { parser })
    }
}

impl Parser for CppParser {
    fn language(&self) -> Language {
        Language::Cpp
    }

    #[instrument(skip(self, source), fields(source_len = source.len()))]
    fn parse(&mut self, source: &str) -> Result<AstNode, ParseError> {
        let tree = self.parser.parse(source, None).ok_or_else(|| {
            warn!("Failed to parse C++ code");
            ParseError::ParseFailed("Failed to parse C++ code".to_string())
        })?;

        let root_node = tree.root_node();
        debug!(
            node_count = root_node.child_count(),
            "C++ AST parsed successfully"
        );
        Ok(convert_tree_sitter_node(root_node, source))
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
