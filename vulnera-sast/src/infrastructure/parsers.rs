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
        let syntax_tree = syn::parse_file(source).map_err(|e| {
            warn!(error = %e, "Failed to parse Rust code");
            ParseError::ParseFailed(format!("Failed to parse Rust code: {}", e))
        })?;

        debug!("Rust AST parsed successfully");

        // Convert syn AST to our simplified AST representation
        Ok(convert_syn_file(&syntax_tree, source))
    }
}

fn convert_syn_file(file: &syn::File, source: &str) -> AstNode {
    let mut children = Vec::new();

    for item in &file.items {
        children.push(convert_syn_item(item, source));
    }

    AstNode {
        node_type: "source_file".to_string(),
        start_byte: 0,
        end_byte: source.len(),
        start_point: (0, 0),
        end_point: (0, 0), // We'd need line/col calculation for full accuracy
        children,
        source: source.to_string(),
    }
}

fn convert_syn_item(item: &syn::Item, source: &str) -> AstNode {
    match item {
        syn::Item::Fn(item_fn) => {
            let mut children = Vec::new();
            for stmt in &item_fn.block.stmts {
                children.push(convert_syn_stmt(stmt, source));
            }

            AstNode {
                node_type: "function_definition".to_string(),
                start_byte: 0, // Simplified
                end_byte: 0,
                start_point: (0, 0),
                end_point: (0, 0),
                children,
                source: "fn ...".to_string(), // Simplified
            }
        }
        _ => AstNode {
            node_type: "item".to_string(),
            start_byte: 0,
            end_byte: 0,
            start_point: (0, 0),
            end_point: (0, 0),
            children: vec![],
            source: "".to_string(),
        },
    }
}

fn convert_syn_stmt(stmt: &syn::Stmt, source: &str) -> AstNode {
    match stmt {
        syn::Stmt::Expr(expr, _) => convert_syn_expr(expr, source),
        syn::Stmt::Local(local) => {
            if let Some(init) = &local.init {
                convert_syn_expr(&init.expr, source)
            } else {
                AstNode {
                    node_type: "local".to_string(),
                    start_byte: 0,
                    end_byte: 0,
                    start_point: (0, 0),
                    end_point: (0, 0),
                    children: vec![],
                    source: "".to_string(),
                }
            }
        }
        _ => AstNode {
            node_type: "stmt".to_string(),
            start_byte: 0,
            end_byte: 0,
            start_point: (0, 0),
            end_point: (0, 0),
            children: vec![],
            source: "".to_string(),
        },
    }
}

fn convert_syn_expr(expr: &syn::Expr, source: &str) -> AstNode {
    match expr {
        syn::Expr::Call(expr_call) => {
            let func_name = if let syn::Expr::Path(path) = &*expr_call.func {
                path.path
                    .segments
                    .last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_default()
            } else {
                "unknown".to_string()
            };

            AstNode {
                node_type: "call".to_string(),
                start_byte: 0,
                end_byte: 0,
                start_point: (0, 0),
                end_point: (0, 0),
                children: vec![],
                source: func_name, // Store function name in source for matching
            }
        }
        syn::Expr::MethodCall(method_call) => {
            AstNode {
                node_type: "call".to_string(),
                start_byte: 0,
                end_byte: 0,
                start_point: (0, 0),
                end_point: (0, 0),
                children: vec![],
                source: method_call.method.to_string(), // Store method name
            }
        }
        syn::Expr::Block(expr_block) => {
            let mut children = Vec::new();
            for stmt in &expr_block.block.stmts {
                children.push(convert_syn_stmt(stmt, source));
            }
            AstNode {
                node_type: "block".to_string(),
                start_byte: 0,
                end_byte: 0,
                start_point: (0, 0),
                end_point: (0, 0),
                children,
                source: "".to_string(),
            }
        }
        _ => AstNode {
            node_type: "expr".to_string(),
            start_byte: 0,
            end_byte: 0,
            start_point: (0, 0),
            end_point: (0, 0),
            children: vec![],
            source: "".to_string(),
        },
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
