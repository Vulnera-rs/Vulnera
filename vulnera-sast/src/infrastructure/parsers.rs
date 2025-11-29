//! AST parsers for different languages

use crate::domain::value_objects::Language;
use syn::spanned::Spanned;
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

impl Default for RustParser {
    fn default() -> Self {
        Self::new()
    }
}

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

/// Convert line/column (1-based) to byte offset in source
fn line_col_to_byte(source: &str, line: usize, col: usize) -> usize {
    if line == 0 {
        return 0;
    }
    let mut byte_offset = 0;
    for (i, line_content) in source.lines().enumerate() {
        if i + 1 == line {
            return byte_offset + col.min(line_content.len());
        }
        byte_offset += line_content.len() + 1; // +1 for newline
    }
    source.len()
}

/// Extract span information from a syn Spanned item
fn get_span_info(span: proc_macro2::Span, source: &str) -> ((u32, u32), (u32, u32), usize, usize) {
    let start = span.start();
    let end = span.end();
    // proc_macro2 line is 1-based, convert to 0-based for consistency with tree-sitter
    let start_line = start.line.saturating_sub(1) as u32;
    let end_line = end.line.saturating_sub(1) as u32;
    let start_point = (start_line, start.column as u32);
    let end_point = (end_line, end.column as u32);
    let start_byte = line_col_to_byte(source, start.line, start.column);
    let end_byte = line_col_to_byte(source, end.line, end.column);
    (start_point, end_point, start_byte, end_byte)
}

fn convert_syn_file(file: &syn::File, source: &str) -> AstNode {
    let mut children = Vec::new();

    for item in &file.items {
        children.push(convert_syn_item(item, source));
    }

    // Calculate end point from source
    let line_count = source.lines().count().saturating_sub(1) as u32;
    let last_line_len = source.lines().last().map(|l| l.len()).unwrap_or(0) as u32;

    AstNode {
        node_type: "source_file".to_string(),
        start_byte: 0,
        end_byte: source.len(),
        start_point: (0, 0),
        end_point: (line_count, last_line_len),
        children,
        source: source.to_string(),
    }
}

fn convert_syn_item(item: &syn::Item, source: &str) -> AstNode {
    match item {
        syn::Item::Fn(item_fn) => {
            let (start_point, end_point, start_byte, end_byte) =
                get_span_info(item_fn.span(), source);
            let mut children = Vec::new();
            for stmt in &item_fn.block.stmts {
                children.push(convert_syn_stmt(stmt, source));
            }

            let fn_source = if end_byte > start_byte && end_byte <= source.len() {
                source[start_byte..end_byte].to_string()
            } else {
                format!("fn {}", item_fn.sig.ident)
            };

            AstNode {
                node_type: "function_definition".to_string(),
                start_byte,
                end_byte,
                start_point,
                end_point,
                children,
                source: fn_source,
            }
        }
        _ => {
            let (start_point, end_point, start_byte, end_byte) = get_span_info(item.span(), source);
            AstNode {
                node_type: "item".to_string(),
                start_byte,
                end_byte,
                start_point,
                end_point,
                children: vec![],
                source: if end_byte > start_byte && end_byte <= source.len() {
                    source[start_byte..end_byte].to_string()
                } else {
                    String::new()
                },
            }
        }
    }
}

fn convert_syn_stmt(stmt: &syn::Stmt, source: &str) -> AstNode {
    match stmt {
        syn::Stmt::Expr(expr, _) => convert_syn_expr(expr, source),
        syn::Stmt::Local(local) => {
            let (start_point, end_point, start_byte, end_byte) =
                get_span_info(local.span(), source);
            if let Some(init) = &local.init {
                // Return the expression node but with the local's span for context
                convert_syn_expr(&init.expr, source)
            } else {
                AstNode {
                    node_type: "local".to_string(),
                    start_byte,
                    end_byte,
                    start_point,
                    end_point,
                    children: vec![],
                    source: if end_byte > start_byte && end_byte <= source.len() {
                        source[start_byte..end_byte].to_string()
                    } else {
                        String::new()
                    },
                }
            }
        }
        _ => {
            // For other statement types, try to get span info
            let span = match stmt {
                syn::Stmt::Item(item) => item.span(),
                syn::Stmt::Macro(m) => m.span(),
                _ => proc_macro2::Span::call_site(), // Fallback
            };
            let (start_point, end_point, start_byte, end_byte) = get_span_info(span, source);
            AstNode {
                node_type: "stmt".to_string(),
                start_byte,
                end_byte,
                start_point,
                end_point,
                children: vec![],
                source: if end_byte > start_byte && end_byte <= source.len() {
                    source[start_byte..end_byte].to_string()
                } else {
                    String::new()
                },
            }
        }
    }
}

fn convert_syn_expr(expr: &syn::Expr, source: &str) -> AstNode {
    let (start_point, end_point, start_byte, end_byte) = get_span_info(expr.span(), source);

    match expr {
        syn::Expr::Call(expr_call) => {
            let func_name = if let syn::Expr::Path(path) = &*expr_call.func {
                path.path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::")
            } else {
                "unknown".to_string()
            };

            AstNode {
                node_type: "call".to_string(),
                start_byte,
                end_byte,
                start_point,
                end_point,
                children: vec![],
                source: func_name, // Store function name in source for matching
            }
        }
        syn::Expr::MethodCall(method_call) => {
            let children = vec![convert_syn_expr(&method_call.receiver, source)];
            AstNode {
                node_type: "call".to_string(),
                start_byte,
                end_byte,
                start_point,
                end_point,
                children,
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
                start_byte,
                end_byte,
                start_point,
                end_point,
                children,
                source: if end_byte > start_byte && end_byte <= source.len() {
                    source[start_byte..end_byte].to_string()
                } else {
                    String::new()
                },
            }
        }
        syn::Expr::Unsafe(expr_unsafe) => {
            let mut children = Vec::new();
            for stmt in &expr_unsafe.block.stmts {
                children.push(convert_syn_stmt(stmt, source));
            }
            AstNode {
                node_type: "unsafe_block".to_string(),
                start_byte,
                end_byte,
                start_point,
                end_point,
                children,
                source: if end_byte > start_byte && end_byte <= source.len() {
                    source[start_byte..end_byte].to_string()
                } else {
                    "unsafe { ... }".to_string()
                },
            }
        }
        _ => AstNode {
            node_type: "expr".to_string(),
            start_byte,
            end_byte,
            start_point,
            end_point,
            children: vec![],
            source: if end_byte > start_byte && end_byte <= source.len() {
                source[start_byte..end_byte].to_string()
            } else {
                String::new()
            },
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

/// Find a nested call node (call or call_expression) inside the provided AST node (DFS).
/// This is a language-agnostic helper used to locate a call site when a pattern matched at
/// a parent node. Returns the first `call` or `call_expression` node found.
pub fn find_call_node(node: &AstNode) -> Option<&AstNode> {
    if node.node_type == "call"
        || node.node_type == "call_expression"
        || node.node_type == "call_expression_statement"
    {
        return Some(node);
    }
    for child in &node.children {
        if let Some(found) = find_call_node(child) {
            return Some(found);
        }
    }
    None
}

/// Simple heuristic to determine if the provided call `node` has a literal argument.
/// It inspects AST child node types for string/integer/floating literal kinds, and then
/// safely inspects the node source to look for a literal as the first argument.
/// Returns true if the first argument is a fixed literal (string/char/int) - i.e., not a variable/expression.
pub fn node_has_literal_argument(node: &AstNode) -> bool {
    // We're primarily interested in call or call_expression nodes.
    if node.node_type != "call"
        && node.node_type != "call_expression"
        && node.node_type != "call_expression_statement"
    {
        return false;
    }

    // Check children for literal node types
    for child in &node.children {
        let nt = child.node_type.as_str();
        // These are common literal node kinds across languages/grammars
        if nt.contains("string")
            || nt.contains("string_literal")
            || nt.contains("char")
            || nt.contains("literal")
            || nt.contains("number")
            || nt == "integer"
            || nt == "float"
        {
            return true;
        }

        // Also check if the child's source begins with a string char (fallback)
        let trimmed = child.source.trim_start();
        if trimmed.starts_with('"') || trimmed.starts_with('\'') {
            return true;
        }
    }

    // Fallback (best effort): find the first '(' and check if the first non-space char is a quote
    if let Some(idx) = node.source.find('(') {
        let after = node.source[idx + 1..].trim_start();
        if after.starts_with('"') || after.starts_with('\'') {
            return true;
        }
    }

    false
}
