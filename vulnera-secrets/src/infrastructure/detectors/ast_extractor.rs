//! AST Context extraction using tree-sitter to provide semantic metadata for secret detection.

use crate::domain::value_objects::SemanticContext;
use std::path::Path;
use tree_sitter::{Language, Node, Parser, Point};

/// Utility for extracting structural context from source code files using tree-sitter.
pub struct AstContextExtractor;

impl AstContextExtractor {
    /// Extracts semantic context for a specific location in a file.
    ///
    /// # Arguments
    /// * `source` - The full content of the file.
    /// * `line` - 1-based line number.
    /// * `column` - 1-based column number.
    /// * `file_path` - Path to the file for language detection and test-context heuristics.
    pub fn extract_context(
        source: &str,
        line: u32,
        column: u32,
        file_path: &Path,
    ) -> SemanticContext {
        let mut context = SemanticContext {
            is_test_context: Self::is_test_file(file_path),
            ..Default::default()
        };

        // Determine language from extension
        let extension = file_path.extension().and_then(|s| s.to_str()).unwrap_or("");

        let language = match Self::get_language(extension) {
            Some(l) => l,
            None => return context, // Fallback if language not supported
        };

        // Initialize parser
        let mut parser = Parser::new();
        if parser.set_language(&language).is_err() {
            return context;
        }

        // Parse source
        let tree = match parser.parse(source, None) {
            Some(t) => t,
            None => return context,
        };

        // Convert 1-based coordinates to 0-based Point for tree-sitter
        let row = line.saturating_sub(1) as usize;
        let col = column.saturating_sub(1) as usize;
        let start_point = Point::new(row, col);
        let end_point = Point::new(row, col + 1);

        // Find the most specific node at the position (including anonymous nodes like comments)
        let root = tree.root_node();
        if let Some(node) = root.named_descendant_for_point_range(start_point, end_point) {
            context.node_type = node.kind().to_string();

            // Check if we're inside a comment by walking up the tree
            let mut current = Some(node);
            while let Some(n) = current {
                let kind = n.kind();
                if kind == "comment"
                    || kind == "line_comment"
                    || kind == "block_comment"
                    || kind == "string_comment"
                {
                    context.node_type = kind.to_string();
                    break;
                }
                current = n.parent();
            }

            let (lhs, rhs) = Self::find_assignment_context(node, source);
            context.lhs_variable = lhs;
            context.rhs_value = rhs;
        }

        context
    }

    /// Maps file extensions to tree-sitter languages.
    fn get_language(extension: &str) -> Option<Language> {
        match extension.to_lowercase().as_str() {
            "py" | "python" => Some(tree_sitter_python::LANGUAGE.into()),
            "js" | "jsx" | "mjs" | "cjs" | "javascript" => {
                Some(tree_sitter_javascript::LANGUAGE.into())
            }
            "ts" | "typescript" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
            "tsx" => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
            "go" | "golang" => Some(tree_sitter_go::LANGUAGE.into()),
            "rs" | "rust" => Some(tree_sitter_rust::LANGUAGE.into()),
            _ => None,
        }
    }

    /// Heuristic to determine if a file is likely a test file.
    fn is_test_file(path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();
        path_str.contains("/tests/")
            || path_str.contains("/test/")
            || path_str.contains("/mocks/")
            || path_str.ends_with("_test.go")
            || path_str.ends_with(".test.js")
            || path_str.ends_with(".spec.js")
            || path_str.ends_with(".test.ts")
            || path_str.contains("conftest.py")
    }

    /// Walks up the AST from a node to find if it's assigned to a variable, returning (LHS, RHS).
    fn find_assignment_context(mut node: Node, source: &str) -> (Option<String>, Option<String>) {
        let mut lhs_variable = None;
        let mut rhs_value = None;

        while let Some(parent) = node.parent() {
            match parent.kind() {
                // Python / JS / TS / Go assignments
                "assignment"
                | "assignment_expression"
                | "assignment_statement"
                | "short_var_declaration" => {
                    // Try to find the left-hand side and right-hand side
                    lhs_variable = parent
                        .child_by_field_name("left")
                        .map(|n| source[n.start_byte()..n.end_byte()].to_string());

                    rhs_value = parent
                        .child_by_field_name("right")
                        .map(|n| source[n.start_byte()..n.end_byte()].to_string());

                    if lhs_variable.is_some() || rhs_value.is_some() {
                        break;
                    }
                }
                "variable_declarator" => {
                    // JavaScript uses 'name', TypeScript/others use 'id'
                    lhs_variable = parent
                        .child_by_field_name("name")
                        .or_else(|| parent.child_by_field_name("id"))
                        .map(|n| source[n.start_byte()..n.end_byte()].to_string());

                    // Try 'value' first, then 'init' for different tree-sitter grammars
                    rhs_value = parent
                        .child_by_field_name("value")
                        .or_else(|| parent.child_by_field_name("init"))
                        .map(|n| source[n.start_byte()..n.end_byte()].to_string());

                    if lhs_variable.is_some() || rhs_value.is_some() {
                        break;
                    }
                }
                // Rust let bindings
                "let_declaration" => {
                    lhs_variable = parent
                        .child_by_field_name("pattern")
                        .map(|n| source[n.start_byte()..n.end_byte()].to_string());

                    rhs_value = parent
                        .child_by_field_name("value")
                        .map(|n| source[n.start_byte()..n.end_byte()].to_string());

                    if lhs_variable.is_some() || rhs_value.is_some() {
                        break;
                    }
                }
                _ => {}
            }

            // Fallback for languages where field names might not match or be missing in some node types
            if lhs_variable.is_none()
                && matches!(
                    parent.kind(),
                    "assignment"
                        | "assignment_expression"
                        | "variable_declarator"
                        | "let_declaration"
                        | "short_var_declaration"
                )
            {
                if let Some(first) = parent.named_child(0) {
                    if first.start_byte() < node.start_byte() {
                        lhs_variable =
                            Some(source[first.start_byte()..first.end_byte()].to_string());
                    }
                }
                if let Some(last) =
                    parent.named_child(parent.named_child_count().saturating_sub(1) as u32)
                {
                    if last.start_byte() >= node.start_byte() {
                        rhs_value = Some(source[last.start_byte()..last.end_byte()].to_string());
                    }
                }
                if lhs_variable.is_some() || rhs_value.is_some() {
                    break;
                }
            }

            node = parent;
        }

        // Clean up LHS (remove common keywords if captured by fallback)
        let lhs_variable = lhs_variable.map(|lhs| {
            lhs.trim_start_matches("const ")
                .trim_start_matches("let ")
                .trim_start_matches("var ")
                .trim()
                .to_string()
        });

        (lhs_variable, rhs_value)
    }
}
