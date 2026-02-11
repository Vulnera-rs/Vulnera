//! Semantic matching helpers
//!
//! Provides lightweight, type-aware inference for rule constraints
//! without introducing a full type system.

use std::collections::HashMap;

use streaming_iterator::StreamingIterator;
use tree_sitter::{Query, QueryCursor, Tree};

use crate::domain::value_objects::Language;

#[derive(Debug, Clone)]
pub struct SemanticContext {
    type_map: HashMap<String, String>,
}

impl SemanticContext {
    pub fn from_tree(tree: &Tree, source: &str, language: Language) -> Self {
        let type_map = infer_types(tree, source.as_bytes(), language);
        Self { type_map }
    }

    pub fn resolve_type(&self, identifier: &str) -> Option<&str> {
        self.type_map.get(identifier).map(|s| s.as_str())
    }
}

fn infer_types(tree: &Tree, source_bytes: &[u8], language: Language) -> HashMap<String, String> {
    let mut types = HashMap::new();

    let queries: Vec<&'static str> = match language {
        Language::Python => vec![
            r#"(assignment
                left: (identifier) @var
                right: (call function: (identifier) @type)
              )"#,
            r#"(assignment
                left: (identifier) @var
                right: (call function: (attribute attribute: (identifier) @type))
              )"#,
        ],
        Language::JavaScript | Language::TypeScript => vec![
            r#"(variable_declarator
                name: (identifier) @var
                value: (new_expression constructor: (identifier) @type)
              )"#,
            r#"(assignment_expression
                left: (identifier) @var
                right: (new_expression constructor: (identifier) @type)
              )"#,
        ],
        _ => Vec::new(),
    };

    if queries.is_empty() {
        return types;
    }

    let ts_language = match language {
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::JavaScript | Language::TypeScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::Go => tree_sitter_go::LANGUAGE.into(),
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::C => tree_sitter_c::LANGUAGE.into(),
        Language::Cpp => tree_sitter_cpp::LANGUAGE.into(),
    };

    for query_str in queries {
        let query = match Query::new(&ts_language, query_str) {
            Ok(q) => q,
            Err(_) => continue,
        };

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source_bytes);

        while let Some(m) = {
            matches.advance();
            matches.get()
        } {
            let mut var: Option<String> = None;
            let mut ty: Option<String> = None;

            for capture in m.captures {
                let capture_name = query.capture_names()[capture.index as usize];
                let text = capture
                    .node
                    .utf8_text(source_bytes)
                    .unwrap_or_default()
                    .to_string();

                match capture_name {
                    "var" => var = Some(text),
                    "type" => ty = Some(text),
                    _ => {}
                }
            }

            if let (Some(var), Some(ty)) = (var, ty) {
                types.insert(var, ty);
            }
        }
    }

    types
}
