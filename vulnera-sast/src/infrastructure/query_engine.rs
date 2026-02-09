//! Tree-sitter query engine for production-grade pattern matching
//!
//! This module provides a native tree-sitter Query/QueryCursor based engine for
//! executing S-expression pattern queries against ASTs. It supports:
//!
//! - Capture extraction with named captures (@name syntax)
//! - Predicate filtering (#eq?, #match?, #not-eq?, etc.)
//! - Multi-language support via grammar selection
//! - Efficient batch query execution

use crate::domain::finding::{Finding, Location, Severity};
use crate::domain::pattern_types::{Pattern, PatternRule};
use crate::domain::value_objects::{Confidence, Language};
use std::collections::HashMap;
use std::sync::Arc;
use streaming_iterator::StreamingIterator;
use thiserror::Error;
use tracing::{debug, instrument, warn};
use tree_sitter::{Language as TsLanguage, Query, QueryCursor, QueryMatch, Tree};

/// Errors that can occur during query execution
#[derive(Debug, Error)]
pub enum QueryEngineError {
    #[error("Failed to parse query: {0}")]
    QueryParseFailed(String),

    #[error("Language not supported: {0:?}")]
    UnsupportedLanguage(Language),

    #[error("Failed to parse source code")]
    ParseFailed,

    #[error("Invalid capture name: {0}")]
    InvalidCapture(String),
}

/// Result of a query match
#[derive(Debug, Clone)]
pub struct QueryMatchResult {
    /// Pattern index that matched
    pub pattern_index: usize,
    /// Named captures with their byte ranges and text
    pub captures: HashMap<String, CaptureInfo>,
    /// Start byte of the entire match
    pub start_byte: usize,
    /// End byte of the entire match
    pub end_byte: usize,
    /// Start position (row, column)
    pub start_position: (usize, usize),
    /// End position (row, column)
    pub end_position: (usize, usize),
}

/// Information about a captured node
#[derive(Debug, Clone)]
pub struct CaptureInfo {
    /// Text content of the captured node
    pub text: String,
    /// Start byte offset
    pub start_byte: usize,
    /// End byte offset
    pub end_byte: usize,
    /// Start position (row, column)
    pub start_position: (usize, usize),
    /// End position (row, column)
    pub end_position: (usize, usize),
    /// Node kind/type
    pub kind: String,
}

/// Tree-sitter query engine for executing S-expression queries
pub struct TreeSitterQueryEngine {
    /// Cached compiled queries per language and query string
    query_cache: HashMap<(Language, String), Arc<Query>>,
}

impl TreeSitterQueryEngine {
    /// Create a new query engine
    pub fn new() -> Self {
        Self {
            query_cache: HashMap::new(),
        }
    }

    /// Get the tree-sitter language for a given Language enum
    fn get_ts_language(language: &Language) -> Result<TsLanguage, QueryEngineError> {
        match language {
            Language::Python => Ok(tree_sitter_python::LANGUAGE.into()),
            Language::JavaScript => Ok(tree_sitter_javascript::LANGUAGE.into()),
            Language::TypeScript => Ok(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
            Language::Rust => Ok(tree_sitter_rust::LANGUAGE.into()),
            Language::Go => Ok(tree_sitter_go::LANGUAGE.into()),
            Language::C => Ok(tree_sitter_c::LANGUAGE.into()),
            Language::Cpp => Ok(tree_sitter_cpp::LANGUAGE.into()),
        }
    }

    /// Get the TSX language for React files
    pub fn get_tsx_language() -> TsLanguage {
        tree_sitter_typescript::LANGUAGE_TSX.into()
    }

    /// Parse source code and return the tree
    #[instrument(skip(self, source), fields(source_len = source.len()))]
    pub fn parse(
        &self,
        source: &str,
        language: &Language,
    ) -> Result<(Tree, TsLanguage), QueryEngineError> {
        let ts_lang = Self::get_ts_language(language)?;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&ts_lang)
            .map_err(|e| QueryEngineError::QueryParseFailed(e.to_string()))?;

        let tree = parser
            .parse(source, None)
            .ok_or(QueryEngineError::ParseFailed)?;
        debug!(
            node_count = tree.root_node().child_count(),
            "Parsed source code"
        );
        Ok((tree, ts_lang))
    }

    /// Compile a query for a given language and return an Arc for shared access
    #[instrument(skip(self, query_str), fields(query_len = query_str.len()))]
    pub fn compile_query(
        &mut self,
        query_str: &str,
        language: &Language,
    ) -> Result<Arc<Query>, QueryEngineError> {
        let cache_key = (language.clone(), query_str.to_string());

        // Check cache first and return Arc clone
        if let Some(query) = self.query_cache.get(&cache_key) {
            return Ok(Arc::clone(query));
        }

        // Compile new query
        let ts_lang = Self::get_ts_language(language)?;
        let query = Query::new(&ts_lang, query_str).map_err(|e| {
            QueryEngineError::QueryParseFailed(format!(
                "Query parse error at offset {}: {}",
                e.offset,
                match e.kind {
                    tree_sitter::QueryErrorKind::Syntax => "syntax error",
                    tree_sitter::QueryErrorKind::NodeType => "unknown node type",
                    tree_sitter::QueryErrorKind::Field => "unknown field name",
                    tree_sitter::QueryErrorKind::Capture => "unknown capture name",
                    tree_sitter::QueryErrorKind::Structure => "invalid query structure",
                    tree_sitter::QueryErrorKind::Predicate => "invalid predicate",
                    tree_sitter::QueryErrorKind::Language => "language error",
                }
            ))
        })?;
        debug!(
            pattern_count = query.pattern_count(),
            capture_count = query.capture_names().len(),
            "Compiled query"
        );
        let query_arc = Arc::new(query);
        self.query_cache.insert(cache_key, Arc::clone(&query_arc));
        Ok(query_arc)
    }

    /// Execute a query against parsed source code
    #[instrument(skip(self, tree, source, query), fields(query_patterns = query.pattern_count()))]
    pub fn execute_query(
        &self,
        query: &Query,
        tree: &Tree,
        source: &[u8],
    ) -> Vec<QueryMatchResult> {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(query, tree.root_node(), source);

        let capture_names: &[&str] = query.capture_names();
        let mut results = Vec::new();

        while let Some(m) = matches.next() {
            if let Some(result) = self.process_match(m, capture_names, source) {
                results.push(result);
            }
        }

        debug!(match_count = results.len(), "Query execution complete");
        results
    }

    /// Process a single query match into a result
    fn process_match(
        &self,
        m: &QueryMatch,
        capture_names: &[&str],
        source: &[u8],
    ) -> Option<QueryMatchResult> {
        if m.captures.is_empty() {
            return None;
        }

        let mut captures = HashMap::new();
        let mut min_start_byte = usize::MAX;
        let mut max_end_byte = 0;
        let mut min_start_pos = (usize::MAX, usize::MAX);
        let mut max_end_pos = (0, 0);

        for capture in m.captures {
            let node = capture.node;
            let capture_name = capture_names.get(capture.index as usize)?;

            let text = node.utf8_text(source).ok()?.to_string();
            let start_byte = node.start_byte();
            let end_byte = node.end_byte();
            let start_pos = node.start_position();
            let end_pos = node.end_position();

            // Track overall match bounds
            if start_byte < min_start_byte {
                min_start_byte = start_byte;
                min_start_pos = (start_pos.row, start_pos.column);
            }
            if end_byte > max_end_byte {
                max_end_byte = end_byte;
                max_end_pos = (end_pos.row, end_pos.column);
            }

            captures.insert(
                capture_name.to_string(),
                CaptureInfo {
                    text,
                    start_byte,
                    end_byte,
                    start_position: (start_pos.row, start_pos.column),
                    end_position: (end_pos.row, end_pos.column),
                    kind: node.kind().to_string(),
                },
            );
        }

        Some(QueryMatchResult {
            pattern_index: m.pattern_index,
            captures,
            start_byte: min_start_byte,
            end_byte: max_end_byte,
            start_position: min_start_pos,
            end_position: max_end_pos,
        })
    }

    /// Execute a query string directly against source code
    #[instrument(skip(self, source, query_str), fields(source_len = source.len()))]
    pub fn query(
        &mut self,
        source: &str,
        language: &Language,
        query_str: &str,
    ) -> Result<Vec<QueryMatchResult>, QueryEngineError> {
        let (tree, _) = self.parse(source, language)?;
        let query = self.compile_query(query_str, language)?;
        Ok(self.execute_query(&query, &tree, source.as_bytes()))
    }

    /// Execute multiple queries in batch (more efficient for multiple rules)
    ///
    /// This method is resilient to individual query failures - if a query fails to compile
    /// for the given language (e.g., using Python syntax for Rust), it will be skipped
    /// and other queries will still be executed.
    #[instrument(skip(self, source, queries), fields(source_len = source.len(), query_count = queries.len()))]
    pub fn batch_query(
        &mut self,
        source: &str,
        language: &Language,
        queries: &[(String, &str)], // (rule_id, query_str)
    ) -> Result<HashMap<String, Vec<QueryMatchResult>>, QueryEngineError> {
        let (tree, _) = self.parse(source, language)?;
        self.batch_query_with_tree(&tree, source, language, queries)
    }

    /// Execute multiple queries against a pre-parsed tree
    #[instrument(skip(self, tree, source, queries), fields(source_len = source.len(), query_count = queries.len()))]
    pub fn batch_query_with_tree(
        &mut self,
        tree: &Tree,
        source: &str,
        language: &Language,
        queries: &[(String, &str)], // (rule_id, query_str)
    ) -> Result<HashMap<String, Vec<QueryMatchResult>>, QueryEngineError> {
        let mut results = HashMap::new();

        for (rule_id, query_str) in queries {
            // Skip queries that fail to compile for this language
            // This allows language-specific queries to coexist without breaking the batch
            match self.compile_query(query_str, language) {
                Ok(query) => {
                    let matches = self.execute_query(&query, tree, source.as_bytes());
                    results.insert(rule_id.clone(), matches);
                }
                Err(e) => {
                    // Log but don't fail - the query might be for a different language
                    warn!(
                        rule_id = %rule_id,
                        language = ?language,
                        error = %e,
                        "Query failed to compile for language, skipping"
                    );
                }
            }
        }

        Ok(results)
    }

    /// Convert a query match to a Finding
    pub fn match_to_finding(
        &self,
        match_result: &QueryMatchResult,
        rule: &Rule,
        file_path: &str,
        source: &str,
    ) -> Finding {
        // Try to get the primary capture (usually @name or first capture)
        let primary_capture = match_result
            .captures
            .get("name")
            .or_else(|| match_result.captures.values().next());

        let (line, column, end_line, end_column) = if let Some(capture) = primary_capture {
            (
                capture.start_position.0 as u32 + 1, // Convert to 1-based
                Some(capture.start_position.1 as u32),
                Some(capture.end_position.0 as u32 + 1),
                Some(capture.end_position.1 as u32),
            )
        } else {
            (
                match_result.start_position.0 as u32 + 1,
                Some(match_result.start_position.1 as u32),
                Some(match_result.end_position.0 as u32 + 1),
                Some(match_result.end_position.1 as u32),
            )
        };

        // Extract code snippet for context
        let snippet: String = source
            .get(match_result.start_byte..match_result.end_byte)
            .unwrap_or("")
            .chars()
            .take(200)
            .collect();

        // Generate deterministic finding ID
        let finding_id = format!(
            "{}-{}-{}",
            rule.id,
            file_path.replace(['/', '\\'], "_"),
            line
        );

        Finding {
            id: finding_id,
            rule_id: rule.id.clone(),
            location: Location {
                file_path: file_path.to_string(),
                line,
                column,
                end_line,
                end_column,
            },
            severity: rule.severity.clone(),
            confidence: Self::calculate_confidence(rule, match_result),
            description: self.format_description(rule, match_result, &snippet),
            recommendation: Some(format!(
                "Review the code at line {} and consider the security implications.",
                line
            )),
            data_flow_path: None,
            snippet: Some(snippet),
        }
    }

    /// Calculate confidence based on rule and match quality
    fn calculate_confidence(rule: &Rule, match_result: &QueryMatchResult) -> Confidence {
        // More captures = higher confidence (more specific match)
        let capture_score = match match_result.captures.len() {
            0..=1 => 0,
            2..=3 => 1,
            _ => 2,
        };

        // Critical/High severity rules tend to be more specific
        let severity_score = match rule.severity {
            Severity::Critical | Severity::High => 1,
            _ => 0,
        };

        match capture_score + severity_score {
            3 => Confidence::High,
            2 => Confidence::Medium,
            _ => Confidence::Low,
        }
    }

    /// Format finding description with captured context
    fn format_description(
        &self,
        rule: &Rule,
        match_result: &QueryMatchResult,
        snippet: &str,
    ) -> String {
        let mut desc = rule.description.clone();

        // Append captured values for context
        if !match_result.captures.is_empty() {
            desc.push_str("\n\nMatched:");
            for (name, info) in &match_result.captures {
                desc.push_str(&format!(
                    "\n  @{}: `{}`",
                    name,
                    info.text.replace('\n', "\\n")
                ));
            }
        }

        // Add code snippet
        if !snippet.is_empty() {
            desc.push_str(&format!("\n\nCode:\n```\n{}\n```", snippet.trim()));
        }

        desc
    }

    /// Match a pattern (including composite patterns) against source code
    pub fn match_pattern(
        &mut self,
        pattern: &Pattern,
        source: &str,
        language: &Language,
        tree: &Tree,
    ) -> Result<Vec<QueryMatchResult>, QueryEngineError> {
        match pattern {
            Pattern::TreeSitterQuery(query_str) => {
                let query = self.compile_query(query_str, language)?;
                Ok(self.execute_query(&query, tree, source.as_bytes()))
            }
            Pattern::Metavariable(pattern_str) => {
                // Parse the metavariable pattern
                use crate::infrastructure::metavar_patterns::{
                    parse_metavar_pattern, translate_to_tree_sitter,
                };

                let parsed = parse_metavar_pattern(pattern_str);

                // Translate to tree-sitter query
                if let Some(ts_query_str) = translate_to_tree_sitter(&parsed, language) {
                    // Compile and execute the generated query
                    match self.compile_query(&ts_query_str, language) {
                        Ok(query) => {
                            let matches = self.execute_query(&query, tree, source.as_bytes());
                            Ok(matches)
                        }
                        Err(e) => {
                            warn!(
                                pattern = pattern_str,
                                error = %e,
                                "Failed to compile metavariable pattern"
                            );
                            Ok(Vec::new())
                        }
                    }
                } else {
                    // Pattern structure not supported, return empty
                    debug!(
                        pattern = pattern_str,
                        "Metavariable pattern structure not supported for translation"
                    );
                    Ok(Vec::new())
                }
            }
            Pattern::AnyOf(patterns) => {
                // Union: collect all matches from all sub-patterns
                let mut all_matches = Vec::new();
                for sub_pattern in patterns {
                    let matches = self.match_pattern(sub_pattern, source, language, tree)?;
                    all_matches.extend(matches);
                }
                // Deduplicate by location
                all_matches.sort_by_key(|m| (m.start_position, m.end_position));
                all_matches.dedup_by(|a, b| {
                    a.start_position == b.start_position && a.end_position == b.end_position
                });
                Ok(all_matches)
            }
            Pattern::AllOf(patterns) => {
                // Intersection: matches that appear in ALL positive sub-patterns,
                // then filtered by any negative sub-patterns (pattern-not).
                if patterns.is_empty() {
                    return Ok(Vec::new());
                }

                let (positives, negatives): (Vec<&Pattern>, Vec<&Pattern>) =
                    patterns.iter().partition(|p| !matches!(p, Pattern::Not(_)));

                if positives.is_empty() {
                    return Ok(Vec::new());
                }

                let mut result = self.match_pattern(positives[0], source, language, tree)?;

                for sub_pattern in positives.iter().skip(1) {
                    let other_matches = self.match_pattern(sub_pattern, source, language, tree)?;

                    // Keep only matches that overlap with other_matches
                    result.retain(|m| {
                        other_matches.iter().any(|o| {
                            // Check for overlapping ranges
                            m.start_byte < o.end_byte && o.start_byte < m.end_byte
                        })
                    });

                    if result.is_empty() {
                        return Ok(result);
                    }
                }

                for sub_pattern in negatives {
                    if let Pattern::Not(inner) = sub_pattern {
                        let negative_matches = self.match_pattern(inner, source, language, tree)?;
                        result.retain(|m| {
                            !negative_matches
                                .iter()
                                .any(|o| m.start_byte < o.end_byte && o.start_byte < m.end_byte)
                        });

                        if result.is_empty() {
                            break;
                        }
                    }
                }

                Ok(result)
            }
            Pattern::Not(_inner_pattern) => {
                // Not is only meaningful inside AllOf as a filter
                Ok(Vec::new())
            }
        }
    }

    /// Match rules against source code and return findings
    #[instrument(skip(self, source, rules), fields(source_len = source.len(), rule_count = rules.len()))]
    pub fn match_rules(
        &mut self,
        source: &str,
        language: &Language,
        file_path: &str,
        rules: &[Rule],
    ) -> Result<Vec<Finding>, QueryEngineError> {
        // Filter rules for this language
        let applicable_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.languages.contains(language))
            .collect();

        if applicable_rules.is_empty() {
            return Ok(Vec::new());
        }

        // Parse source once
        let (tree, _) = self.parse(source, language)?;

        let mut findings = Vec::new();

        for rule in applicable_rules {
            match self.match_pattern(&rule.pattern, source, language, &tree) {
                Ok(matches) => {
                    for m in matches {
                        // Skip synthetic matches from Not patterns
                        if m.start_byte == 0 && m.end_byte == 0 && m.captures.is_empty() {
                            continue;
                        }
                        findings.push(self.match_to_finding(&m, rule, file_path, source));
                    }
                }
                Err(e) => {
                    warn!(
                        rule_id = %rule.id,
                        error = %e,
                        "Failed to match pattern for rule"
                    );
                }
            }
        }

        debug!(finding_count = findings.len(), "Rule matching complete");
        Ok(findings)
    }
}

impl Default for TreeSitterQueryEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Common tree-sitter queries for security analysis
pub mod common_queries {
    /// Python: Find all eval() calls
    pub const PYTHON_EVAL_CALL: &str = r#"
(call
  function: (identifier) @name
  (#eq? @name "eval")
) @call
"#;

    /// Python: Find all exec() calls
    pub const PYTHON_EXEC_CALL: &str = r#"
(call
  function: (identifier) @name
  (#eq? @name "exec")
) @call
"#;

    /// Python: Find subprocess calls with shell=True
    pub const PYTHON_SHELL_TRUE: &str = r#"
(call
  function: (attribute
    object: (identifier) @module
    attribute: (identifier) @method)
  arguments: (argument_list
    (keyword_argument
      name: (identifier) @kwarg
      value: (true) @value))
  (#eq? @module "subprocess")
  (#match? @method "^(run|call|Popen|check_output|check_call)$")
  (#eq? @kwarg "shell")
) @call
"#;

    /// Python: Find SQL string concatenation
    pub const PYTHON_SQL_CONCAT: &str = r#"
(assignment
  left: (identifier) @var
  right: (binary_operator
    left: (string) @sql_start
    operator: "+"
    right: (_) @value)
  (#match? @sql_start "(SELECT|INSERT|UPDATE|DELETE|DROP)")
) @assignment
"#;

    /// JavaScript: Find innerHTML assignments
    pub const JS_INNER_HTML: &str = r#"
(assignment_expression
  left: (member_expression
    property: (property_identifier) @prop)
  (#eq? @prop "innerHTML")
) @assignment
"#;

    /// JavaScript: Find document.write calls
    pub const JS_DOCUMENT_WRITE: &str = r#"
(call_expression
  function: (member_expression
    object: (identifier) @obj
    property: (property_identifier) @method)
  (#eq? @obj "document")
  (#eq? @method "write")
) @call
"#;

    /// JavaScript: Find eval() calls
    pub const JS_EVAL_CALL: &str = r#"
(call_expression
  function: (identifier) @name
  (#eq? @name "eval")
) @call
"#;

    /// Rust: Find unwrap() calls
    pub const RUST_UNWRAP: &str = r#"
(call_expression
  function: (field_expression
    field: (field_identifier) @method)
  (#eq? @method "unwrap")
) @call
"#;

    /// Rust: Find expect() calls
    pub const RUST_EXPECT: &str = r#"
(call_expression
  function: (field_expression
    field: (field_identifier) @method)
  (#eq? @method "expect")
) @call
"#;

    /// Rust: Find unsafe blocks
    pub const RUST_UNSAFE: &str = "(unsafe_block) @unsafe";

    /// Rust: Find raw pointer dereferences
    pub const RUST_RAW_DEREF: &str = r#"
(unary_expression
  operator: "*"
  operand: (_) @ptr
) @deref
"#;

    /// Go: Find fmt.Sprintf with user input (potential format string vulnerability)
    pub const GO_FMT_SPRINTF: &str = r#"
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @func)
  (#eq? @pkg "fmt")
  (#eq? @func "Sprintf")
) @call
"#;

    /// C: Find strcpy calls (buffer overflow risk)
    pub const C_STRCPY: &str = r#"
(call_expression
  function: (identifier) @name
  (#eq? @name "strcpy")
) @call
"#;

    /// C: Find gets calls (always unsafe)
    pub const C_GETS: &str = r#"
(call_expression
  function: (identifier) @name
  (#eq? @name "gets")
) @call
"#;

    /// C: Find sprintf calls (buffer overflow risk)
    pub const C_SPRINTF: &str = r#"
(call_expression
  function: (identifier) @name
  (#eq? @name "sprintf")
) @call
"#;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_eval_detection() {
        let mut engine = TreeSitterQueryEngine::new();
        let source = r#"
result = eval(user_input)
safe = eval("1 + 2")
"#;

        let matches = engine
            .query(source, &Language::Python, common_queries::PYTHON_EVAL_CALL)
            .unwrap();

        assert_eq!(matches.len(), 2);
        for m in &matches {
            assert!(m.captures.contains_key("name"));
            assert_eq!(m.captures.get("name").unwrap().text, "eval");
        }
    }

    #[test]
    fn test_javascript_innerhtml_detection() {
        let mut engine = TreeSitterQueryEngine::new();
        let source = r#"
element.innerHTML = userInput;
div.textContent = safe;
"#;

        let matches = engine
            .query(source, &Language::JavaScript, common_queries::JS_INNER_HTML)
            .unwrap();

        assert_eq!(matches.len(), 1);
        assert!(matches[0].captures.contains_key("prop"));
        assert_eq!(matches[0].captures.get("prop").unwrap().text, "innerHTML");
    }

    #[test]
    fn test_rust_unwrap_detection() {
        let mut engine = TreeSitterQueryEngine::new();
        let source = r#"
fn main() {
    let value = some_option.unwrap();
    let safe = some_result.unwrap_or_default();
}
"#;

        let matches = engine
            .query(source, &Language::Rust, common_queries::RUST_UNWRAP)
            .unwrap();

        assert_eq!(matches.len(), 1);
        assert!(matches[0].captures.contains_key("method"));
        assert_eq!(matches[0].captures.get("method").unwrap().text, "unwrap");
    }

    #[test]
    fn test_rust_unsafe_detection() {
        let mut engine = TreeSitterQueryEngine::new();
        let source = r#"
fn main() {
    unsafe {
        let ptr = raw_ptr.as_ptr();
    }
    let safe = 42;
}
"#;

        let matches = engine
            .query(source, &Language::Rust, common_queries::RUST_UNSAFE)
            .unwrap();

        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_c_strcpy_detection() {
        let mut engine = TreeSitterQueryEngine::new();
        let source = r#"
int main() {
    char dest[10];
    strcpy(dest, src);
    strncpy(dest, src, sizeof(dest));
}
"#;

        let matches = engine
            .query(source, &Language::C, common_queries::C_STRCPY)
            .unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].captures.get("name").unwrap().text, "strcpy");
    }

    #[test]
    fn test_batch_query() {
        let mut engine = TreeSitterQueryEngine::new();
        let source = r#"
result = eval(user_input)
os.system("rm -rf /")
"#;

        let queries = vec![
            ("eval-call".to_string(), common_queries::PYTHON_EVAL_CALL),
            ("exec-call".to_string(), common_queries::PYTHON_EXEC_CALL),
        ];

        let results = engine
            .batch_query(source, &Language::Python, &queries)
            .unwrap();

        assert_eq!(results.get("eval-call").unwrap().len(), 1);
        assert_eq!(results.get("exec-call").unwrap().len(), 0);
    }

    #[test]
    fn test_batch_query_with_tree() {
        let mut engine = TreeSitterQueryEngine::new();
        let source = "result = eval(user_input)\n";
        let (tree, _) = engine.parse(source, &Language::Python).unwrap();

        let queries = vec![
            ("eval-call".to_string(), common_queries::PYTHON_EVAL_CALL),
            ("exec-call".to_string(), common_queries::PYTHON_EXEC_CALL),
        ];

        let results = engine
            .batch_query_with_tree(&tree, source, &Language::Python, &queries)
            .unwrap();

        assert_eq!(results.get("eval-call").unwrap().len(), 1);
        assert_eq!(results.get("exec-call").unwrap().len(), 0);
    }

    #[test]
    fn test_composite_pattern_allof_with_not_filters() {
        let mut engine = TreeSitterQueryEngine::new();
        let source = "foo(bar(x))";
        let (tree, _) = engine.parse(source, &Language::Python).unwrap();

        let pattern = Pattern::AllOf(vec![
            Pattern::Metavariable("foo($X)".to_string()),
            Pattern::Not(Box::new(Pattern::Metavariable("bar($X)".to_string()))),
        ]);

        let matches = engine
            .match_pattern(&pattern, source, &Language::Python, &tree)
            .unwrap();

        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_query_cache() {
        let mut engine = TreeSitterQueryEngine::new();
        let source = "eval(x)";

        // First query should compile
        let _ = engine
            .query(source, &Language::Python, common_queries::PYTHON_EVAL_CALL)
            .unwrap();

        // Cache should have one entry
        assert_eq!(engine.query_cache.len(), 1);

        // Second query with same params should use cache
        let _ = engine
            .query(source, &Language::Python, common_queries::PYTHON_EVAL_CALL)
            .unwrap();

        // Still one entry
        assert_eq!(engine.query_cache.len(), 1);

        // Different query should add new entry
        let _ = engine
            .query(source, &Language::Python, common_queries::PYTHON_EXEC_CALL)
            .unwrap();

        assert_eq!(engine.query_cache.len(), 2);
    }

    #[test]
    fn test_invalid_query_error() {
        let mut engine = TreeSitterQueryEngine::new();
        let source = "x = 1";
        let invalid_query = "(invalid_node_type_xyz)";

        let result = engine.query(source, &Language::Python, invalid_query);
        assert!(result.is_err());

        if let Err(QueryEngineError::QueryParseFailed(msg)) = result {
            assert!(msg.contains("unknown node type"));
        } else {
            panic!("Expected QueryParseFailed error");
        }
    }
}
