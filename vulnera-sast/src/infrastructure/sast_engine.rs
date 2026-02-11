//! Unified SAST analysis engine
//!
//! Eliminates triple-nested locks by combining query caching,
//! parsing, and TaintQueryEngine into a single structure with consistent locking.
//!
//! ## Lock Ordering Policy
//!
//! Mutable state uses `tokio::sync::RwLock`. The compiled query cache uses
//! moka (lock-free concurrent cache) and requires no external locking.
//!
//! 1. `parser`       — tree-sitter parser state (write per language switch)
//! 2. `taint_engine` — taint query engine (write for detection runs)
//!
//! **Rules:**
//! - Never hold `taint_engine` while acquiring `parser`.
//! - `query()` uses the lock-free `query_cache`, then acquires `parser`.
//! - `detect_taint()` acquires only `taint_engine`.
//! - `parse()` acquires only `parser`.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use streaming_iterator::StreamingIterator;
use tokio::sync::RwLock;
use tracing::{debug, instrument, trace};
use tree_sitter::{Query, QueryPredicateArg, Tree};

use crate::domain::finding::{
    DataFlowFinding, DataFlowNode, DataFlowPath, Finding, Location, Severity,
};
use crate::domain::pattern_types::{Pattern, PatternRule};
use crate::domain::value_objects::{Confidence, Language};
use crate::infrastructure::data_flow::{TaintMatch, TaintQueryEngine};
use crate::infrastructure::parsers::{ParseError, Parser, TreeSitterParser};
use crate::infrastructure::query_engine::{
    CaptureInfo, QueryEngineError, QueryMatchResult, extract_metavariable_bindings,
};
use crate::infrastructure::regex_cache;
use crate::infrastructure::semantic::SemanticContext;
use crate::infrastructure::symbol_table::{SymbolTable, SymbolTableBuilder};
use crate::infrastructure::taint_queries::TaintConfig;

/// Shared compiled query cache backed by moka for bounded, lock-free concurrent access.
pub type QueryCache = moka::future::Cache<(Language, String), Arc<Query>>;

/// Create a new query cache with the given max capacity.
pub fn new_query_cache(max_capacity: u64) -> QueryCache {
    moka::future::Cache::builder()
        .max_capacity(max_capacity)
        .build()
}

/// Unified SAST engine with consistent locking
///
/// Combines pattern matching and taint analysis in a single structure
/// with unified lock management to prevent deadlocks.
pub struct SastEngine {
    /// Parser state - reinitialized per language
    parser: RwLock<TreeSitterParser>,
    /// Taint query engine for data flow analysis
    taint_engine: RwLock<TaintQueryEngine>,
    /// Bounded lock-free compiled query cache (shared with TaintQueryEngine)
    query_cache: QueryCache,
}

/// Thread-safe handle to SastEngine
pub type SastEngineHandle = Arc<SastEngine>;

/// Errors that can occur during SAST engine operations
#[derive(Debug, thiserror::Error)]
pub enum SastEngineError {
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),
    #[error("Query error: {0}")]
    Query(#[from] QueryEngineError),
    #[error("Invalid query: {0}")]
    InvalidQuery(String),
    #[error("Language not supported: {0:?}")]
    UnsupportedLanguage(Language),
}

/// Result type for SAST engine operations
pub type Result<T> = std::result::Result<T, SastEngineError>;

impl SastEngine {
    /// Create a new SAST engine with default configuration
    pub fn new() -> Self {
        Self::with_cache_capacity(512)
    }

    /// Create with a specific query cache capacity
    pub fn with_cache_capacity(max_capacity: u64) -> Self {
        let parser = TreeSitterParser::new(Language::Python).unwrap_or_else(|_| {
            TreeSitterParser::new(Language::Rust).expect("Rust parser should work")
        });

        let cache = new_query_cache(max_capacity);

        Self {
            parser: RwLock::new(parser),
            taint_engine: RwLock::new(TaintQueryEngine::with_shared_cache(cache.clone())),
            query_cache: cache,
        }
    }

    /// Parse source code into AST for the given language
    #[instrument(skip(self, source), fields(language = %language, source_len = source.len()))]
    pub async fn parse(&self, source: &str, language: Language) -> Result<Tree> {
        let mut parser = self.parser.write().await;

        // Reinitialize parser for the target language if needed
        if (*parser).language() != language {
            *parser = TreeSitterParser::new(language)?;
        }

        parser.parse_tree(source).map_err(SastEngineError::Parse)
    }

    /// Execute a tree-sitter query against source code
    #[instrument(skip(self, source), fields(language = %language))]
    pub async fn query(
        &self,
        source: &str,
        language: Language,
        query_str: &str,
    ) -> Result<Vec<QueryMatchResult>> {
        let query = self.get_or_compile_query(language, query_str).await?;

        // Parse the source
        let tree = self.parse(source, language).await?;

        let results = self.execute_query_with_tree(&query, &tree, source);

        debug!(match_count = results.len(), "Query executed");
        Ok(results)
    }

    fn execute_query_with_tree(
        &self,
        query: &Query,
        tree: &Tree,
        source: &str,
    ) -> Vec<QueryMatchResult> {
        let mut cursor = tree_sitter::QueryCursor::new();
        let root_node = tree.root_node();
        let mut matches = cursor.matches(query, root_node, source.as_bytes());
        let capture_names = query.capture_names();

        let mut results = Vec::new();
        while let Some(match_result) = {
            matches.advance();
            matches.get()
        } {
            if match_result.captures.is_empty() {
                continue;
            }

            // Evaluate text predicates (#eq?, #match?, #not-eq?, #not-match?)
            if !evaluate_predicates(query, match_result, source.as_bytes()) {
                continue;
            }

            if let Some(result) = build_match_result(match_result, capture_names, source.as_bytes())
            {
                results.push(result);
            }
        }

        results
    }

    fn match_pattern<'a>(
        &'a self,
        pattern: &'a Pattern,
        source: &'a str,
        language: Language,
        tree: &'a Tree,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<QueryMatchResult>>> + Send + 'a>> {
        Box::pin(async move {
            match pattern {
                Pattern::TreeSitterQuery(query_str) => {
                    let query = self.get_or_compile_query(language, query_str).await?;
                    Ok(self.execute_query_with_tree(&query, tree, source))
                }
                Pattern::Metavariable(pattern_str) => {
                    use crate::infrastructure::metavar_patterns::{
                        parse_metavar_pattern, translate_to_tree_sitter,
                    };

                    let parsed = parse_metavar_pattern(pattern_str);
                    if let Some(ts_query_str) = translate_to_tree_sitter(&parsed, &language) {
                        let query = self.get_or_compile_query(language, &ts_query_str).await?;
                        Ok(self.execute_query_with_tree(&query, tree, source))
                    } else {
                        debug!(pattern = pattern_str, "Metavariable pattern not supported");
                        Ok(Vec::new())
                    }
                }
                Pattern::AnyOf(patterns) => {
                    let mut all_matches = Vec::new();
                    for sub_pattern in patterns {
                        let matches = self
                            .match_pattern(sub_pattern, source, language, tree)
                            .await?;
                        all_matches.extend(matches);
                    }
                    all_matches.sort_by_key(|m| (m.start_position, m.end_position));
                    all_matches.dedup_by(|a, b| {
                        a.start_position == b.start_position && a.end_position == b.end_position
                    });
                    Ok(all_matches)
                }
                Pattern::AllOf(patterns) => {
                    if patterns.is_empty() {
                        return Ok(Vec::new());
                    }

                    let (positives, negatives): (Vec<&Pattern>, Vec<&Pattern>) =
                        patterns.iter().partition(|p| !matches!(p, Pattern::Not(_)));

                    if positives.is_empty() {
                        return Ok(Vec::new());
                    }

                    let mut result = self
                        .match_pattern(positives[0], source, language, tree)
                        .await?;

                    for sub_pattern in positives.iter().skip(1) {
                        let other_matches = self
                            .match_pattern(sub_pattern, source, language, tree)
                            .await?;
                        result.retain(|m| {
                            other_matches
                                .iter()
                                .any(|o| m.start_byte < o.end_byte && o.start_byte < m.end_byte)
                        });

                        if result.is_empty() {
                            return Ok(result);
                        }
                    }

                    for sub_pattern in negatives {
                        if let Pattern::Not(inner) = sub_pattern {
                            let negative_matches =
                                self.match_pattern(inner, source, language, tree).await?;
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
                Pattern::Not(_inner) => Ok(Vec::new()),
            }
        })
    }

    /// Execute multiple rules against source code
    #[instrument(skip(self, source, rules), fields(language = %language, rule_count = rules.len()))]
    pub async fn query_batch(
        &self,
        source: &str,
        language: Language,
        rules: &[&PatternRule],
    ) -> Vec<(String, Vec<QueryMatchResult>)> {
        let mut results = Vec::new();

        let tree = match self.parse(source, language).await {
            Ok(tree) => tree,
            Err(e) => {
                debug!(error = %e, "Failed to parse source for query batch");
                return results;
            }
        };

        for rule in rules {
            match self
                .match_pattern(&rule.pattern, source, language, &tree)
                .await
            {
                Ok(matches) if !matches.is_empty() => {
                    results.push((rule.id.clone(), matches));
                }
                Err(e) => {
                    debug!(rule_id = %rule.id, error = %e, "Query failed");
                }
                _ => {}
            }
        }

        results
    }

    pub async fn metavariable_constraints_pass(
        &self,
        rule: &PatternRule,
        match_result: &QueryMatchResult,
        language: Language,
        semantic_context: Option<&SemanticContext>,
    ) -> bool {
        if rule.metavariable_constraints.is_empty() {
            return self.semantic_constraints_pass(rule, match_result, semantic_context);
        }

        let mut parsed_cache: HashMap<String, Tree> = HashMap::new();

        for constraint in &rule.metavariable_constraints {
            let Some(bound_text) = match_result.bindings.get(&constraint.metavariable) else {
                return false;
            };

            match &constraint.condition {
                crate::domain::pattern_types::MetavariableCondition::Regex { regex } => {
                    let Ok(re) = regex_cache::get_regex(regex) else {
                        debug!(pattern = %regex, "Invalid metavariable constraint regex");
                        return false;
                    };
                    if !re.is_match(bound_text) {
                        return false;
                    }
                }
                crate::domain::pattern_types::MetavariableCondition::Pattern {
                    patterns,
                    patterns_not,
                } => {
                    let tree = if let Some(tree) = parsed_cache.get(bound_text) {
                        tree.clone()
                    } else {
                        let tree = match self.parse(bound_text, language).await {
                            Ok(tree) => tree,
                            Err(_) => return false,
                        };
                        parsed_cache.insert(bound_text.clone(), tree.clone());
                        tree
                    };

                    for pattern in patterns {
                        let matches = match self
                            .match_pattern(pattern, bound_text, language, &tree)
                            .await
                        {
                            Ok(matches) => matches,
                            Err(_) => return false,
                        };
                        if matches.is_empty() {
                            return false;
                        }
                    }

                    for pattern in patterns_not {
                        let matches = match self
                            .match_pattern(pattern, bound_text, language, &tree)
                            .await
                        {
                            Ok(matches) => matches,
                            Err(_) => return false,
                        };
                        if !matches.is_empty() {
                            return false;
                        }
                    }
                }
            }
        }

        self.semantic_constraints_pass(rule, match_result, semantic_context)
    }

    fn semantic_constraints_pass(
        &self,
        rule: &PatternRule,
        match_result: &QueryMatchResult,
        semantic_context: Option<&SemanticContext>,
    ) -> bool {
        let Some(semantic) = rule.semantic.as_ref() else {
            return true;
        };

        if semantic.required_types.is_empty() {
            return true;
        }

        for (metavar, allowed_types) in &semantic.required_types {
            let Some(bound_text) = match_result.bindings.get(metavar) else {
                return false;
            };

            let identifier = normalize_identifier(bound_text);

            let inferred = semantic_context
                .and_then(|ctx| ctx.resolve_type(&identifier))
                .map(|s| s.to_string());

            match inferred {
                Some(ty) => {
                    if !allowed_types.iter().any(|allowed| allowed == &ty) {
                        return false;
                    }
                }
                None => {
                    if !semantic.allow_unknown_types {
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Detect taint sources, sinks, and sanitizers
    #[instrument(skip(self, tree, source_bytes), fields(language = %language))]
    pub async fn detect_taint(
        &self,
        tree: &Tree,
        source_bytes: &[u8],
        language: Language,
        config: &TaintConfig,
    ) -> Vec<TaintMatch> {
        let mut engine = self.taint_engine.write().await;
        engine.set_config(config.clone());

        // Combine sources, sinks, and sanitizers into one list
        let mut matches = Vec::new();
        matches.extend(engine.detect_sources(tree, source_bytes, &language).await);
        matches.extend(engine.detect_sinks(tree, source_bytes, &language).await);
        matches.extend(
            engine
                .detect_sanitizers(tree, source_bytes, &language)
                .await,
        );

        debug!(match_count = matches.len(), "Taint detection complete");

        matches
    }

    // ====================================================================
    // Symbol Table Integration - Scope-aware analysis
    // ====================================================================

    /// Build symbol table from parsed AST
    #[instrument(skip(self, tree, source), fields(language = %language, file_path = %file_path))]
    pub fn build_symbol_table(
        &self,
        tree: &Tree,
        source: &str,
        language: Language,
        file_path: &str,
    ) -> SymbolTable {
        let builder = SymbolTableBuilder::new(source, language, file_path);
        builder.build_from_ast(tree.root_node())
    }

    /// Analyze file with symbol-aware taint tracking
    #[instrument(skip(self, source), fields(language = %language, file_path = %file_path))]
    pub async fn analyze_with_symbols(
        &self,
        source: &str,
        file_path: &str,
        language: Language,
        rules: &[&PatternRule],
    ) -> Result<Vec<Finding>> {
        use crate::infrastructure::data_flow::DataFlowAnalyzer;

        // 1. Parse the source
        let tree = self.parse(source, language).await?;

        // 2. Build symbol table
        let mut analyzer = DataFlowAnalyzer::new();
        analyzer.build_symbols(&tree, source, language, file_path);

        // 3. Detect taint sources, sinks, and sanitizers
        let taint_matches = self
            .detect_taint(&tree, source.as_bytes(), language, &TaintConfig::default())
            .await;

        // 4. Process taint matches with symbol awareness
        for tm in &taint_matches {
            if let Some(var_name) = &tm.variable_name {
                // Check if this is a source, sink, or sanitizer based on pattern name
                let is_source = tm.category.contains("source")
                    || matches!(
                        tm.pattern_name.as_str(),
                        "user-input"
                            | "request-get"
                            | "env-read"
                            | "file-read"
                            | "network-read"
                            | "command-line-arg"
                            | "form-input"
                    );

                let is_sink = tm.category.contains("sink")
                    || matches!(
                        tm.pattern_name.as_str(),
                        "sql-injection"
                            | "command-injection"
                            | "xss"
                            | "path-traversal"
                            | "eval"
                            | "exec"
                            | "ssrf"
                            | "unsafe-deserialization"
                    );

                let is_sanitizer = tm.category.contains("sanitizer") || tm.clears_labels.is_some();

                if is_source {
                    analyzer.mark_tainted(
                        var_name,
                        &tm.pattern_name,
                        file_path,
                        tm.line as u32,
                        tm.column as u32,
                    );
                } else if is_sanitizer && analyzer.is_tainted(var_name) {
                    analyzer.sanitize(
                        var_name,
                        &tm.pattern_name,
                        file_path,
                        tm.line as u32,
                        tm.column as u32,
                    );
                } else if is_sink {
                    // Check if tainted data reaches sink
                    let _ = analyzer.check_sink(
                        var_name,
                        &tm.pattern_name,
                        file_path,
                        tm.line as u32,
                        tm.column as u32,
                    );
                }
            }
        }

        // 5. Convert data flow findings to regular findings
        let mut findings = Vec::new();
        for path in analyzer.get_detected_paths() {
            let finding = self.dataflow_to_finding(path, file_path);
            findings.push(finding);
        }

        // 6. Also run regular pattern matching rules
        let pattern_results = self.query_batch(source, language, rules).await;
        for (rule_id, matches) in pattern_results {
            if let Some(rule) = rules.iter().find(|r| r.id == rule_id) {
                for match_result in matches {
                    findings.push(self.match_to_finding(&match_result, rule, file_path, source));
                }
            }
        }

        debug!(finding_count = findings.len(), "Analysis complete");
        Ok(findings)
    }

    /// Convert a data flow finding to a regular Finding
    fn dataflow_to_finding(&self, df: &DataFlowFinding, file_path: &str) -> Finding {
        // Build data flow path from the data flow finding
        let data_flow_path = Some(DataFlowPath {
            source: DataFlowNode {
                location: Location {
                    file_path: df.source.file.clone(),
                    line: df.source.line,
                    column: Some(df.source.column),
                    end_line: Some(df.source.line),
                    end_column: Some(df.source.column),
                },
                description: df.source.note.clone().unwrap_or_default(),
                expression: df.source.expression.clone(),
            },
            steps: df
                .intermediate_steps
                .iter()
                .map(|step| DataFlowNode {
                    location: Location {
                        file_path: step.file.clone(),
                        line: step.line,
                        column: Some(step.column),
                        end_line: Some(step.line),
                        end_column: Some(step.column),
                    },
                    description: step.note.clone().unwrap_or_default(),
                    expression: step.expression.clone(),
                })
                .collect(),
            sink: DataFlowNode {
                location: Location {
                    file_path: df.sink.file.clone(),
                    line: df.sink.line,
                    column: Some(df.sink.column),
                    end_line: Some(df.sink.line),
                    end_column: Some(df.sink.column),
                },
                description: df.sink.note.clone().unwrap_or_default(),
                expression: df.sink.expression.clone(),
            },
        });

        Finding {
            id: format!("{}-{}-{}", df.rule_id, file_path, df.sink.line),
            rule_id: df.rule_id.clone(),
            location: Location {
                file_path: file_path.to_string(),
                line: df.sink.line,
                column: Some(df.sink.column),
                end_line: Some(df.sink.line),
                end_column: Some(df.sink.column),
            },
            severity: Severity::High,
            confidence: Confidence::High,
            description: format!(
                "Tainted data flows to sink: {}",
                df.sink.note.clone().unwrap_or_default()
            ),
            recommendation: Some("Sanitize input before using in sensitive operations".to_string()),
            data_flow_path,
            snippet: Some(df.sink.expression.clone()),
            bindings: None,
        }
    }

    /// Convert a query match to a Finding
    pub fn match_to_finding(
        &self,
        match_result: &QueryMatchResult,
        rule: &PatternRule,
        file_path: &str,
        source: &str,
    ) -> Finding {
        let line = match_result.start_position.0 as u32 + 1;
        let column = Some(match_result.start_position.1 as u32);
        let end_line = Some(match_result.end_position.0 as u32 + 1);
        let end_column = Some(match_result.end_position.1 as u32);

        // Extract code snippet
        let snippet = source[match_result.start_byte..match_result.end_byte].to_string();

        let bindings = if match_result.bindings.is_empty() {
            None
        } else {
            Some(match_result.bindings.clone())
        };

        let description_template = rule.message.as_deref().unwrap_or(&rule.description);
        let description = interpolate_template(description_template, &match_result.bindings);
        let recommendation = rule
            .fix
            .as_ref()
            .map(|fix| interpolate_template(fix, &match_result.bindings));

        Finding {
            id: format!("{}-{}-{}", rule.id, file_path, line),
            rule_id: rule.id.clone(),
            location: Location {
                file_path: file_path.to_string(),
                line,
                column,
                end_line,
                end_column,
            },
            severity: rule.severity.clone(),
            confidence: Confidence::High,
            description,
            recommendation,
            data_flow_path: None,
            snippet: Some(snippet),
            bindings,
        }
    }

    /// Get or compile a query, caching the result via moka (lock-free)
    async fn get_or_compile_query(
        &self,
        language: Language,
        query_str: &str,
    ) -> Result<Arc<Query>> {
        let cache_key = (language, query_str.to_string());

        // moka's try_get_with handles dedup: only one compilation per key
        let query = self
            .query_cache
            .try_get_with(cache_key, async {
                let grammar = language.grammar();
                Query::new(&grammar, query_str)
                    .map(Arc::new)
                    .map_err(|e| SastEngineError::InvalidQuery(format!("{:?}", e)))
            })
            .await
            .map_err(|e| SastEngineError::InvalidQuery(e.to_string()))?;

        Ok(query)
    }

    /// Get the shared query cache (for use by other components)
    pub fn shared_query_cache(&self) -> &QueryCache {
        &self.query_cache
    }
}

impl Default for SastEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of taint detection
pub type TaintDetectionResult = Vec<TaintMatch>;

fn build_match_result(
    match_result: &tree_sitter::QueryMatch,
    capture_names: &[&str],
    source: &[u8],
) -> Option<QueryMatchResult> {
    if match_result.captures.is_empty() {
        return None;
    }

    let mut captures = HashMap::new();
    let mut captures_by_name: HashMap<String, Vec<CaptureInfo>> = HashMap::new();
    let mut min_start_byte = usize::MAX;
    let mut max_end_byte = 0;
    let mut min_start_pos = (usize::MAX, usize::MAX);
    let mut max_end_pos = (0, 0);

    for capture in match_result.captures {
        let node = capture.node;
        let capture_name = capture_names.get(capture.index as usize)?;

        let text = node.utf8_text(source).ok()?.to_string();
        let start_byte = node.start_byte();
        let end_byte = node.end_byte();
        let start_pos = node.start_position();
        let end_pos = node.end_position();

        if start_byte < min_start_byte {
            min_start_byte = start_byte;
            min_start_pos = (start_pos.row, start_pos.column);
        }
        if end_byte > max_end_byte {
            max_end_byte = end_byte;
            max_end_pos = (end_pos.row, end_pos.column);
        }

        let info = CaptureInfo {
            text,
            start_byte,
            end_byte,
            start_position: (start_pos.row, start_pos.column),
            end_position: (end_pos.row, end_pos.column),
            kind: node.kind().to_string(),
        };

        captures
            .entry(capture_name.to_string())
            .or_insert_with(|| info.clone());
        captures_by_name
            .entry(capture_name.to_string())
            .or_default()
            .push(info);
    }

    let bindings = extract_metavariable_bindings(&captures_by_name)?;

    Some(QueryMatchResult {
        pattern_index: match_result.pattern_index,
        captures,
        captures_by_name,
        bindings,
        start_byte: min_start_byte,
        end_byte: max_end_byte,
        start_position: min_start_pos,
        end_position: max_end_pos,
    })
}

/// Evaluate text predicates for a query match.
///
/// Tree-sitter queries can contain predicates like `#eq?`, `#match?`, `#not-eq?`,
/// `#not-match?` which filter matches based on captured text content.
///
/// Returns `true` if ALL predicates pass (match should be kept).
fn evaluate_predicates(
    query: &Query,
    match_result: &tree_sitter::QueryMatch,
    source_bytes: &[u8],
) -> bool {
    evaluate_predicates_ext(query, match_result, source_bytes)
}

/// Public version of predicate evaluation for use by other modules (e.g. query_engine).
pub fn evaluate_predicates_ext(
    query: &Query,
    match_result: &tree_sitter::QueryMatch,
    source_bytes: &[u8],
) -> bool {
    let predicates = query.general_predicates(match_result.pattern_index);

    for predicate in predicates {
        let op = predicate.operator.as_ref();

        match op {
            "eq?" | "not-eq?" => {
                if predicate.args.len() < 2 {
                    continue;
                }

                let capture_idx = match &predicate.args[0] {
                    QueryPredicateArg::Capture(idx) => *idx,
                    _ => continue,
                };

                let expected = match &predicate.args[1] {
                    QueryPredicateArg::String(s) => s.as_ref(),
                    _ => continue,
                };

                // Find the capture text from the match
                let captured_text = match_result
                    .captures
                    .iter()
                    .find(|c| c.index == capture_idx)
                    .and_then(|c| c.node.utf8_text(source_bytes).ok());

                let Some(text) = captured_text else {
                    // Capture not found in this match — predicate fails
                    if op == "eq?" {
                        return false;
                    }
                    continue;
                };

                let matches = text == expected;
                if (op == "eq?" && !matches) || (op == "not-eq?" && matches) {
                    return false;
                }
            }

            "match?" | "not-match?" => {
                if predicate.args.len() < 2 {
                    continue;
                }

                let capture_idx = match &predicate.args[0] {
                    QueryPredicateArg::Capture(idx) => *idx,
                    _ => continue,
                };

                let pattern = match &predicate.args[1] {
                    QueryPredicateArg::String(s) => s.as_ref(),
                    _ => continue,
                };

                let captured_text = match_result
                    .captures
                    .iter()
                    .find(|c| c.index == capture_idx)
                    .and_then(|c| c.node.utf8_text(source_bytes).ok());

                let Some(text) = captured_text else {
                    if op == "match?" {
                        return false;
                    }
                    continue;
                };

                let Ok(re) = regex_cache::get_regex(pattern) else {
                    trace!(pattern, "Failed to compile predicate regex");
                    continue;
                };

                let matches = re.is_match(text);
                if (op == "match?" && !matches) || (op == "not-match?" && matches) {
                    return false;
                }
            }

            "any-eq?" | "any-not-eq?" => {
                if predicate.args.len() < 2 {
                    continue;
                }

                let capture_idx = match &predicate.args[0] {
                    QueryPredicateArg::Capture(idx) => *idx,
                    _ => continue,
                };

                let expected = match &predicate.args[1] {
                    QueryPredicateArg::String(s) => s.as_ref(),
                    _ => continue,
                };

                // Check ALL captures with the given index (not just the first)
                let any_match = match_result
                    .captures
                    .iter()
                    .filter(|c| c.index == capture_idx)
                    .any(|c| {
                        c.node
                            .utf8_text(source_bytes)
                            .map(|t| t == expected)
                            .unwrap_or(false)
                    });

                if (op == "any-eq?" && !any_match) || (op == "any-not-eq?" && any_match) {
                    return false;
                }
            }

            // Unknown predicates are ignored (pass-through)
            _ => {
                trace!(operator = op, "Unknown predicate operator, skipping");
            }
        }
    }

    true
}

fn interpolate_template(template: &str, bindings: &HashMap<String, String>) -> String {
    if bindings.is_empty() {
        return template.to_string();
    }

    let re = regex_cache::metavar_template_regex();
    re.replace_all(template, |caps: &regex::Captures<'_>| {
        bindings
            .get(caps.get(0).map(|m| m.as_str()).unwrap_or(""))
            .cloned()
            .unwrap_or_else(|| caps[0].to_string())
    })
    .to_string()
}

fn normalize_identifier(text: &str) -> String {
    let trimmed = text.trim();
    let without_call = trimmed.strip_suffix("()").unwrap_or(trimmed);
    without_call
        .rsplit('.')
        .next()
        .unwrap_or(without_call)
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sast_engine_creation() {
        let engine = SastEngine::new();
        assert!(engine.parser.try_write().is_ok());
    }

    #[tokio::test]
    async fn test_parse_simple_code() {
        let engine = SastEngine::new();
        let result = engine.parse("fn main() {}", Language::Rust).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_query_with_cache() {
        let engine = SastEngine::new();

        // First query - cache miss
        let result1 = engine
            .query("fn main() {}", Language::Rust, "(function_item) @fn")
            .await;
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap().len(), 1);

        // Second query - cache hit
        let result2 = engine
            .query("fn test() {}", Language::Rust, "(function_item) @fn")
            .await;
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_predicate_eq_filters_correctly() {
        let engine = SastEngine::new();

        // Only match function named 'eval', not 'safe_func'
        let code = r#"eval(); safe_func();"#;
        let query_str = r#"(call_expression function: (identifier) @fn (#eq? @fn "eval")) @call"#;

        let results = engine
            .query(code, Language::JavaScript, query_str)
            .await
            .unwrap();
        assert_eq!(
            results.len(),
            1,
            "Should match only eval(), not safe_func()"
        );
    }

    #[tokio::test]
    async fn test_predicate_match_regex() {
        let engine = SastEngine::new();

        let code = r#"exec("cmd"); spawn("sh"); JSON.parse("{}");"#;
        let query_str =
            r#"(call_expression function: (identifier) @fn (#match? @fn "^(exec|spawn)$")) @call"#;

        let results = engine
            .query(code, Language::JavaScript, query_str)
            .await
            .unwrap();
        assert_eq!(results.len(), 2, "Should match exec and spawn but not JSON");
    }

    #[tokio::test]
    async fn test_predicate_not_eq() {
        let engine = SastEngine::new();

        let code = r#"eval(); safe();"#;
        let query_str =
            r#"(call_expression function: (identifier) @fn (#not-eq? @fn "eval")) @call"#;

        let results = engine
            .query(code, Language::JavaScript, query_str)
            .await
            .unwrap();
        assert_eq!(results.len(), 1, "Should match safe() but not eval()");
    }

    #[tokio::test]
    async fn test_typescript_ts_ignore_predicate() {
        let engine = SastEngine::new();

        let code = r#"function safe(): number { return 1; }"#;
        let code_with_comment = r#"function risky(): void { // @ts-ignore
      undeclaredFunction();
    }"#;
        let query_str = r#"(comment) @comment (#match? @comment "@ts-ignore")"#;

        let results = engine
            .query(code, Language::TypeScript, query_str)
            .await
            .unwrap();
        let results_with_comment = engine
            .query(code_with_comment, Language::TypeScript, query_str)
            .await
            .unwrap();

        assert_eq!(
            results.len(),
            0,
            "Should not match ts-ignore when no comment exists"
        );
        assert_eq!(
            results_with_comment.len(),
            1,
            "Should match ts-ignore when comment exists"
        );
    }
}
