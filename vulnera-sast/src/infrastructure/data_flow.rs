//! Data Flow Analysis
//!
//! Taint tracking and data flow analysis for detecting vulnerabilities
//! where user input flows to sensitive sinks without proper sanitization.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use tree_sitter::{Query, Tree};

use crate::domain::call_graph::CallSite;
use crate::domain::finding::{
    DataFlowFinding, FlowStep, FlowStepKind, Location, TaintLabel, TaintState,
};
use crate::domain::taint_types::{DataFlowRule, FunctionTaintSummary};
use crate::domain::value_objects::Language;
use crate::infrastructure::query_engine;
use crate::infrastructure::symbol_table::{Symbol, SymbolKind, SymbolTable, SymbolTableBuilder};
use crate::infrastructure::taint_queries::{
    TaintConfig, TaintPattern, get_sanitizer_queries, get_sink_queries, get_source_queries,
};

/// Data flow analyzer for taint tracking
#[derive(Debug)]
pub struct DataFlowAnalyzer {
    /// Symbol table for scope-aware variable tracking
    symbol_table: SymbolTable,

    /// Detected data flow paths (source -> sink)
    detected_paths: Vec<DataFlowFinding>,
    /// Rules for source/sink/sanitizer detection
    rules: Vec<DataFlowRule>,
}

impl DataFlowAnalyzer {
    pub fn new() -> Self {
        Self {
            symbol_table: SymbolTable::new(),
            detected_paths: Vec::new(),
            rules: Vec::new(),
        }
    }

    /// Add a data flow rule
    pub fn add_rule(&mut self, rule: DataFlowRule) {
        self.rules.push(rule);
    }

    /// Add multiple rules
    pub fn add_rules(&mut self, rules: impl IntoIterator<Item = DataFlowRule>) {
        self.rules.extend(rules);
    }

    /// Mark a variable as tainted from a source
    pub fn mark_tainted(
        &mut self,
        var_name: &str,
        source_name: &str,
        file: &str,
        line: u32,
        column: u32,
    ) {
        let label = TaintLabel {
            source: source_name.to_string(),
            category: self.categorize_source(source_name),
        };

        let state = TaintState {
            labels: vec![label],
            origin_file: file.to_string(),
            origin_line: line,
            flow_path: vec![FlowStep {
                kind: FlowStepKind::Source,
                expression: var_name.to_string(),
                file: file.to_string(),
                line,
                column,
                note: Some(format!("Tainted from {}", source_name)),
            }],
        };

        self.ensure_symbol(var_name, file, line, column);
        let _ = self.symbol_table.update_taint_any_scope(var_name, state);
    }

    /// Propagate taint from one expression to another
    pub fn propagate_taint(
        &mut self,
        from_expr: &str,
        to_expr: &str,
        file: &str,
        line: u32,
        column: u32,
    ) {
        if let Some(source_state) = self.symbol_table.get_taint_any_scope(from_expr).cloned() {
            let mut new_state = source_state;
            new_state.flow_path.push(FlowStep {
                kind: FlowStepKind::Propagation,
                expression: to_expr.to_string(),
                file: file.to_string(),
                line,
                column,
                note: Some(format!("Propagated from {}", from_expr)),
            });
            self.ensure_symbol(to_expr, file, line, column);
            let _ = self.symbol_table.update_taint_any_scope(to_expr, new_state);
        }
    }

    /// Check if expression is tainted
    pub fn is_tainted(&self, expr: &str) -> bool {
        self.symbol_table.is_tainted_any_scope(expr)
    }

    /// Get taint state for an expression
    pub fn get_taint_state(&self, expr: &str) -> Option<&TaintState> {
        self.symbol_table.get_taint_any_scope(expr)
    }

    /// Remove taint (sanitization)
    pub fn sanitize(
        &mut self,
        expr: &str,
        sanitizer_name: &str,
        file: &str,
        line: u32,
        column: u32,
    ) {
        if let Some(mut state) = self.symbol_table.get_taint_any_scope(expr).cloned() {
            state.flow_path.push(FlowStep {
                kind: FlowStepKind::Sanitizer,
                expression: expr.to_string(),
                file: file.to_string(),
                line,
                column,
                note: Some(format!("Sanitized by {}", sanitizer_name)),
            });
        }

        self.symbol_table.clear_taint_any_scope(expr);
    }

    // ====================================================================
    // Symbol Table Integration - Scope-aware taint tracking
    // ====================================================================

    /// Build symbol table from AST before analysis
    pub fn build_symbols(
        &mut self,
        tree: &Tree,
        source: &str,
        language: Language,
        file_path: &str,
    ) {
        let builder = SymbolTableBuilder::new(source, language, file_path);
        self.symbol_table = builder.build_from_ast(tree.root_node());
    }

    /// Get reference to the symbol table
    pub fn symbol_table(&self) -> &SymbolTable {
        &self.symbol_table
    }

    /// Get mutable reference to the symbol table
    pub fn symbol_table_mut(&mut self) -> &mut SymbolTable {
        &mut self.symbol_table
    }

    /// Check if tainted data reaches a sink
    pub fn check_sink(
        &mut self,
        expr: &str,
        sink_name: &str,
        file: &str,
        line: u32,
        column: u32,
    ) -> Option<DataFlowFinding> {
        if let Some(state) = self.symbol_table.get_taint_any_scope(expr) {
            let path = DataFlowFinding {
                rule_id: String::new(), // Will be set by caller
                source: state
                    .flow_path
                    .first()
                    .cloned()
                    .unwrap_or_else(|| FlowStep {
                        kind: FlowStepKind::Source,
                        expression: expr.to_string(),
                        file: file.to_string(),
                        line,
                        column,
                        note: None,
                    }),
                sink: FlowStep {
                    kind: FlowStepKind::Sink,
                    expression: expr.to_string(),
                    file: file.to_string(),
                    line,
                    column,
                    note: Some(format!("Flows to sink: {}", sink_name)),
                },
                intermediate_steps: state.flow_path[1..].to_vec(),
                labels: state.labels.clone(),
            };

            self.detected_paths.push(path.clone());
            return Some(path);
        }
        None
    }

    /// Get all detected vulnerability paths
    pub fn get_detected_paths(&self) -> &[DataFlowFinding] {
        &self.detected_paths
    }

    /// Clear all taint states (e.g., between function analyses)
    pub fn clear(&mut self) {
        self.symbol_table.clear_all_taints();
    }

    fn ensure_symbol(&mut self, name: &str, file: &str, line: u32, column: u32) {
        if self.symbol_table.resolve(name).is_some() {
            return;
        }

        let location = Location {
            file_path: file.to_string(),
            line,
            column: Some(column),
            end_line: Some(line),
            end_column: Some(column),
        };

        let symbol = Symbol::new(
            name,
            SymbolKind::Variable,
            self.symbol_table.current_scope_id(),
            location,
        );
        let _ = self.symbol_table.declare(symbol);
    }

    /// Categorize a source by its name
    fn categorize_source(&self, source_name: &str) -> String {
        let lower = source_name.to_lowercase();
        if lower.contains("input") || lower.contains("request") || lower.contains("param") {
            "user_input".to_string()
        } else if lower.contains("env") || lower.contains("config") {
            "configuration".to_string()
        } else if lower.contains("file") || lower.contains("read") {
            "file_input".to_string()
        } else if lower.contains("network") || lower.contains("socket") {
            "network_input".to_string()
        } else {
            "unknown".to_string()
        }
    }
}

impl Default for DataFlowAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Inter-procedural data flow context
/// Tracks taint across function boundaries using call graph information
#[derive(Debug, Default)]
pub struct InterProceduralContext {
    /// Taint states per function scope
    function_contexts: HashMap<String, DataFlowAnalyzer>,
    /// Parameter taint mapping: function_id -> param_index -> taint_state
    param_taint: HashMap<String, HashMap<usize, TaintState>>,
    /// Return value taint: function_id -> taint_state
    return_taint: HashMap<String, TaintState>,
    /// Function summaries computed during analysis (unified type)
    function_summaries: HashMap<String, FunctionTaintSummary>,
    /// Call graph edges for inter-procedural propagation: caller_id -> call sites
    call_edges: HashMap<String, Vec<CallSite>>,
    /// Topological order of functions for analysis (callees first)
    topo_order: Vec<String>,
}

impl InterProceduralContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed inter-procedural context from a built call graph.
    ///
    /// Imports call graph edges, function nodes, and topological order
    /// so that inter-procedural taint propagation can follow actual call edges.
    pub fn seed_from_call_graph(&mut self, graph: &crate::infrastructure::call_graph::CallGraph) {
        // Import function summaries from call graph (if any pre-existing)
        for func in graph.functions() {
            self.enter_function(&func.id);
            if let Some(summary) = graph.get_function_summary(&func.id) {
                self.function_summaries
                    .insert(func.id.clone(), summary.clone());
            }
        }

        // Import call edges for inter-procedural traversal
        for func in graph.functions() {
            let calls = graph.get_calls(&func.id);
            if !calls.is_empty() {
                self.call_edges.insert(func.id.clone(), calls.to_vec());
            }
        }

        // Cache topological order (callees before callers)
        self.topo_order = graph.topological_order();
    }

    /// Get the topological order for analysis (callees first)
    pub fn topo_order(&self) -> &[String] {
        &self.topo_order
    }

    /// Get call edges from a function
    pub fn get_call_edges(&self, function_id: &str) -> &[CallSite] {
        self.call_edges
            .get(function_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Enter a function context
    pub fn enter_function(&mut self, function_id: &str) {
        self.function_contexts
            .entry(function_id.to_string())
            .or_default();
    }

    /// Get the analyzer for a function
    pub fn get_analyzer(&mut self, function_id: &str) -> &mut DataFlowAnalyzer {
        self.function_contexts
            .entry(function_id.to_string())
            .or_default()
    }

    /// Mark a function parameter as potentially tainted
    pub fn mark_param_tainted(&mut self, function_id: &str, param_index: usize, state: TaintState) {
        self.param_taint
            .entry(function_id.to_string())
            .or_default()
            .insert(param_index, state);
    }

    /// Check if a parameter is tainted
    pub fn get_param_taint(&self, function_id: &str, param_index: usize) -> Option<&TaintState> {
        self.param_taint
            .get(function_id)
            .and_then(|params| params.get(&param_index))
    }

    /// Mark function return as tainted
    pub fn mark_return_tainted(&mut self, function_id: &str, state: TaintState) {
        self.return_taint.insert(function_id.to_string(), state);
    }

    /// Check if function return is tainted
    pub fn get_return_taint(&self, function_id: &str) -> Option<&TaintState> {
        self.return_taint.get(function_id)
    }

    /// Set the summary for a function (computed after analysis)
    pub fn set_function_summary(&mut self, function_id: &str, summary: FunctionTaintSummary) {
        self.function_summaries
            .insert(function_id.to_string(), summary);
    }

    /// Get the summary for a function
    pub fn get_function_summary(&self, function_id: &str) -> Option<&FunctionTaintSummary> {
        self.function_summaries.get(function_id)
    }

    /// Propagate taint through a function call using computed summaries
    /// Returns the taint state of the return value, if any
    pub fn propagate_through_call(
        &self,
        function_id: &str,
        argument_taints: &[Option<TaintState>],
        call_file: &str,
        call_line: u32,
        call_column: u32,
    ) -> Option<TaintState> {
        // First check if we have a pre-computed summary for this function
        if let Some(summary) = self.function_summaries.get(function_id) {
            // Check if function is a sanitizer - it clears taint
            if summary.is_sanitizer {
                return None;
            }

            // Check if function returns tainted data inherently
            if summary.return_tainted {
                let state = TaintState {
                    labels: vec![TaintLabel {
                        source: function_id.to_string(),
                        category: "function_return".to_string(),
                    }],
                    origin_file: call_file.to_string(),
                    origin_line: call_line,
                    flow_path: vec![FlowStep {
                        kind: FlowStepKind::Source,
                        expression: format!("{}()", function_id),
                        file: call_file.to_string(),
                        line: call_line,
                        column: call_column,
                        note: Some("Return value from tainted function".to_string()),
                    }],
                };
                return Some(state);
            }

            // Check if any tainted argument flows to return
            for param_idx in &summary.params_to_return {
                if let Some(Some(arg_taint)) = argument_taints.get(*param_idx) {
                    // Clone and extend the taint state
                    let mut new_state = arg_taint.clone();
                    new_state.flow_path.push(FlowStep {
                        kind: FlowStepKind::Propagation,
                        expression: format!("{}() call", function_id),
                        file: call_file.to_string(),
                        line: call_line,
                        column: call_column,
                        note: Some(format!("Param {} flows to return", param_idx)),
                    });
                    return Some(new_state);
                }
            }

            return None;
        }

        None
    }

    /// Compute summary for a function based on its analysis results
    ///
    /// This method analyzes the taint states within a function to determine:
    /// - Which parameters flow to the return value
    /// - Which parameters flow to dangerous sinks
    /// - Whether the function acts as a sanitizer
    pub fn compute_function_summary(&mut self, function_id: &str) {
        let mut summary = FunctionTaintSummary {
            function_id: function_id.to_string(),
            ..FunctionTaintSummary::default()
        };

        // 1. Check if return is tainted and track its origin
        if let Some(return_state) = self.return_taint.get(function_id) {
            summary.return_tainted = true;

            // Track which parameters contributed to the return taint
            // by analyzing the labels on the return taint state
            for label in &return_state.labels {
                // Check if this label's source indicates a parameter
                // Parameter sources are encoded as "param:N" in the source field
                if let Some(param_str) = label.source.strip_prefix("param:") {
                    if let Ok(param_idx) = param_str.parse::<usize>() {
                        summary.params_to_return.insert(param_idx);
                    }
                }
            }
        }

        // 2. Analyze parameter taints that we've tracked
        if let Some(param_taints) = self.param_taint.get(function_id) {
            for &param_idx in param_taints.keys() {
                // Check if this parameter's taint reached any sinks
                // This information comes from the function's analyzer findings
                if let Some(analyzer) = self.function_contexts.get(function_id) {
                    for finding in analyzer.get_detected_paths() {
                        // Check if the source or any intermediate step involves this parameter
                        let param_source = format!("param:{}", param_idx);

                        let source_from_param =
                            finding.labels.iter().any(|l| l.source == param_source);

                        let intermediate_from_param = finding
                            .intermediate_steps
                            .iter()
                            .any(|step| step.expression.contains(&format!("param_{}", param_idx)));

                        if source_from_param || intermediate_from_param {
                            // This parameter reached this sink
                            summary
                                .params_to_sinks
                                .entry(param_idx)
                                .or_default()
                                .push(finding.sink.expression.clone());
                        }
                    }
                }

                // If param is tainted and return is tainted, check for flow
                // by examining if any taint state has labels from this param
                if summary.return_tainted {
                    if let Some(analyzer) = self.function_contexts.get(function_id) {
                        let param_source = format!("param:{}", param_idx);

                        for (_, taint_state) in
                            analyzer.symbol_table().get_all_tainted_in_all_scopes()
                        {
                            // Check if this state has labels from the parameter
                            let from_param =
                                taint_state.labels.iter().any(|l| l.source == param_source);

                            // If any taint state from this param exists, and return is tainted,
                            // mark parameter as flowing to return
                            if from_param {
                                summary.params_to_return.insert(param_idx);
                                break;
                            }
                        }
                    }
                }
            }
        }

        // 3. Check if this function is a sanitizer
        // A function is a sanitizer if it has sanitizer rules applied
        // or if it clears taint without reaching sinks
        if let Some(analyzer) = self.function_contexts.get(function_id) {
            // Simple heuristic: function is sanitizer if no findings and processes taint
            let has_taint_input = !self
                .param_taint
                .get(function_id)
                .map_or(true, |p| p.is_empty());
            let has_no_findings = analyzer.get_detected_paths().is_empty();

            // Sanitizer: takes tainted input, produces non-tainted or cleaned output
            if has_taint_input && has_no_findings && !summary.return_tainted {
                summary.is_sanitizer = true;
            }
        }

        self.function_summaries
            .insert(function_id.to_string(), summary);
    }

    /// Collect all detected paths from all function contexts
    pub fn collect_all_paths(&self) -> Vec<DataFlowFinding> {
        self.function_contexts
            .values()
            .flat_map(|analyzer| analyzer.get_detected_paths().to_vec())
            .collect()
    }

    /// Get statistics about the inter-procedural context
    pub fn stats(&self) -> InterProceduralStats {
        InterProceduralStats {
            functions_analyzed: self.function_contexts.len(),
            summaries_computed: self.function_summaries.len(),
            total_findings: self.collect_all_paths().len(),
        }
    }
}

/// Statistics about inter-procedural analysis
#[derive(Debug, Clone)]
pub struct InterProceduralStats {
    pub functions_analyzed: usize,
    pub summaries_computed: usize,
    pub total_findings: usize,
}

// =============================================================================
// TaintQueryEngine - AST-aware taint detection
// =============================================================================

/// A detected taint location in code
#[derive(Debug, Clone)]
pub struct TaintMatch {
    /// Pattern that matched
    pub pattern_name: String,
    /// Category (e.g., "user_input", "sql_injection")
    pub category: String,
    /// Line number (0-indexed)
    pub line: usize,
    /// Column (0-indexed byte offset)
    pub column: usize,
    /// End line
    pub end_line: usize,
    /// End column
    pub end_column: usize,
    /// The matched expression text
    pub matched_text: String,
    /// Variable name if applicable
    pub variable_name: Option<String>,
    /// Labels introduced (for sources)
    pub labels: Vec<String>,
    /// Labels cleared (for sanitizers)
    pub clears_labels: Option<Vec<String>>,
    /// Whether this is a strong/known pattern
    pub is_known: bool,
}

/// Engine for AST-aware taint source/sink/sanitizer detection
/// Uses tree-sitter queries for precise pattern matching
pub struct TaintQueryEngine {
    /// Taint configuration
    config: TaintConfig,
    /// Cache: (language_key, pattern_type) -> patterns already retrieved
    pattern_cache: HashMap<(String, TaintPatternType), Vec<TaintPattern>>,
    /// Shared compiled query cache (moka, lock-free)
    shared_cache: Option<crate::infrastructure::sast_engine::QueryCache>,
    /// Fallback local cache when no shared cache is provided
    local_cache: HashMap<(Language, String), Arc<Query>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TaintPatternType {
    Source,
    Sink,
    Sanitizer,
}

impl Default for TaintQueryEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TaintQueryEngine {
    /// Create a new taint query engine with default config
    pub fn new() -> Self {
        Self {
            config: TaintConfig::default(),
            pattern_cache: HashMap::new(),
            shared_cache: None,
            local_cache: HashMap::new(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: TaintConfig) -> Self {
        Self {
            config,
            pattern_cache: HashMap::new(),
            shared_cache: None,
            local_cache: HashMap::new(),
        }
    }

    /// Create with a shared moka query cache (injected from SastEngine)
    pub fn with_shared_cache(cache: crate::infrastructure::sast_engine::QueryCache) -> Self {
        Self {
            config: TaintConfig::default(),
            pattern_cache: HashMap::new(),
            shared_cache: Some(cache),
            local_cache: HashMap::new(),
        }
    }

    /// Create with an owned query engine (convenience constructor)
    pub fn new_owned() -> Self {
        Self::new()
    }

    /// Create with owned query engine and custom config
    pub fn new_owned_with_config(config: TaintConfig) -> Self {
        Self::with_config(config)
    }

    /// Detect taint sources in the parsed AST
    pub async fn detect_sources(
        &mut self,
        tree: &Tree,
        source_code: &[u8],
        language: &Language,
    ) -> Vec<TaintMatch> {
        let patterns = self.get_patterns(language, TaintPatternType::Source);
        self.execute_patterns(
            tree,
            source_code,
            language,
            &patterns,
            TaintPatternType::Source,
        )
        .await
    }

    /// Detect taint sinks in the parsed AST
    pub async fn detect_sinks(
        &mut self,
        tree: &Tree,
        source_code: &[u8],
        language: &Language,
    ) -> Vec<TaintMatch> {
        let patterns = self.get_patterns(language, TaintPatternType::Sink);
        self.execute_patterns(
            tree,
            source_code,
            language,
            &patterns,
            TaintPatternType::Sink,
        )
        .await
    }

    /// Detect sanitizers in the parsed AST
    pub async fn detect_sanitizers(
        &mut self,
        tree: &Tree,
        source_code: &[u8],
        language: &Language,
    ) -> Vec<TaintMatch> {
        let patterns = self.get_patterns(language, TaintPatternType::Sanitizer);
        self.execute_patterns(
            tree,
            source_code,
            language,
            &patterns,
            TaintPatternType::Sanitizer,
        )
        .await
    }

    /// Get patterns for a language and type, using cache
    fn get_patterns(
        &mut self,
        language: &Language,
        pattern_type: TaintPatternType,
    ) -> Vec<TaintPattern> {
        let key = (language.to_string(), pattern_type);

        if let Some(cached) = self.pattern_cache.get(&key) {
            return cached.clone();
        }

        let patterns = match pattern_type {
            TaintPatternType::Source => get_source_queries(language, &self.config),
            TaintPatternType::Sink => get_sink_queries(language, &self.config),
            TaintPatternType::Sanitizer => get_sanitizer_queries(language, &self.config),
        };

        self.pattern_cache.insert(key, patterns.clone());
        patterns
    }

    /// Execute patterns against the AST and collect matches
    async fn execute_patterns(
        &mut self,
        tree: &Tree,
        source_code: &[u8],
        language: &Language,
        patterns: &[TaintPattern],
        pattern_type: TaintPatternType,
    ) -> Vec<TaintMatch> {
        let mut matches = Vec::new();

        for pattern in patterns {
            // Get or compile the query using shared moka cache or local fallback
            let cache_key = (*language, pattern.query.clone());
            let query = if let Some(ref shared) = self.shared_cache {
                // Try shared moka cache first
                if let Some(q) = shared.get(&cache_key).await {
                    q
                } else {
                    match query_engine::compile_query(&pattern.query, language) {
                        Ok(q_arc) => {
                            shared.insert(cache_key, q_arc.clone()).await;
                            q_arc
                        }
                        Err(e) => {
                            tracing::warn!(
                                pattern = %pattern.name,
                                language = %language,
                                error = %e,
                                "Failed to compile taint query"
                            );
                            continue;
                        }
                    }
                }
            } else if let Some(q) = self.local_cache.get(&cache_key) {
                q.clone()
            } else {
                match query_engine::compile_query(&pattern.query, language) {
                    Ok(q_arc) => {
                        self.local_cache.insert(cache_key, q_arc.clone());
                        q_arc
                    }
                    Err(e) => {
                        tracing::warn!(
                            pattern = %pattern.name,
                            language = %language,
                            error = %e,
                            "Failed to compile taint query"
                        );
                        continue;
                    }
                }
            };

            // Execute query
            let query_matches = query_engine::execute_query(&query, tree, source_code);

            for qm in query_matches {
                // Extract variable name from captures if available
                // Captures is HashMap<String, CaptureInfo>
                // We check multiple common capture names used in taint patterns
                let variable_name = qm
                    .captures
                    .iter()
                    .find(|(name, _)| {
                        matches!(
                            name.as_str(),
                            "name"
                                | "var"
                                | "target"
                                | "source"
                                | "arg"
                                | "url"
                                | "path"
                                | "query"
                                | "value"
                                | "addr"
                                | "req"
                        )
                    })
                    .map(|(_, info)| info.text.clone());

                // Get matched text from the first capture or construct from positions
                let matched_text = qm
                    .captures
                    .values()
                    .next()
                    .map(|info| info.text.clone())
                    .unwrap_or_default();

                let taint_match = TaintMatch {
                    pattern_name: pattern.name.clone(),
                    category: pattern.category.clone(),
                    line: qm.start_position.0,
                    column: qm.start_position.1,
                    end_line: qm.end_position.0,
                    end_column: qm.end_position.1,
                    matched_text: matched_text.clone(),
                    variable_name: variable_name.clone(),
                    labels: if pattern_type == TaintPatternType::Source {
                        pattern.labels.clone()
                    } else {
                        vec![]
                    },
                    clears_labels: if pattern_type == TaintPatternType::Sanitizer {
                        pattern.clears_labels.clone()
                    } else {
                        None
                    },
                    is_known: pattern.is_known,
                };

                matches.push(taint_match);
            }
        }

        matches
    }

    /// Check if a specific line contains a taint source
    pub async fn is_source_at_line(
        &mut self,
        tree: &Tree,
        source_code: &[u8],
        language: &Language,
        line: usize,
    ) -> Option<TaintMatch> {
        self.detect_sources(tree, source_code, language)
            .await
            .into_iter()
            .find(|m| m.line == line)
    }

    /// Check if a specific line contains a taint sink
    pub async fn is_sink_at_line(
        &mut self,
        tree: &Tree,
        source_code: &[u8],
        language: &Language,
        line: usize,
    ) -> Option<TaintMatch> {
        self.detect_sinks(tree, source_code, language)
            .await
            .into_iter()
            .find(|m| m.line == line)
    }

    /// Check if a specific line contains a sanitizer
    pub async fn is_sanitizer_at_line(
        &mut self,
        tree: &Tree,
        source_code: &[u8],
        language: &Language,
        line: usize,
    ) -> Option<TaintMatch> {
        self.detect_sanitizers(tree, source_code, language)
            .await
            .into_iter()
            .find(|m| m.line == line)
    }

    /// Get confidence reduction for a sanitizer match
    /// Known sanitizers return None (full clear), generic ones return reduced confidence
    pub fn get_sanitizer_confidence(&self, sanitizer: &TaintMatch) -> Option<f32> {
        if sanitizer.is_known {
            None // Full clear
        } else {
            Some(self.config.generic_validation_confidence)
        }
    }
}

/// Work-list based data flow solver for fixpoint iteration
#[derive(Debug)]
pub struct DataFlowSolver<T: Clone + PartialEq> {
    /// Current state at each program point (block/statement ID)
    states: HashMap<String, T>,
    /// Work list of points to process
    worklist: VecDeque<String>,
    /// Processed points
    processed: HashSet<String>,
}

impl<T: Clone + PartialEq + Default> DataFlowSolver<T> {
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
            worklist: VecDeque::new(),
            processed: HashSet::new(),
        }
    }

    /// Initialize a program point with a state
    pub fn initialize(&mut self, point_id: &str, state: T) {
        self.states.insert(point_id.to_string(), state);
        self.worklist.push_back(point_id.to_string());
    }

    /// Get state at a program point
    pub fn get_state(&self, point_id: &str) -> Option<&T> {
        self.states.get(point_id)
    }

    /// Update state at a program point, returns true if changed
    pub fn update_state(&mut self, point_id: &str, new_state: T) -> bool {
        let changed = self
            .states
            .get(point_id)
            .map(|old| *old != new_state)
            .unwrap_or(true);

        if changed {
            self.states.insert(point_id.to_string(), new_state);
            if !self.worklist.contains(&point_id.to_string()) {
                self.worklist.push_back(point_id.to_string());
            }
        }
        changed
    }

    /// Process work list until fixpoint
    pub fn solve<F>(&mut self, mut transfer: F)
    where
        F: FnMut(&str, &T) -> Vec<(String, T)>,
    {
        while let Some(point_id) = self.worklist.pop_front() {
            self.processed.insert(point_id.clone());

            if let Some(state) = self.states.get(&point_id).cloned() {
                let successors = transfer(&point_id, &state);
                for (succ_id, new_state) in successors {
                    self.update_state(&succ_id, new_state);
                }
            }
        }
    }

    /// Check if analysis has reached fixpoint
    pub fn is_fixpoint(&self) -> bool {
        self.worklist.is_empty()
    }
}

impl<T: Clone + PartialEq + Default> Default for DataFlowSolver<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_taint_tracking() {
        let mut analyzer = DataFlowAnalyzer::new();

        analyzer.mark_tainted("user_input", "request.get_param", "app.py", 10, 0);
        assert!(analyzer.is_tainted("user_input"));

        analyzer.propagate_taint("user_input", "query", "app.py", 15, 0);
        assert!(analyzer.is_tainted("query"));

        let state = analyzer.get_taint_state("query").unwrap();
        assert_eq!(state.flow_path.len(), 2);
    }

    #[test]
    fn test_sanitization() {
        let mut analyzer = DataFlowAnalyzer::new();

        analyzer.mark_tainted("user_input", "request.get_param", "app.py", 10, 0);
        analyzer.sanitize("user_input", "escape_html", "app.py", 15, 0);

        assert!(!analyzer.is_tainted("user_input"));
    }

    #[test]
    fn test_sink_detection() {
        let mut analyzer = DataFlowAnalyzer::new();

        analyzer.mark_tainted("user_input", "request.get_param", "app.py", 10, 0);
        analyzer.propagate_taint("user_input", "query", "app.py", 15, 0);

        let path = analyzer.check_sink("query", "execute_sql", "app.py", 20, 0);
        assert!(path.is_some());

        let path = path.unwrap();
        assert_eq!(path.sink.line, 20);
        assert_eq!(path.intermediate_steps.len(), 1);
    }

    #[test]
    fn test_inter_procedural_context() {
        let mut ctx = InterProceduralContext::new();

        ctx.enter_function("process_input");
        let analyzer = ctx.get_analyzer("process_input");
        analyzer.mark_tainted("param", "function_arg", "lib.py", 1, 0);

        // Mark parameter 0 as tainted
        let taint_state = TaintState {
            labels: vec![TaintLabel {
                source: "user".to_string(),
                category: "user_input".to_string(),
            }],
            origin_file: "app.py".to_string(),
            origin_line: 5,
            flow_path: vec![],
        };
        ctx.mark_param_tainted("process_input", 0, taint_state);

        assert!(ctx.get_param_taint("process_input", 0).is_some());
    }
}
