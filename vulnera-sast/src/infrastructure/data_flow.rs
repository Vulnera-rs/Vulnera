//! Data Flow Analysis
//!
//! Taint tracking and data flow analysis for detecting vulnerabilities
//! where user input flows to sensitive sinks without proper sanitization.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};

use tree_sitter::Tree;

use crate::domain::entities::{
    DataFlowFinding, DataFlowRule, FlowStep, FlowStepKind, TaintLabel, TaintState,
};
use crate::domain::value_objects::Language;
use crate::infrastructure::query_engine::TreeSitterQueryEngine;
use crate::infrastructure::taint_queries::{
    TaintConfig, TaintPattern, get_sanitizer_queries, get_sink_queries, get_source_queries,
};

/// Data flow analyzer for taint tracking
#[derive(Debug)]
pub struct DataFlowAnalyzer {
    /// Active taint states indexed by variable/expression
    taint_states: HashMap<String, TaintState>,
    /// Detected data flow paths (source -> sink)
    detected_paths: Vec<DataFlowFinding>,
    /// Rules for source/sink/sanitizer detection
    rules: Vec<DataFlowRule>,
}

impl DataFlowAnalyzer {
    pub fn new() -> Self {
        Self {
            taint_states: HashMap::new(),
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

        self.taint_states.insert(var_name.to_string(), state);
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
        if let Some(source_state) = self.taint_states.get(from_expr).cloned() {
            let mut new_state = source_state;
            new_state.flow_path.push(FlowStep {
                kind: FlowStepKind::Propagation,
                expression: to_expr.to_string(),
                file: file.to_string(),
                line,
                column,
                note: Some(format!("Propagated from {}", from_expr)),
            });
            self.taint_states.insert(to_expr.to_string(), new_state);
        }
    }

    /// Check if expression is tainted
    pub fn is_tainted(&self, expr: &str) -> bool {
        self.taint_states.contains_key(expr)
    }

    /// Get taint state for an expression
    pub fn get_taint_state(&self, expr: &str) -> Option<&TaintState> {
        self.taint_states.get(expr)
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
        if let Some(state) = self.taint_states.get_mut(expr) {
            state.flow_path.push(FlowStep {
                kind: FlowStepKind::Sanitizer,
                expression: expr.to_string(),
                file: file.to_string(),
                line,
                column,
                note: Some(format!("Sanitized by {}", sanitizer_name)),
            });
            // Remove from taint tracking
            self.taint_states.remove(expr);
        }
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
        if let Some(state) = self.taint_states.get(expr) {
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
        self.taint_states.clear();
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
/// Tracks taint across function boundaries
#[derive(Debug, Default)]
pub struct InterProceduralContext {
    /// Taint states per function scope
    function_contexts: HashMap<String, DataFlowAnalyzer>,
    /// Parameter taint mapping: function_id -> param_index -> is_tainted
    param_taint: HashMap<String, HashMap<usize, TaintState>>,
    /// Return value taint: function_id -> taint_state
    return_taint: HashMap<String, TaintState>,
}

impl InterProceduralContext {
    pub fn new() -> Self {
        Self::default()
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

    /// Propagate taint through a function call
    /// Returns the taint state of the return value, if any
    pub fn propagate_through_call(
        &self,
        function_id: &str,
        argument_taints: &[Option<TaintState>],
    ) -> Option<TaintState> {
        // If any argument is tainted and flows to return, propagate
        for (idx, arg_taint) in argument_taints.iter().enumerate() {
            if arg_taint.is_some() {
                // Check if this parameter flows to return
                if self.get_param_taint(function_id, idx).is_some() {
                    // Combine with return taint if exists
                    if let Some(ret_taint) = self.get_return_taint(function_id) {
                        return Some(ret_taint.clone());
                    }
                }
            }
        }

        // Check if function has inherent return taint (e.g., reads from source)
        self.get_return_taint(function_id).cloned()
    }

    /// Collect all detected paths from all function contexts
    pub fn collect_all_paths(&self) -> Vec<DataFlowFinding> {
        self.function_contexts
            .values()
            .flat_map(|analyzer| analyzer.get_detected_paths().to_vec())
            .collect()
    }
}

// =============================================================================
// TaintQueryEngine - Production-ready AST-aware taint detection
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
    /// Underlying tree-sitter query engine (owned, wrapped in RwLock for interior mutability)
    query_engine: Arc<RwLock<TreeSitterQueryEngine>>,
    /// Taint configuration
    config: TaintConfig,
    /// Cache: (language_key, pattern_type) -> patterns already retrieved
    pattern_cache: HashMap<(String, TaintPatternType), Vec<TaintPattern>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TaintPatternType {
    Source,
    Sink,
    Sanitizer,
}

impl TaintQueryEngine {
    /// Create a new taint query engine with default config
    pub fn new(query_engine: Arc<RwLock<TreeSitterQueryEngine>>) -> Self {
        Self {
            query_engine,
            config: TaintConfig::default(),
            pattern_cache: HashMap::new(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(
        query_engine: Arc<RwLock<TreeSitterQueryEngine>>,
        config: TaintConfig,
    ) -> Self {
        Self {
            query_engine,
            config,
            pattern_cache: HashMap::new(),
        }
    }

    /// Create with an owned query engine (convenience constructor)
    pub fn new_owned() -> Self {
        Self {
            query_engine: Arc::new(RwLock::new(TreeSitterQueryEngine::new())),
            config: TaintConfig::default(),
            pattern_cache: HashMap::new(),
        }
    }

    /// Create with owned query engine and custom config
    pub fn new_owned_with_config(config: TaintConfig) -> Self {
        Self {
            query_engine: Arc::new(RwLock::new(TreeSitterQueryEngine::new())),
            config,
            pattern_cache: HashMap::new(),
        }
    }

    /// Detect taint sources in the parsed AST
    pub fn detect_sources(
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
    }

    /// Detect taint sinks in the parsed AST
    pub fn detect_sinks(
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
    }

    /// Detect sanitizers in the parsed AST
    pub fn detect_sanitizers(
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
    fn execute_patterns(
        &mut self,
        tree: &Tree,
        source_code: &[u8],
        language: &Language,
        patterns: &[TaintPattern],
        pattern_type: TaintPatternType,
    ) -> Vec<TaintMatch> {
        let mut matches = Vec::new();

        for pattern in patterns {
            // Compile the query using RwLock for interior mutability
            let query = {
                let mut engine = match self.query_engine.write() {
                    Ok(guard) => guard,
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to acquire query engine write lock");
                        continue;
                    }
                };

                match engine.compile_query(&pattern.query, language) {
                    Ok(q) => q,
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

            // Execute query with read lock
            let query_matches = {
                let engine = match self.query_engine.read() {
                    Ok(guard) => guard,
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to acquire query engine read lock");
                        continue;
                    }
                };
                engine.execute_query(&query, tree, source_code)
            };

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
                    matched_text,
                    variable_name,
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
    pub fn is_source_at_line(
        &mut self,
        tree: &Tree,
        source_code: &[u8],
        language: &Language,
        line: usize,
    ) -> Option<TaintMatch> {
        self.detect_sources(tree, source_code, language)
            .into_iter()
            .find(|m| m.line == line)
    }

    /// Check if a specific line contains a taint sink
    pub fn is_sink_at_line(
        &mut self,
        tree: &Tree,
        source_code: &[u8],
        language: &Language,
        line: usize,
    ) -> Option<TaintMatch> {
        self.detect_sinks(tree, source_code, language)
            .into_iter()
            .find(|m| m.line == line)
    }

    /// Check if a specific line contains a sanitizer
    pub fn is_sanitizer_at_line(
        &mut self,
        tree: &Tree,
        source_code: &[u8],
        language: &Language,
        line: usize,
    ) -> Option<TaintMatch> {
        self.detect_sanitizers(tree, source_code, language)
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
