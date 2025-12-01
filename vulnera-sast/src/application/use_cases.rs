//! SAST use cases
//!
//! Native SAST analysis pipeline with:
//! - Tree-sitter as the primary analysis engine (S-expression pattern queries)
//! - Inter-procedural data flow analysis (taint tracking)
//! - Call graph analysis for cross-function vulnerability detection
//! - PostgreSQL rule storage with hot-reload
//! - SARIF v2.1.0 export

use std::path::Path;
use std::sync::{Arc, RwLock as StdRwLock};
use streaming_iterator::StreamingIterator;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

use vulnera_core::config::{AnalysisDepth, SastConfig};

use crate::domain::entities::{
    DataFlowNode, DataFlowPath, FileSuppressions, Finding as SastFinding, Location, Pattern, Rule,
    Severity,
};
use crate::domain::value_objects::{AnalysisEngine, Language};
use crate::infrastructure::ast_cache::AstCacheService;
use crate::infrastructure::call_graph::CallGraphBuilder;
use crate::infrastructure::data_flow::{InterProceduralContext, TaintQueryEngine};
use crate::infrastructure::query_engine::TreeSitterQueryEngine;
use crate::infrastructure::rules::{
    PostgresRuleRepository, RuleEngine, RuleRepository, SastRuleRepository,
};
use crate::infrastructure::sarif::{SarifExporter, SarifExporterConfig};
use crate::infrastructure::scanner::DirectoryScanner;
use crate::infrastructure::taint_queries::get_propagation_queries;

/// Result of a SAST scan
#[derive(Debug)]
pub struct ScanResult {
    pub findings: Vec<SastFinding>,
    pub files_scanned: usize,
    pub analysis_engine: AnalysisEngine,
}

impl ScanResult {
    /// Export findings to SARIF JSON string
    pub fn to_sarif_json(
        &self,
        rules: &[Rule],
        tool_name: Option<&str>,
        tool_version: Option<&str>,
    ) -> Result<String, serde_json::Error> {
        let config = SarifExporterConfig {
            tool_name: tool_name.unwrap_or("vulnera-sast").to_string(),
            tool_version: Some(
                tool_version
                    .unwrap_or(env!("CARGO_PKG_VERSION"))
                    .to_string(),
            ),
            ..Default::default()
        };
        let exporter = SarifExporter::with_config(config);
        let report = exporter.export(&self.findings, rules);
        serde_json::to_string_pretty(&report)
    }
}

/// Configuration for the analysis pipeline
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    /// Enable AST caching via Dragonfly
    pub enable_ast_cache: bool,
    /// AST cache TTL in hours
    pub ast_cache_ttl_hours: u64,
    /// Maximum concurrent file analysis
    pub max_concurrent_files: usize,
    /// Enable inter-procedural data flow analysis
    pub enable_data_flow: bool,
    /// Enable call graph analysis
    pub enable_call_graph: bool,
    /// Analysis depth: Quick, Standard, or Deep
    pub analysis_depth: AnalysisDepth,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            enable_ast_cache: true,
            ast_cache_ttl_hours: 1,
            max_concurrent_files: 4,
            enable_data_flow: true,
            enable_call_graph: true,
            analysis_depth: AnalysisDepth::Standard,
        }
    }
}

impl From<&SastConfig> for AnalysisConfig {
    fn from(config: &SastConfig) -> Self {
        Self {
            enable_ast_cache: config.enable_ast_cache.unwrap_or(true),
            ast_cache_ttl_hours: config.ast_cache_ttl_hours.unwrap_or(4),
            max_concurrent_files: config.max_concurrent_files.unwrap_or(4),
            enable_data_flow: config.enable_data_flow,
            enable_call_graph: config.enable_call_graph,
            analysis_depth: config.analysis_depth,
        }
    }
}

/// Production-ready use case for scanning a project
pub struct ScanProjectUseCase {
    scanner: DirectoryScanner,
    rule_repository: Arc<RwLock<RuleRepository>>,
    rule_engine: RuleEngine,
    /// AST cache for parsed file caching (Dragonfly-backed)
    ast_cache: Option<Arc<dyn AstCacheService>>,
    /// Inter-procedural data flow context
    data_flow_context: Arc<RwLock<InterProceduralContext>>,
    /// Call graph builder
    call_graph_builder: Arc<RwLock<CallGraphBuilder>>,
    /// Taint query engine for AST-aware taint detection (uses std::sync::RwLock internally)
    taint_query_engine: Arc<StdRwLock<TaintQueryEngine>>,
    /// Analysis configuration
    config: AnalysisConfig,
}

impl ScanProjectUseCase {
    pub fn new() -> Self {
        Self::with_config(&SastConfig::default(), AnalysisConfig::default())
    }

    pub fn with_config(sast_config: &SastConfig, analysis_config: AnalysisConfig) -> Self {
        let scanner = DirectoryScanner::new(sast_config.max_scan_depth)
            .with_exclude_patterns(sast_config.exclude_patterns.clone());

        let rule_repository = if let Some(ref rule_file_path) = sast_config.rule_file_path {
            RuleRepository::with_file_and_defaults(rule_file_path)
        } else {
            RuleRepository::new()
        };

        Self {
            scanner,
            rule_repository: Arc::new(RwLock::new(rule_repository)),
            rule_engine: RuleEngine::new(),
            ast_cache: None,
            data_flow_context: Arc::new(RwLock::new(InterProceduralContext::new())),
            call_graph_builder: Arc::new(RwLock::new(CallGraphBuilder::new())),
            taint_query_engine: Arc::new(StdRwLock::new(TaintQueryEngine::new_owned())),
            config: analysis_config,
        }
    }

    pub async fn with_database_rules(
        self,
        db_repository: &PostgresRuleRepository,
    ) -> Result<Self, ScanError> {
        let tree_sitter_rules = db_repository
            .get_tree_sitter_rules()
            .await
            .map_err(|e| ScanError::DatabaseError(e.to_string()))?;

        {
            let mut repo = self.rule_repository.write().await;
            repo.extend_with_rules(tree_sitter_rules);
        }

        Ok(self)
    }

    /// Add AST cache service for parsed file caching
    ///
    /// When enabled, parsed ASTs are cached by content hash in Dragonfly,
    /// reducing parse time for unchanged files.
    pub fn with_ast_cache(mut self, cache: Arc<dyn AstCacheService>) -> Self {
        self.ast_cache = Some(cache);
        self
    }

    #[instrument(skip(self), fields(root = %root.display()))]
    pub async fn execute(&self, root: &Path) -> Result<ScanResult, ScanError> {
        info!("Starting native SAST scan");

        let files = self.scanner.scan(root).map_err(|e| {
            error!(error = %e, "Failed to scan directory");
            ScanError::Io(e)
        })?;

        let file_count = files.len();
        info!(file_count, analysis_depth = ?self.config.analysis_depth, "Found files to scan");

        let mut all_findings = Vec::new();
        let mut files_scanned = 0;

        let rules = self.rule_repository.read().await;
        let all_rules = rules.get_all_rules();

        // Phase 1: Build call graph (if enabled and not Quick mode)
        if self.config.enable_call_graph && self.config.analysis_depth != AnalysisDepth::Quick {
            debug!("Building call graph for inter-procedural analysis");
            let mut call_graph = self.call_graph_builder.write().await;
            for file in &files {
                if let Ok(content) = std::fs::read_to_string(&file.path) {
                    call_graph.analyze_file(&file.path.display().to_string(), &content);
                }
            }
        }

        // Phase 2: Analyze each file
        for file in files {
            debug!(file = %file.path.display(), language = ?file.language, "Scanning file");

            let content = match std::fs::read_to_string(&file.path) {
                Ok(content) => content,
                Err(e) => {
                    warn!(file = %file.path.display(), error = %e, "Failed to read file");
                    continue;
                }
            };

            let suppressions = FileSuppressions::parse(&content);
            let is_test_context = Self::is_test_file(&file.path, &content);

            files_scanned += 1;

            // Get rules applicable to this language
            let applicable_rules: Vec<&Rule> = all_rules
                .iter()
                .filter(|r| r.languages.contains(&file.language))
                .collect();

            if applicable_rules.is_empty() {
                continue;
            }

            // Execute tree-sitter pattern analysis
            self.execute_tree_sitter_analysis(
                &file.path,
                &file.language,
                &content,
                &applicable_rules,
                &suppressions,
                is_test_context,
                &mut all_findings,
            )
            .await?;

            // Phase 3: Data flow analysis
            if self.config.enable_data_flow && self.config.analysis_depth != AnalysisDepth::Quick {
                self.execute_data_flow_analysis(
                    &file.path,
                    &file.language,
                    &content,
                    &mut all_findings,
                )
                .await;
            }
        }

        // Phase 4: Adjust severity for data-flow confirmed findings
        if self.config.enable_data_flow && self.config.analysis_depth != AnalysisDepth::Quick {
            Self::adjust_severity_for_data_flow(&mut all_findings);
        }

        all_findings = Self::deduplicate_findings(all_findings);

        info!(
            finding_count = all_findings.len(),
            files_scanned, "SAST scan completed"
        );

        Ok(ScanResult {
            findings: all_findings,
            files_scanned,
            analysis_engine: AnalysisEngine::TreeSitter,
        })
    }

    async fn execute_tree_sitter_analysis(
        &self,
        file_path: &Path,
        language: &Language,
        content: &str,
        rules: &[&Rule],
        suppressions: &FileSuppressions,
        is_test_context: bool,
        findings: &mut Vec<SastFinding>,
    ) -> Result<(), ScanError> {
        // Filter to tree-sitter query rules
        let ts_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| matches!(&r.pattern, Pattern::TreeSitterQuery(_)))
            .copied()
            .collect();

        if ts_rules.is_empty() {
            return Ok(());
        }

        debug!(
            rule_count = ts_rules.len(),
            file = %file_path.display(),
            "Executing tree-sitter rules"
        );

        let results = self
            .rule_engine
            .execute_tree_sitter_rules(&ts_rules, language, content)
            .await;

        let query_engine = self.rule_engine.query_engine();
        let engine = query_engine.read().await;

        for (rule_id, matches) in results {
            let rule = ts_rules.iter().find(|r| r.id == rule_id);
            if let Some(rule) = rule {
                for match_result in matches {
                    let line = match_result.start_position.0 as u32 + 1;

                    if suppressions.is_suppressed(line, &rule.id) {
                        debug!(rule_id = %rule.id, line, "Finding suppressed by comment");
                        continue;
                    }

                    if is_test_context && rule.options.suppress_in_tests {
                        debug!(rule_id = %rule.id, line, "Finding suppressed in test context");
                        continue;
                    }

                    let finding = engine.match_to_finding(
                        &match_result,
                        rule,
                        &file_path.display().to_string(),
                        content,
                    );
                    findings.push(finding);
                }
            }
        }

        Ok(())
    }

    /// Execute data flow analysis on a file to detect taint vulnerabilities
    /// Uses tree-sitter queries for AST-aware source/sink/sanitizer detection
    async fn execute_data_flow_analysis(
        &self,
        file_path: &Path,
        language: &Language,
        content: &str,
        findings: &mut Vec<SastFinding>,
    ) {
        // Skip if data flow is disabled
        if !self.config.enable_data_flow {
            return;
        }

        debug!(file = %file_path.display(), "Running data flow analysis");

        // Parse the file with tree-sitter (outside of any lock)
        let query_engine = TreeSitterQueryEngine::new();
        let (tree, _) = match query_engine.parse(content, language) {
            Ok(t) => t,
            Err(e) => {
                warn!(
                    file = %file_path.display(),
                    error = %e,
                    "Failed to parse file for data flow analysis"
                );
                return;
            }
        };

        let source_bytes = content.as_bytes();
        let file_str = file_path.display().to_string();

        // Detect sources, sinks, and sanitizers using tree-sitter queries
        // Acquire lock, do detection, release lock before any await
        let (sources, sinks, sanitizers, sanitizer_confidence, assignments) = {
            let mut taint_engine = match self.taint_query_engine.write() {
                Ok(guard) => guard,
                Err(e) => {
                    error!(error = %e, "Failed to acquire taint engine write lock");
                    return;
                }
            };

            let sources = taint_engine.detect_sources(&tree, source_bytes, language);
            let sinks = taint_engine.detect_sinks(&tree, source_bytes, language);
            let sanitizers = taint_engine.detect_sanitizers(&tree, source_bytes, language);
            let assignments = Self::extract_assignments(&tree, source_bytes, language);

            // Collect confidence values for sanitizers
            let sanitizer_confidence: Vec<Option<f32>> = sanitizers
                .iter()
                .map(|s| taint_engine.get_sanitizer_confidence(s))
                .collect();

            (
                sources,
                sinks,
                sanitizers,
                sanitizer_confidence,
                assignments,
            )
        }; // Lock released here

        debug!(
            file = %file_str,
            sources = sources.len(),
            sinks = sinks.len(),
            sanitizers = sanitizers.len(),
            "Taint analysis results"
        );

        // Setup data flow context
        let mut ctx = self.data_flow_context.write().await;
        ctx.enter_function(&file_str);
        let analyzer = ctx.get_analyzer(&file_str);

        // Mark all detected sources as tainted
        for source in &sources {
            let var_name = source
                .variable_name
                .as_deref()
                .unwrap_or(&source.matched_text);

            analyzer.mark_tainted(
                var_name,
                &source.pattern_name,
                &file_str,
                source.line as u32 + 1, // Convert to 1-indexed
                source.column as u32,
            );

            debug!(
                var = %var_name,
                source = %source.pattern_name,
                category = %source.category,
                line = source.line + 1,
                "Marked tainted from AST pattern"
            );
        }

        // Propagate taint through assignments
        // If a tainted variable is assigned to another variable, mark the target as tainted
        // We iterate multiple times to handle transitive propagation (a = b; c = a)
        let mut changed = true;
        let max_iterations = 10; // Prevent infinite loops
        let mut iteration = 0;

        while changed && iteration < max_iterations {
            changed = false;
            iteration += 1;

            for (target, source_expr, line, column) in &assignments {
                // Skip if target is already tainted
                if analyzer.is_tainted(target) {
                    continue;
                }

                // Check if the source expression contains any tainted source
                // This handles both direct source references and method chain results
                for source in &sources {
                    // Check both variable_name and matched_text
                    let source_var = source
                        .variable_name
                        .as_deref()
                        .unwrap_or(&source.matched_text);

                    // The source expression should contain some part of the tainted source
                    // This handles cases like:
                    // - Direct: targetURL := r.URL.Query().Get("url")
                    // - Indirect: targetURL := someVar (where someVar was tainted)
                    let source_in_expr = source_expr.contains(source_var)
                        || source_expr.contains(&source.matched_text);

                    if source_in_expr {
                        analyzer.mark_tainted(
                            target,
                            &format!("propagated from {}", source_var),
                            &file_str,
                            *line as u32 + 1,
                            *column as u32,
                        );
                        debug!(
                            target = %target,
                            source_var = %source_var,
                            source_expr = %source_expr,
                            line = line + 1,
                            "Propagated taint through assignment"
                        );
                        changed = true;
                        break;
                    }
                }

                // Also check if the source_expr contains any already-tainted variable
                // This handles transitive propagation
                if !changed {
                    // Check each previously tainted variable (from sources and propagation)
                    for prev_source in &sources {
                        let prev_var = prev_source
                            .variable_name
                            .as_deref()
                            .unwrap_or(&prev_source.matched_text);
                        if source_expr.contains(prev_var) && analyzer.is_tainted(prev_var) {
                            analyzer.mark_tainted(
                                target,
                                &format!("propagated from {}", prev_var),
                                &file_str,
                                *line as u32 + 1,
                                *column as u32,
                            );
                            debug!(
                                target = %target,
                                prev_var = %prev_var,
                                line = line + 1,
                                "Propagated taint transitively"
                            );
                            changed = true;
                            break;
                        }
                    }
                }
            }
        }

        // Apply sanitizers - either clear taint or reduce confidence
        for (idx, sanitizer) in sanitizers.iter().enumerate() {
            let var_name = sanitizer
                .variable_name
                .as_deref()
                .unwrap_or(&sanitizer.matched_text);

            if sanitizer.is_known {
                // Known sanitizer - clear taint completely
                analyzer.sanitize(
                    var_name,
                    &sanitizer.pattern_name,
                    &file_str,
                    sanitizer.line as u32 + 1,
                    sanitizer.column as u32,
                );
                debug!(
                    var = %var_name,
                    sanitizer = %sanitizer.pattern_name,
                    "Cleared taint (known sanitizer)"
                );
            } else {
                // Generic validation - we still track but note the confidence reduction
                let confidence = sanitizer_confidence
                    .get(idx)
                    .copied()
                    .flatten()
                    .unwrap_or(1.0);
                debug!(
                    var = %var_name,
                    sanitizer = %sanitizer.pattern_name,
                    confidence = confidence,
                    "Generic validation detected (confidence reduced)"
                );
                // Note: For full implementation, we'd store reduced confidence in TaintState
            }
        }

        // Check sinks for tainted data
        for sink in &sinks {
            // Try to find a tainted variable in the sink expression
            let sink_var = sink.variable_name.as_deref().unwrap_or(&sink.matched_text);

            // Check if any of our tracked tainted variables appear in this sink
            // CRITICAL: Only consider variables that are STILL tainted (not sanitized)
            // This filters out variables that have been cleared by sanitizers
            let potential_taints: Vec<&str> = sources
                .iter()
                .filter_map(|s| s.variable_name.as_deref())
                .filter(|var| analyzer.is_tainted(var))
                .collect();

            for tainted_var in potential_taints {
                if sink.matched_text.contains(tainted_var) || sink_var == tainted_var {
                    if let Some(data_flow_finding) = analyzer.check_sink(
                        tainted_var,
                        &sink.pattern_name,
                        &file_str,
                        sink.line as u32 + 1,
                        sink.column as u32,
                    ) {
                        // Build the finding with data flow path
                        let source_node = DataFlowNode {
                            location: Location {
                                file_path: data_flow_finding.source.file.clone(),
                                line: data_flow_finding.source.line,
                                column: Some(data_flow_finding.source.column),
                                end_line: Some(data_flow_finding.source.line),
                                end_column: None,
                            },
                            description: data_flow_finding
                                .source
                                .note
                                .unwrap_or_else(|| "Taint source".to_string()),
                            expression: data_flow_finding.source.expression.clone(),
                        };

                        let sink_node = DataFlowNode {
                            location: Location {
                                file_path: data_flow_finding.sink.file.clone(),
                                line: data_flow_finding.sink.line,
                                column: Some(data_flow_finding.sink.column),
                                end_line: Some(data_flow_finding.sink.line),
                                end_column: None,
                            },
                            description: data_flow_finding
                                .sink
                                .note
                                .unwrap_or_else(|| "Taint sink".to_string()),
                            expression: data_flow_finding.sink.expression.clone(),
                        };

                        let steps: Vec<DataFlowNode> = data_flow_finding
                            .intermediate_steps
                            .iter()
                            .map(|step| DataFlowNode {
                                location: Location {
                                    file_path: step.file.clone(),
                                    line: step.line,
                                    column: Some(step.column),
                                    end_line: Some(step.line),
                                    end_column: None,
                                },
                                description: step
                                    .note
                                    .clone()
                                    .unwrap_or_else(|| "Propagation".to_string()),
                                expression: step.expression.clone(),
                            })
                            .collect();

                        let finding = SastFinding {
                            id: uuid::Uuid::new_v4().to_string(),
                            rule_id: format!("data-flow-{}", sink.category),
                            location: Location {
                                file_path: file_str.clone(),
                                line: sink.line as u32 + 1,
                                column: Some(sink.column as u32),
                                end_line: Some(sink.end_line as u32 + 1),
                                end_column: Some(sink.end_column as u32),
                            },
                            severity: Severity::High,
                            confidence: crate::domain::value_objects::Confidence::High,
                            description: format!(
                                "Tainted data from {} flows to {}: {}",
                                data_flow_finding.source.expression,
                                sink.category,
                                sink.pattern_name
                            ),
                            recommendation: Some(format!(
                                "Sanitize or validate the data before passing to {}. \
                                 Consider using appropriate escaping for {} context.",
                                sink.pattern_name, sink.category
                            )),
                            data_flow_path: Some(DataFlowPath {
                                source: source_node,
                                sink: sink_node,
                                steps,
                            }),
                            snippet: Some(sink.matched_text.clone()),
                        };
                        findings.push(finding);
                    }
                }
            }
        }
    }

    /// Adjust severity for findings confirmed by data flow analysis
    fn adjust_severity_for_data_flow(findings: &mut Vec<SastFinding>) {
        for finding in findings.iter_mut() {
            if finding.data_flow_path.is_some() {
                // Escalate severity when data flow confirms the vulnerability
                match finding.severity {
                    Severity::Low => finding.severity = Severity::Medium,
                    Severity::Medium => finding.severity = Severity::High,
                    Severity::High => finding.severity = Severity::Critical,
                    _ => {}
                }
            }
        }
    }

    fn deduplicate_findings(findings: Vec<SastFinding>) -> Vec<SastFinding> {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        findings
            .into_iter()
            .filter(|f| {
                let key = format!("{}:{}:{}", f.rule_id, f.location.file_path, f.location.line);
                seen.insert(key)
            })
            .collect()
    }

    /// Extract assignment statements from AST for taint propagation
    /// Returns tuples of (target_variable, source_expression, line, column)
    fn extract_assignments(
        tree: &tree_sitter::Tree,
        source_code: &[u8],
        language: &Language,
    ) -> Vec<(String, String, usize, usize)> {
        let mut assignments = Vec::new();
        let queries = get_propagation_queries(language);

        // Get tree-sitter language
        let ts_language = match language {
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            Language::JavaScript | Language::TypeScript => tree_sitter_javascript::LANGUAGE.into(),
            Language::Go => tree_sitter_go::LANGUAGE.into(),
            Language::Rust => tree_sitter_rust::LANGUAGE.into(),
            Language::C => tree_sitter_c::LANGUAGE.into(),
            Language::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        };

        for query_str in queries {
            let query = match tree_sitter::Query::new(&ts_language, query_str) {
                Ok(q) => q,
                Err(e) => {
                    debug!(
                        language = %language,
                        error = %e,
                        "Failed to compile propagation query"
                    );
                    continue;
                }
            };

            let mut cursor = tree_sitter::QueryCursor::new();
            let mut matches = cursor.matches(&query, tree.root_node(), source_code);

            while let Some(m) = {
                matches.advance();
                matches.get()
            } {
                let mut target: Option<String> = None;
                let mut source: Option<String> = None;
                let mut line = 0;
                let mut column = 0;

                for capture in m.captures {
                    let capture_name = query.capture_names()[capture.index as usize];
                    let text = capture
                        .node
                        .utf8_text(source_code)
                        .unwrap_or_default()
                        .to_string();

                    match capture_name {
                        "target" => {
                            target = Some(text);
                            line = capture.node.start_position().row;
                            column = capture.node.start_position().column;
                        }
                        "source" => {
                            source = Some(text);
                        }
                        _ => {}
                    }
                }

                if let (Some(t), Some(s)) = (target, source) {
                    assignments.push((t, s, line, column));
                }
            }
        }

        assignments
    }

    fn is_test_file(path: &Path, content: &str) -> bool {
        let path_str = path.display().to_string();
        if path_str.contains("/tests/")
            || path_str.contains("/test/")
            || path_str.ends_with("_test.rs")
            || path_str.ends_with("_test.py")
            || path_str.ends_with(".test.js")
            || path_str.ends_with(".test.ts")
            || path_str.ends_with("_test.go")
            || path_str.contains("/benches/")
            || path_str.contains("/examples/")
        {
            return true;
        }

        if content.contains("#[cfg(test)]") || content.contains("#[test]") {
            return true;
        }

        false
    }
}

impl Default for ScanProjectUseCase {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    ParseFailed(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Query engine error: {0}")]
    QueryEngineError(String),
}
