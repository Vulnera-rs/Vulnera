//! SAST use cases
//!
//! Native SAST analysis pipeline with:
//! - Tree-sitter as the primary analysis engine (S-expression pattern queries)
//! - Inter-procedural data flow analysis (taint tracking)
//! - Call graph analysis for cross-function vulnerability detection
//! - SARIF v2.1.0 export

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use streaming_iterator::StreamingIterator;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

use vulnera_core::config::{AnalysisDepth, SastConfig};

use crate::domain::{
    DataFlowFinding, DataFlowNode, DataFlowPath, FileSuppressions, Finding as SastFinding,
    Location, Pattern, Rule, Severity,
};
use crate::domain::value_objects::{AnalysisEngine, Language};
use crate::infrastructure::ast_cache::AstCacheService;
use crate::infrastructure::call_graph::CallGraphBuilder;
use crate::infrastructure::data_flow::{InterProceduralContext, TaintMatch};
use crate::infrastructure::sast_engine::{SastEngine, SastEngineHandle};
use crate::infrastructure::rules::{RuleEngine, RuleRepository};
use crate::infrastructure::sarif::{SarifExporter, SarifExporterConfig};
use crate::infrastructure::scanner::DirectoryScanner;
use crate::infrastructure::taint_queries::{get_propagation_queries, TaintConfig};

/// Result of a SAST scan
#[derive(Debug)]
pub struct ScanResult {
    /// Detected security findings
    pub findings: Vec<SastFinding>,
    /// Number of files successfully scanned
    pub files_scanned: usize,
    /// Number of files skipped (too large, binary, etc.)
    pub files_skipped: usize,
    /// Number of files that failed to parse or analyze
    pub files_failed: usize,
    /// Analysis engine used
    pub analysis_engine: AnalysisEngine,
    /// Errors encountered during analysis (non-fatal)
    pub errors: Vec<String>,
    /// Total scan duration in milliseconds
    pub duration_ms: u64,
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
    /// Enable dynamic depth selection based on repository size
    pub dynamic_depth_enabled: bool,
    /// File count threshold to reduce depth (None = disabled)
    pub dynamic_depth_file_count_threshold: Option<usize>,
    /// Total bytes threshold to reduce depth (None = disabled)
    pub dynamic_depth_total_bytes_threshold: Option<u64>,
    /// Maximum number of cached parsed trees per scan
    pub tree_cache_max_entries: usize,
    /// Maximum file size to analyze in bytes (files larger are skipped)
    pub max_file_size_bytes: u64,
    /// Per-file analysis timeout in seconds
    pub per_file_timeout_seconds: u64,
    /// Overall scan timeout in seconds (None = no limit)
    pub scan_timeout_seconds: Option<u64>,
    /// Maximum findings per file (prevents memory explosion)
    pub max_findings_per_file: usize,
    /// Maximum total findings across all files (None = no limit)
    pub max_total_findings: Option<usize>,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            enable_ast_cache: true,
            ast_cache_ttl_hours: 1,
            max_concurrent_files: 8,
            enable_data_flow: true,
            enable_call_graph: true,
            analysis_depth: AnalysisDepth::Standard,
            dynamic_depth_enabled: false,
            dynamic_depth_file_count_threshold: None,
            dynamic_depth_total_bytes_threshold: None,
            tree_cache_max_entries: 1024,
            max_file_size_bytes: 1_048_576, // 1MB
            per_file_timeout_seconds: 30,
            scan_timeout_seconds: None,
            max_findings_per_file: 100,
            max_total_findings: None,
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
            dynamic_depth_enabled: config.dynamic_depth_enabled.unwrap_or(false),
            dynamic_depth_file_count_threshold: config.dynamic_depth_file_count_threshold,
            dynamic_depth_total_bytes_threshold: config.dynamic_depth_total_bytes_threshold,
            tree_cache_max_entries: config.tree_cache_max_entries.unwrap_or(1024),
            max_file_size_bytes: config.max_file_size_bytes.unwrap_or(1_048_576),
            per_file_timeout_seconds: config.per_file_timeout_seconds.unwrap_or(30),
            scan_timeout_seconds: config.scan_timeout_seconds,
            max_findings_per_file: config.max_findings_per_file.unwrap_or(100),
            max_total_findings: config.max_total_findings,
        }
    }
}

/// AST cache statistics for observability
#[derive(Debug, Default, Clone)]
struct AstCacheStats {
    l1_hits: u64,
    l1_misses: u64,
    l2_hits: u64,
    l2_misses: u64,
}

/// Production-ready use case for scanning a project
pub struct ScanProjectUseCase {
    scanner: DirectoryScanner,
    rule_repository: Arc<RwLock<RuleRepository>>,
    sast_engine: SastEngineHandle,
    /// AST cache for parsed file caching (Dragonfly-backed)
    ast_cache: Option<Arc<dyn AstCacheService>>,
    /// Inter-procedural data flow context
    data_flow_context: Arc<RwLock<InterProceduralContext>>,
    /// Call graph builder
    call_graph_builder: Arc<RwLock<CallGraphBuilder>>,
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
            sast_engine: Arc::new(SastEngine::new()),
            ast_cache: None,
            data_flow_context: Arc::new(RwLock::new(InterProceduralContext::new())),
            call_graph_builder: Arc::new(RwLock::new(CallGraphBuilder::new())),
            config: analysis_config,
        }
    }

    /// Add AST cache service for parsed file caching
    ///
    /// When enabled, parsed ASTs are cached by content hash in Dragonfly,
    /// reducing parse time for unchanged files.
    pub fn with_ast_cache(mut self, cache: Arc<dyn AstCacheService>) -> Self {
        self.ast_cache = Some(cache);
        self
    }

    fn update_l2_cache_stats(stats: &mut AstCacheStats, hit: bool) {
        if hit {
            stats.l2_hits = stats.l2_hits.saturating_add(1);
        } else {
            stats.l2_misses = stats.l2_misses.saturating_add(1);
        }
    }

    fn compute_content_hash(&self, content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn resolve_analysis_depth(&self, file_count: usize, total_bytes: u64) -> AnalysisDepth {
        if !self.config.dynamic_depth_enabled {
            return self.config.analysis_depth;
        }

        let exceeds_file = self
            .config
            .dynamic_depth_file_count_threshold
            .map(|t| file_count >= t)
            .unwrap_or(false);
        let exceeds_bytes = self
            .config
            .dynamic_depth_total_bytes_threshold
            .map(|t| total_bytes >= t)
            .unwrap_or(false);

        if exceeds_file || exceeds_bytes {
            match self.config.analysis_depth {
                AnalysisDepth::Deep => AnalysisDepth::Standard,
                AnalysisDepth::Standard => AnalysisDepth::Quick,
                AnalysisDepth::Quick => AnalysisDepth::Quick,
            }
        } else {
            self.config.analysis_depth
        }
    }

    #[instrument(skip(self), fields(root = %root.display()))]
    pub async fn execute(&self, root: &Path) -> Result<ScanResult, ScanError> {
        let start_time = std::time::Instant::now();
        info!("Starting native SAST scan");

        let files = self.scanner.scan(root).map_err(|e| {
            error!(error = %e, "Failed to scan directory");
            ScanError::Io(e)
        })?;

        let file_count = files.len();
        let total_bytes: u64 = files
            .iter()
            .filter_map(|file| std::fs::metadata(&file.path).ok().map(|meta| meta.len()))
            .sum();
        let effective_depth = self.resolve_analysis_depth(file_count, total_bytes);
        info!(
            file_count,
            total_bytes,
            configured_depth = ?self.config.analysis_depth,
            effective_depth = ?effective_depth,
            "Found files to scan"
        );

        let mut all_findings = Vec::new();
        let mut files_scanned = 0;
        let mut files_skipped = 0;
        let mut files_failed = 0;
        let mut errors: Vec<String> = Vec::new();
        let mut ast_cache_stats = AstCacheStats::default();

        let rules = self.rule_repository.read().await;
        let all_rules = rules.get_all_rules();

        // =========================================================================
        // Phase 1: Build Call Graph & Parse All Files
        // =========================================================================
        // In enterprise mode, we first build the complete call graph by parsing
        // all files, then resolve cross-file references before analysis.

        let mut parsed_files: HashMap<String, (tree_sitter::Tree, String)> = HashMap::new();

        if self.config.enable_call_graph && effective_depth != AnalysisDepth::Quick {
            debug!("Phase 1: Building call graph with cross-file resolution");
            let mut call_graph = self.call_graph_builder.write().await;
            let mut query_engine = SastEngine::new();

            // 1a. Parse all files and build initial graph
            for file in &files {
                if let Ok(content) = std::fs::read_to_string(&file.path) {
                    let file_path_str = file.path.display().to_string();

                    let tree = match query_engine.parse(&content, file.language).await {
                        Ok(tree) => tree,
                        Err(_) => continue,
                    };

                    // Build call graph nodes and edges
                    call_graph.analyze_ast(
                        &file_path_str,
                        &tree,
                        &file.language,
                        &content,
                        &mut query_engine,
                    );

                    // Cache the parsed tree for reuse in analysis phase
                    if parsed_files.len() < self.config.tree_cache_max_entries {
                        parsed_files.insert(file_path_str, (tree, content));
                    }
                }
            }

            // 1b. Resolve cross-file references
            let resolved_count = call_graph.graph_mut().resolve_all_calls();
            let stats = call_graph.graph().stats();

            info!(
                functions = stats.total_functions,
                calls = stats.total_calls,
                resolved = resolved_count,
                entry_points = stats.entry_points,
                "Call graph built with cross-file resolution"
            );
        }

        // =========================================================================
        // Phase 2: File Analysis (Pattern Matching & Data Flow)
        // =========================================================================
        for file in files {
            // Check file size limit
            let file_size = match std::fs::metadata(&file.path) {
                Ok(meta) => meta.len(),
                Err(e) => {
                    debug!(file = %file.path.display(), error = %e, "Failed to get file metadata");
                    files_skipped += 1;
                    continue;
                }
            };

            if file_size > self.config.max_file_size_bytes {
                debug!(
                    file = %file.path.display(),
                    file_size,
                    max_size = self.config.max_file_size_bytes,
                    "Skipping file: exceeds size limit"
                );
                files_skipped += 1;
                continue;
            }

            debug!(file = %file.path.display(), language = ?file.language, "Scanning file");

            let content = match std::fs::read_to_string(&file.path) {
                Ok(content) => content,
                Err(e) => {
                    warn!(file = %file.path.display(), error = %e, "Failed to read file");
                    files_failed += 1;
                    errors.push(format!("Failed to read {}: {}", file.path.display(), e));
                    continue;
                }
            };

            let file_path_str = file.path.display().to_string();
            let content_hash = self.compute_content_hash(&content);
            let mut cached_tree = parsed_files
                .get(&file_path_str)
                .map(|(tree, _)| tree.clone());

            if cached_tree.is_some() {
                ast_cache_stats.l1_hits = ast_cache_stats.l1_hits.saturating_add(1);
            } else {
                ast_cache_stats.l1_misses = ast_cache_stats.l1_misses.saturating_add(1);
            }

            if cached_tree.is_none() {
                if let Some(cache) = self.ast_cache.as_ref() {
                    match cache.get(&content_hash, &file.language).await {
                        Ok(Some(_)) => Self::update_l2_cache_stats(&mut ast_cache_stats, true),
                        Ok(None) => Self::update_l2_cache_stats(&mut ast_cache_stats, false),
                        Err(e) => {
                            warn!(error = %e, "Failed to read L2 AST cache");
                        }
                    }
                }

                let query_engine = SastEngine::new();
                match query_engine.parse(&content, file.language).await {
                    Ok(tree) => {
                        cached_tree = Some(tree);
                    }
                    Err(_) => {}
                }
            }

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
            if let Err(e) = self
                .execute_tree_sitter_analysis(
                    &file.path,
                    &file.language,
                    &content,
                    &applicable_rules,
                    &suppressions,
                    is_test_context,
                    cached_tree.as_ref(),
                    &mut all_findings,
                )
                .await
            {
                warn!(file = %file.path.display(), error = %e, "Tree-sitter analysis failed");
                errors.push(format!(
                    "Analysis failed for {}: {}",
                    file.path.display(),
                    e
                ));
            }

            // Phase 3: Data flow analysis
            if self.config.enable_data_flow && effective_depth != AnalysisDepth::Quick {
                self.execute_data_flow_analysis(
                    &file.path,
                    &file.language,
                    &content,
                    cached_tree.as_ref(),
                    &mut all_findings,
                )
                .await;
            }

            // Check max findings per file limit
            let file_finding_count = all_findings
                .iter()
                .filter(|f| f.location.file_path == file.path.display().to_string())
                .count();
            if file_finding_count >= self.config.max_findings_per_file {
                debug!(
                    file = %file.path.display(),
                    count = file_finding_count,
                    "Max findings per file limit reached"
                );
            }

            // Check max total findings limit
            if let Some(max_total) = self.config.max_total_findings {
                if all_findings.len() >= max_total {
                    info!(
                        total_findings = all_findings.len(),
                        max_total, "Max total findings limit reached, stopping scan early"
                    );
                    break;
                }
            }
        }

        // Phase 4: Adjust severity for data-flow confirmed findings
        if self.config.enable_data_flow && effective_depth != AnalysisDepth::Quick {
            Self::adjust_severity_for_data_flow(&mut all_findings);
        }

        all_findings = Self::deduplicate_findings(all_findings);

        let duration_ms = start_time.elapsed().as_millis() as u64;
        info!(
            l1_hits = ast_cache_stats.l1_hits,
            l1_misses = ast_cache_stats.l1_misses,
            l2_hits = ast_cache_stats.l2_hits,
            l2_misses = ast_cache_stats.l2_misses,
            "SAST AST cache stats"
        );
        info!(
            finding_count = all_findings.len(),
            files_scanned, files_skipped, files_failed, duration_ms, "SAST scan completed"
        );

        Ok(ScanResult {
            findings: all_findings,
            files_scanned,
            files_skipped,
            files_failed,
            analysis_engine: AnalysisEngine::TreeSitter,
            errors,
            duration_ms,
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
        tree: Option<&tree_sitter::Tree>,
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

        let results = {
            self.sast_engine
                .query_batch(content, *language, &ts_rules)
                .await
        };

        // Get sast_engine for match_to_finding
        let sast_engine = Arc::clone(&self.sast_engine);

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

                    let finding = sast_engine.match_to_finding(
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
        tree: Option<&tree_sitter::Tree>,
        findings: &mut Vec<SastFinding>,
    ) {
        // Skip if data flow is disabled
        if !self.config.enable_data_flow {
            return;
        }

        debug!(file = %file_path.display(), "Running data flow analysis");

        // Parse the file with tree-sitter (outside of any lock)
        let tree = if let Some(tree) = tree {
            tree.clone()
        } else {
            match self.sast_engine.parse(content, *language).await {
                Ok(tree) => tree,
                Err(e) => {
                    warn!(
                        file = %file_path.display(),
                        error = %e,
                        "Failed to parse file for data flow analysis"
                    );
                    return;
                }
            }
        };

        let source_bytes = content.as_bytes();
        let file_str = file_path.display().to_string();

        // Detect sources, sinks, and sanitizers using tree-sitter queries
        let (sources, sinks, sanitizers, sanitizer_confidence, assignments) = {
            let matches = self.sast_engine.detect_taint(&tree, source_bytes, *language, &TaintConfig::default()).await;
            
            // Split matches into sources, sinks, and sanitizers based on their properties
            let sources: Vec<_> = matches.iter().filter(|m| !m.labels.is_empty()).cloned().collect();
            let sinks: Vec<_> = matches.iter().filter(|m| m.labels.is_empty() && m.clears_labels.is_none()).cloned().collect();
            let sanitizers: Vec<_> = matches.iter().filter(|m| m.clears_labels.is_some()).cloned().collect();
            
            let assignments = Self::extract_assignments(&tree, source_bytes, language);

            // Collect confidence values for sanitizers
            let sanitizer_confidence: Vec<Option<f32>> = sanitizers
                .iter()
                .map(|s| if s.is_known { None } else { Some(0.5) })
                .collect();

            (
                sources,
                sinks,
                sanitizers,
                sanitizer_confidence,
                assignments,
            )
        };

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
        let mut changed = true;
        let max_iterations = 10; // Prevent infinite loops
        let mut iteration = 0;

        // Create a set of sanitized variables to block propagation
        let sanitized_vars: std::collections::HashSet<&str> = sanitizers
            .iter()
            .filter_map(|s| s.variable_name.as_deref().or(Some(&s.matched_text)))
            .collect();

        tracing::trace!(
            sanitized_vars = ?sanitized_vars,
            "Sanitized variables blocking taint propagation"
        );

        while changed && iteration < max_iterations {
            changed = false;
            iteration += 1;

            for (target, source_expr, line, column) in &assignments {
                // Skip if target is already tainted
                if analyzer.is_tainted(target) {
                    continue;
                }

                // Skip if target is a sanitized variable (prevent re-tainting)
                if sanitized_vars.contains(target.as_str()) {
                    tracing::trace!(
                        target = %target,
                        "Skipping taint propagation to sanitized variable"
                    );
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

            // Strategy 1: Check if the sink variable itself is tainted (Direct Propagation)
            // This handles cases like: x = source; y = x; sink(y)
            if analyzer.is_tainted(sink_var) {
                if let Some(data_flow_finding) = analyzer.check_sink(
                    sink_var,
                    &sink.pattern_name,
                    &file_str,
                    sink.line as u32 + 1,
                    sink.column as u32,
                ) {
                    Self::add_finding(findings, &data_flow_finding, sink, &file_str);
                    continue; // Found a match, move to next sink
                }
            }

            // Strategy 2: Check if any active tainted variable is part of the sink expression
            // This handles cases like: sink("prefix" + source)
            // CRITICAL: Only consider variables that are STILL tainted (not sanitized)
            let active_taints: Vec<&str> = sources
                .iter()
                .filter_map(|s| s.variable_name.as_deref())
                .filter(|var| analyzer.is_tainted(var))
                .collect();

            for tainted_var in active_taints {
                // Skip if we already checked this var as sink_var
                if tainted_var == sink_var {
                    continue;
                }

                // Use regex to check for whole word match to avoid false positives with short var names
                // e.g. "r" matching in "u.String()"
                let pattern = format!(r"\b{}\b", regex::escape(tainted_var));
                let re = regex::Regex::new(&pattern)
                    .unwrap_or_else(|_| regex::Regex::new(tainted_var).unwrap());

                if re.is_match(&sink.matched_text) {
                    if let Some(data_flow_finding) = analyzer.check_sink(
                        tainted_var,
                        &sink.pattern_name,
                        &file_str,
                        sink.line as u32 + 1,
                        sink.column as u32,
                    ) {
                        Self::add_finding(findings, &data_flow_finding, sink, &file_str);
                        // Don't break here, there might be multiple taints in one sink
                    }
                }
            }
        }
    }

    fn add_finding(
        findings: &mut Vec<SastFinding>,
        data_flow_finding: &DataFlowFinding,
        sink: &TaintMatch,
        file_str: &str,
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
                .clone()
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
                .clone()
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
                file_path: file_str.to_string(),
                line: sink.line as u32 + 1,
                column: Some(sink.column as u32),
                end_line: Some(sink.end_line as u32 + 1),
                end_column: Some(sink.end_column as u32),
            },
            severity: Severity::High,
            confidence: crate::domain::value_objects::Confidence::High,
            description: format!(
                "Tainted data from {} flows to {}: {}",
                data_flow_finding.source.expression, sink.category, sink.pattern_name
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
    /// Failed to read a file during scanning
    #[error("Failed to read file '{path}': {message}")]
    FileRead {
        path: std::path::PathBuf,
        message: String,
    },

    /// Failed to parse source code
    #[error("Failed to parse {language} file '{path}': {message}")]
    ParseFailed {
        path: std::path::PathBuf,
        language: String,
        message: String,
        line: Option<u32>,
    },

    /// Query compilation failed for a rule
    #[error("Query compilation failed for rule '{rule_id}': {message}")]
    QueryCompilation { rule_id: String, message: String },

    /// Scan timeout exceeded
    #[error("Scan timeout after {duration_ms}ms for path '{path}'")]
    Timeout {
        path: std::path::PathBuf,
        duration_ms: u64,
    },

    /// Resource limit exceeded
    #[error("Resource limit exceeded: {message}")]
    ResourceLimit { message: String },

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Generic IO error (for backward compatibility)
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl ScanError {
    /// Create a file read error with context
    pub fn file_read(path: impl Into<std::path::PathBuf>, source: std::io::Error) -> Self {
        Self::FileRead {
            path: path.into(),
            message: source.to_string(),
        }
    }

    /// Create a parse error with context
    pub fn parse_failed(
        path: impl Into<std::path::PathBuf>,
        language: &Language,
        message: impl Into<String>,
        line: Option<u32>,
    ) -> Self {
        Self::ParseFailed {
            path: path.into(),
            language: language.to_string(),
            message: message.into(),
            line,
        }
    }

    /// Create a timeout error
    pub fn timeout(path: impl Into<std::path::PathBuf>, duration: std::time::Duration) -> Self {
        Self::Timeout {
            path: path.into(),
            duration_ms: duration.as_millis() as u64,
        }
    }

    /// Create a resource limit error
    pub fn resource_limit(message: impl Into<String>) -> Self {
        Self::ResourceLimit {
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AnalysisConfig, ScanProjectUseCase};
    use vulnera_core::config::{AnalysisDepth, SastConfig};

    fn build_use_case(mut config: AnalysisConfig) -> ScanProjectUseCase {
        config.enable_call_graph = false;
        config.enable_data_flow = false;
        ScanProjectUseCase::with_config(&SastConfig::default(), config)
    }

    #[test]
    fn test_dynamic_depth_disabled_returns_configured() {
        let config = AnalysisConfig {
            analysis_depth: AnalysisDepth::Deep,
            dynamic_depth_enabled: false,
            dynamic_depth_file_count_threshold: Some(10),
            dynamic_depth_total_bytes_threshold: Some(100),
            ..AnalysisConfig::default()
        };

        let use_case = build_use_case(config);
        let depth = use_case.resolve_analysis_depth(10, 100);
        assert_eq!(depth, AnalysisDepth::Deep);
    }

    #[test]
    fn test_dynamic_depth_file_threshold_downgrades() {
        let config = AnalysisConfig {
            analysis_depth: AnalysisDepth::Deep,
            dynamic_depth_enabled: true,
            dynamic_depth_file_count_threshold: Some(10),
            dynamic_depth_total_bytes_threshold: None,
            ..AnalysisConfig::default()
        };

        let use_case = build_use_case(config);
        let depth = use_case.resolve_analysis_depth(10, 0);
        assert_eq!(depth, AnalysisDepth::Standard);
    }

    #[test]
    fn test_dynamic_depth_bytes_threshold_downgrades() {
        let config = AnalysisConfig {
            analysis_depth: AnalysisDepth::Standard,
            dynamic_depth_enabled: true,
            dynamic_depth_file_count_threshold: None,
            dynamic_depth_total_bytes_threshold: Some(100),
            ..AnalysisConfig::default()
        };

        let use_case = build_use_case(config);
        let depth = use_case.resolve_analysis_depth(0, 100);
        assert_eq!(depth, AnalysisDepth::Quick);
    }

    #[test]
    fn test_dynamic_depth_no_threshold_exceeded_keeps_depth() {
        let config = AnalysisConfig {
            analysis_depth: AnalysisDepth::Standard,
            dynamic_depth_enabled: true,
            dynamic_depth_file_count_threshold: Some(100),
            dynamic_depth_total_bytes_threshold: Some(10_000),
            ..AnalysisConfig::default()
        };

        let use_case = build_use_case(config);
        let depth = use_case.resolve_analysis_depth(10, 100);
        assert_eq!(depth, AnalysisDepth::Standard);
    }
}
