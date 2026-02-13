//! SAST use cases
//!
//! Native SAST analysis pipeline with:
//! - Tree-sitter as the primary analysis engine (S-expression pattern queries)
//! - Inter-procedural data flow analysis (taint tracking)
//! - Call graph analysis for cross-function vulnerability detection
//! - SARIF v2.1.0 export

use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use streaming_iterator::StreamingIterator;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

use vulnera_core::config::{AnalysisDepth, SastConfig};

use crate::domain::call_graph::ParameterInfo;
use crate::domain::finding::{
    DataFlowFinding, DataFlowNode, DataFlowPath, Finding as SastFinding, Location, Severity,
};
use crate::domain::pattern_types::PatternRule;
use crate::domain::suppression::FileSuppressions;
use crate::domain::value_objects::Language;
use crate::infrastructure::ast_cache::AstCacheService;
use crate::infrastructure::call_graph::CallGraphBuilder;
use crate::infrastructure::data_flow::{DataFlowAnalyzer, InterProceduralContext, TaintMatch};
use crate::infrastructure::incremental::IncrementalTracker;
use crate::infrastructure::oxc_frontend::OxcFrontend;
use crate::infrastructure::parser_frontend::{
    JavaScriptFrontend, ParserFrontend, ParserFrontendSelector,
};
use crate::infrastructure::parsers::convert_tree_sitter_node;
use crate::infrastructure::regex_cache;
use crate::infrastructure::rules::{
    BuiltinRuleLoader, CompositeRuleLoader, FileRuleLoader, RulePackLoader, RuleRepository,
};
use crate::infrastructure::sarif::{SarifExporter, SarifExporterConfig};
use crate::infrastructure::sast_engine::{SastEngine, SastEngineHandle};
use crate::infrastructure::scanner::{DirectoryScanner, ScanFile};
use crate::infrastructure::semantic::SemanticContext;
use crate::infrastructure::taint_queries::{
    TaintConfig, get_propagation_queries, get_sanitizer_queries,
};

type CallUpdate = (
    String,
    u32,
    u32,
    String,
    Vec<Option<crate::domain::finding::TaintState>>,
);

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
    /// Errors encountered during analysis (non-fatal)
    pub errors: Vec<String>,
    /// Total scan duration in milliseconds
    pub duration_ms: u64,
}

impl ScanResult {
    /// Export findings to SARIF JSON string
    pub fn to_sarif_json(
        &self,
        rules: &[PatternRule],
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

// ─── Default value helpers ──────────────────
const fn default_true() -> bool {
    true
}
const fn default_ast_cache_ttl() -> u64 {
    4
}
const fn default_max_concurrent() -> usize {
    8
}
const fn default_tree_cache_max() -> usize {
    1024
}
const fn default_max_file_size() -> u64 {
    1_048_576
}
const fn default_per_file_timeout() -> u64 {
    30
}
const fn default_max_findings_per_file() -> usize {
    100
}
fn default_js_ts_frontend() -> JavaScriptFrontend {
    JavaScriptFrontend::OxcPreferred
}

fn parse_js_ts_frontend(value: Option<&str>) -> JavaScriptFrontend {
    match value
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("tree_sitter") => JavaScriptFrontend::TreeSitter,
        Some("oxc_preferred") => JavaScriptFrontend::OxcPreferred,
        _ => default_js_ts_frontend(),
    }
}
fn default_depth_file_threshold() -> Option<usize> {
    Some(500)
}
fn default_depth_bytes_threshold() -> Option<u64> {
    Some(52_428_800)
} // 50 MB

/// Configuration for the analysis pipeline.
///
/// All fields carry sensible defaults via `#[serde(default)]`, so typical usage
/// only needs `AnalysisConfig::default()` or `AnalysisConfig::from(&sast_config)`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalysisConfig {
    /// Enable AST caching via Dragonfly
    #[serde(default = "default_true")]
    pub enable_ast_cache: bool,
    /// AST cache TTL in hours
    #[serde(default = "default_ast_cache_ttl")]
    pub ast_cache_ttl_hours: u64,
    /// Maximum concurrent file analysis
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_files: usize,
    /// Enable inter-procedural data flow analysis
    #[serde(default = "default_true")]
    pub enable_data_flow: bool,
    /// Enable call graph analysis
    #[serde(default = "default_true")]
    pub enable_call_graph: bool,
    /// Analysis depth: Quick, Standard, or Deep
    pub analysis_depth: AnalysisDepth,
    /// Enable dynamic depth auto-detection based on repository size (opt-out)
    #[serde(default = "default_true")]
    pub dynamic_depth_enabled: bool,
    /// File count threshold to reduce depth (default: 500 files)
    #[serde(default = "default_depth_file_threshold")]
    pub dynamic_depth_file_count_threshold: Option<usize>,
    /// Total bytes threshold to reduce depth (default: 50 MB)
    #[serde(default = "default_depth_bytes_threshold")]
    pub dynamic_depth_total_bytes_threshold: Option<u64>,
    /// Maximum number of cached parsed trees per scan
    #[serde(default = "default_tree_cache_max")]
    pub tree_cache_max_entries: usize,
    /// Maximum file size to analyze in bytes (files larger are skipped)
    #[serde(default = "default_max_file_size")]
    pub max_file_size_bytes: u64,
    /// Per-file analysis timeout in seconds
    #[serde(default = "default_per_file_timeout")]
    pub per_file_timeout_seconds: u64,
    /// Overall scan timeout in seconds (None = no limit)
    pub scan_timeout_seconds: Option<u64>,
    /// Maximum findings per file (prevents memory explosion)
    #[serde(default = "default_max_findings_per_file")]
    pub max_findings_per_file: usize,
    /// Maximum total findings across all files (None = no limit)
    pub max_total_findings: Option<usize>,
    /// Path to incremental state file (None = full scan every time)
    pub incremental_state_path: Option<PathBuf>,
    /// Preferred parser frontend strategy for JavaScript/TypeScript.
    #[serde(default = "default_js_ts_frontend")]
    pub js_ts_frontend: JavaScriptFrontend,
}

impl From<&SastConfig> for AnalysisConfig {
    fn from(config: &SastConfig) -> Self {
        Self {
            enable_ast_cache: config.enable_ast_cache.unwrap_or(default_true()),
            ast_cache_ttl_hours: config
                .ast_cache_ttl_hours
                .unwrap_or(default_ast_cache_ttl()),
            max_concurrent_files: config
                .max_concurrent_files
                .unwrap_or(default_max_concurrent()),
            enable_data_flow: config.enable_data_flow,
            enable_call_graph: config.enable_call_graph,
            analysis_depth: config.analysis_depth,
            dynamic_depth_enabled: config.dynamic_depth_enabled.unwrap_or(default_true()),
            dynamic_depth_file_count_threshold: config
                .dynamic_depth_file_count_threshold
                .or_else(default_depth_file_threshold),
            dynamic_depth_total_bytes_threshold: config
                .dynamic_depth_total_bytes_threshold
                .or_else(default_depth_bytes_threshold),
            tree_cache_max_entries: config
                .tree_cache_max_entries
                .unwrap_or(default_tree_cache_max()),
            max_file_size_bytes: config
                .max_file_size_bytes
                .unwrap_or(default_max_file_size()),
            per_file_timeout_seconds: config
                .per_file_timeout_seconds
                .unwrap_or(default_per_file_timeout()),
            scan_timeout_seconds: config.scan_timeout_seconds,
            max_findings_per_file: config
                .max_findings_per_file
                .unwrap_or(default_max_findings_per_file()),
            max_total_findings: config.max_total_findings,
            incremental_state_path: config.incremental_state_path.clone(),
            js_ts_frontend: parse_js_ts_frontend(config.js_ts_frontend.as_deref()),
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

#[derive(Debug, Clone)]
struct LineRange {
    start_line: u32,
    end_line: u32,
}

#[derive(Debug, Clone)]
struct FunctionRange {
    id: String,
    start_line: u32,
    end_line: u32,
    parameters: Vec<ParameterInfo>,
}

#[derive(Debug, Clone)]
struct CallAssignment {
    target: String,
    callee: String,
    args: Vec<String>,
    line: usize,
    column: usize,
}

#[derive(Debug)]
struct ScanPlan {
    files: Vec<ScanFile>,
    rules: Vec<PatternRule>,
    effective_depth: AnalysisDepth,
    effective_parallelism: usize,
    ast_cache_ttl: Duration,
}

#[derive(Debug, Default)]
struct AnalysisStageResult {
    findings: Vec<SastFinding>,
    files_scanned: usize,
    files_skipped: usize,
    files_failed: usize,
    errors: Vec<String>,
}

/// Production-ready use case for scanning a project
pub struct ScanProjectUseCase {
    scanner: DirectoryScanner,
    rule_repository: Arc<RwLock<RuleRepository>>,
    sast_engine: SastEngineHandle,
    /// AST cache for parsed file caching (Dragonfly-backed)
    ast_cache: Option<Arc<dyn AstCacheService>>,
    /// Taint configuration (built-in + custom)
    taint_config: TaintConfig,
    /// Inter-procedural data flow context
    data_flow_context: Arc<RwLock<InterProceduralContext>>,
    /// Call graph builder
    call_graph_builder: Arc<RwLock<CallGraphBuilder>>,
    /// Content-hash tracker for incremental analysis (skip unchanged files)
    incremental_tracker: Mutex<Option<IncrementalTracker>>,
    /// OXC parser frontend for JS/TS primary parsing lane.
    oxc_frontend: OxcFrontend,
    /// Parser frontend selector for language-specific routing.
    parser_frontend_selector: ParserFrontendSelector,
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

        let mut loaders: Vec<Box<dyn crate::infrastructure::rules::RuleLoader>> =
            vec![Box::new(BuiltinRuleLoader::new())];

        if let Some(ref rule_file_path) = sast_config.rule_file_path {
            loaders.push(Box::new(FileRuleLoader::new(rule_file_path)));
        }

        if !sast_config.rule_packs.is_empty() {
            loaders.push(Box::new(RulePackLoader::new(
                sast_config.rule_packs.clone(),
                sast_config.rule_pack_allowlist.clone(),
            )));
        }

        let rule_repository = RuleRepository::from_loader(&CompositeRuleLoader::new(loaders));

        // Load incremental state if path is configured
        let incremental_tracker = analysis_config
            .incremental_state_path
            .as_deref()
            .map(|path| {
                IncrementalTracker::load_from_file(path).unwrap_or_else(|e| {
                    warn!(error = %e, "Failed to load incremental state, starting fresh");
                    IncrementalTracker::new()
                })
            });

        let taint_config = Self::load_taint_config(sast_config);

        Self {
            scanner,
            rule_repository: Arc::new(RwLock::new(rule_repository)),
            sast_engine: Arc::new(SastEngine::new()),
            ast_cache: None,
            taint_config,
            data_flow_context: Arc::new(RwLock::new(InterProceduralContext::new())),
            call_graph_builder: Arc::new(RwLock::new(CallGraphBuilder::new())),
            incremental_tracker: Mutex::new(incremental_tracker),
            oxc_frontend: OxcFrontend,
            parser_frontend_selector: ParserFrontendSelector::new(analysis_config.js_ts_frontend),
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

    fn compute_content_hash(content: &str) -> String {
        IncrementalTracker::hash_content(content)
    }

    fn load_taint_config(sast_config: &SastConfig) -> TaintConfig {
        let mut config = TaintConfig::default();

        if let Some(ref path) = sast_config.taint_config_path {
            match TaintConfig::from_file(path) {
                Ok(file_config) => {
                    config.merge(file_config);
                    info!(path = %path.display(), "Loaded custom taint configuration");
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "Failed to load taint configuration");
                }
            }
        }

        config
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

    fn resolve_effective_parallelism(&self, file_count: usize, total_bytes: u64) -> usize {
        let configured = self.config.max_concurrent_files.max(1);
        let cpu_cap = std::thread::available_parallelism()
            .map(|n| n.get().saturating_mul(2))
            .unwrap_or(2)
            .max(1);
        let mut effective = configured.min(cpu_cap).max(1);

        if file_count < 16 {
            effective = 1;
        } else if file_count < 64 {
            effective = effective.min(4);
        }

        if total_bytes > 268_435_456 {
            effective = (effective / 2).max(1);
        }

        effective
    }

    #[instrument(skip(self), fields(root = %root.display()))]
    pub async fn execute(&self, root: &Path) -> Result<ScanResult, ScanError> {
        let start_time = std::time::Instant::now();
        info!("Starting native SAST scan");

        let plan = self.build_scan_plan(root).await?;

        let (parsed_files, mut stage_index_errors) = self
            .build_parse_index_stage(
                &plan.files,
                plan.effective_depth,
                plan.effective_parallelism,
                plan.ast_cache_ttl,
            )
            .await;

        let mut ast_cache_stats = AstCacheStats::default();
        let mut stage_analysis = self
            .run_analysis_stage(
                &plan.files,
                &plan.rules,
                plan.effective_depth,
                plan.ast_cache_ttl,
                &parsed_files,
                &mut ast_cache_stats,
            )
            .await;

        stage_analysis.errors.append(&mut stage_index_errors);

        if self.config.enable_data_flow && plan.effective_depth != AnalysisDepth::Quick {
            Self::adjust_severity_for_data_flow(&mut stage_analysis.findings);
        }

        stage_analysis.findings = Self::deduplicate_findings(stage_analysis.findings);

        {
            let mut tracker = self.incremental_tracker.lock().unwrap();
            if let Some(ref mut t) = *tracker {
                t.finalize(
                    stage_analysis.files_scanned + stage_analysis.files_skipped,
                    stage_analysis.files_skipped,
                );
                if let Some(ref state_path) = self.config.incremental_state_path {
                    if let Err(e) = t.save_to_file(state_path) {
                        warn!(error = %e, "Failed to save incremental state");
                    }
                }
                let stats = t.stats();
                info!(
                    previous = stats.previous_files,
                    analyzed = stats.files_analyzed,
                    skipped = stats.files_skipped,
                    "Incremental analysis stats"
                );
            }
        }

        let duration_ms = start_time.elapsed().as_millis() as u64;
        info!(
            l1_hits = ast_cache_stats.l1_hits,
            l1_misses = ast_cache_stats.l1_misses,
            l2_hits = ast_cache_stats.l2_hits,
            l2_misses = ast_cache_stats.l2_misses,
            "SAST AST cache stats"
        );
        info!(
            finding_count = stage_analysis.findings.len(),
            files_scanned = stage_analysis.files_scanned,
            files_skipped = stage_analysis.files_skipped,
            files_failed = stage_analysis.files_failed,
            effective_parallelism = plan.effective_parallelism,
            duration_ms,
            "SAST scan completed"
        );

        Ok(ScanResult {
            findings: stage_analysis.findings,
            files_scanned: stage_analysis.files_scanned,
            files_skipped: stage_analysis.files_skipped,
            files_failed: stage_analysis.files_failed,
            errors: stage_analysis.errors,
            duration_ms,
        })
    }

    async fn build_scan_plan(&self, root: &Path) -> Result<ScanPlan, ScanError> {
        let files = self.scanner.scan(root).map_err(|e| {
            error!(error = %e, "Failed to scan directory");
            ScanError::scan_failed(root, e)
        })?;

        let file_count = files.len();
        let total_bytes: u64 = files
            .iter()
            .filter_map(|file| std::fs::metadata(&file.path).ok().map(|meta| meta.len()))
            .sum();

        let effective_depth = self.resolve_analysis_depth(file_count, total_bytes);
        let effective_parallelism = self.resolve_effective_parallelism(file_count, total_bytes);
        info!(
            file_count,
            total_bytes,
            configured_depth = ?self.config.analysis_depth,
            effective_depth = ?effective_depth,
            configured_parallelism = self.config.max_concurrent_files,
            effective_parallelism,
            "Scan planning stage completed"
        );

        let rules = {
            let rules_guard = self.rule_repository.read().await;
            rules_guard.get_all_rules().to_vec()
        };

        Ok(ScanPlan {
            files,
            rules,
            effective_depth,
            effective_parallelism,
            ast_cache_ttl: Duration::from_secs(self.config.ast_cache_ttl_hours.saturating_mul(3600)),
        })
    }

    async fn build_parse_index_stage(
        &self,
        files: &[ScanFile],
        effective_depth: AnalysisDepth,
        effective_parallelism: usize,
        ast_cache_ttl: Duration,
    ) -> (HashMap<String, (tree_sitter::Tree, String)>, Vec<String>) {
        let mut parsed_files: HashMap<String, (tree_sitter::Tree, String)> = HashMap::new();
        let mut errors = Vec::new();

        if !(self.config.enable_call_graph && effective_depth != AnalysisDepth::Quick) {
            return (parsed_files, errors);
        }

        debug!("Stage: parse/index with cross-file call graph");
        let mut call_graph = self.call_graph_builder.write().await;

        let results = stream::iter(files.iter().cloned())
            .map(|file| async move {
                let file_path_str = file.path.display().to_string();
                let content = std::fs::read_to_string(&file.path)
                    .map_err(|e| format!("Failed to read {} in parse/index: {}", file.path.display(), e))?;

                let selected_frontend = self.parser_frontend_selector.select(file.language);
                let mut warnings = Vec::new();

                if selected_frontend == ParserFrontend::Oxc && OxcFrontend::supports(file.language) {
                    if let Err(err) = self.oxc_frontend.parse_file(&file.path, &content) {
                        warnings.push(format!(
                            "OXC parse warning for {}: {}",
                            file.path.display(),
                            err
                        ));
                    }
                }

                let tree = self
                    .sast_engine
                    .parse(&content, file.language)
                    .await
                    .map_err(|e| {
                        format!(
                            "Parse/index stage failed for {}: {}",
                            file.path.display(),
                            e
                        )
                    })?;

                Ok::<_, String>((file_path_str, file.language, content, tree, warnings))
            })
            .buffer_unordered(effective_parallelism.max(1))
            .collect::<Vec<_>>()
            .await;

        for result in results {
            match result {
                Ok((file_path_str, language, content, tree, warnings)) => {
                    for warning in warnings {
                        warn!(file = %file_path_str, "{}", warning);
                        errors.push(warning);
                    }

                    if self.config.enable_ast_cache {
                        if let Some(cache) = self.ast_cache.as_ref() {
                            let content_hash = Self::compute_content_hash(&content);
                            let ast = convert_tree_sitter_node(tree.root_node(), &content, None);
                            if let Err(e) = cache
                                .set(&content_hash, &language, &ast, Some(ast_cache_ttl))
                                .await
                            {
                                warn!(error = %e, "Failed to write L2 AST cache");
                            }
                        }
                    }

                    call_graph.analyze_ast(&file_path_str, &tree, &language, &content);

                    if parsed_files.len() < self.config.tree_cache_max_entries {
                        parsed_files.insert(file_path_str, (tree, content));
                    }
                }
                Err(error) => errors.push(error),
            }
        }

        let resolved_count = call_graph.graph_mut().resolve_all_calls();
        let stats = call_graph.graph().stats();
        info!(
            functions = stats.total_functions,
            calls = stats.total_calls,
            resolved = resolved_count,
            entry_points = stats.entry_points,
            "Parse/index stage call graph built"
        );

        {
            let mut df_ctx = self.data_flow_context.write().await;
            df_ctx.seed_from_call_graph(call_graph.graph());
        }

        {
            let file_deps = call_graph.graph().file_dependencies();
            if !file_deps.is_empty() {
                let mut tracker = self.incremental_tracker.lock().unwrap();
                if let Some(ref mut t) = *tracker {
                    debug!(
                        cross_file_edges = file_deps.len(),
                        "Setting file dependencies from call graph"
                    );
                    t.set_file_dependencies(file_deps);
                }
            }
        }

        (parsed_files, errors)
    }

    async fn run_analysis_stage(
        &self,
        files: &[ScanFile],
        all_rules: &[PatternRule],
        effective_depth: AnalysisDepth,
        ast_cache_ttl: Duration,
        parsed_files: &HashMap<String, (tree_sitter::Tree, String)>,
        ast_cache_stats: &mut AstCacheStats,
    ) -> AnalysisStageResult {
        let mut stage = AnalysisStageResult::default();

        for file in files {
            let selected_frontend = self.parser_frontend_selector.select(file.language);
            debug!(
                file = %file.path.display(),
                language = %file.language,
                frontend = ?selected_frontend,
                "Stage: file analysis routing"
            );

            let file_size = match std::fs::metadata(&file.path) {
                Ok(meta) => meta.len(),
                Err(e) => {
                    debug!(file = %file.path.display(), error = %e, "Failed to get file metadata");
                    stage.files_skipped += 1;
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
                stage.files_skipped += 1;
                continue;
            }

            let content = match std::fs::read_to_string(&file.path) {
                Ok(content) => content,
                Err(e) => {
                    warn!(file = %file.path.display(), error = %e, "Failed to read file");
                    stage.files_failed += 1;
                    stage
                        .errors
                        .push(format!("Failed to read {}: {}", file.path.display(), e));
                    continue;
                }
            };

            if selected_frontend == ParserFrontend::Oxc && OxcFrontend::supports(file.language) {
                if let Err(err) = self.oxc_frontend.parse_file(&file.path, &content) {
                    warn!(
                        file = %file.path.display(),
                        language = %file.language,
                        error = %err,
                        "OXC parse failed, continuing with Tree-sitter compatibility lane"
                    );
                    stage.errors.push(format!(
                        "OXC parse warning for {}: {}",
                        file.path.display(),
                        err
                    ));
                }
            }

            let file_path_str = file.path.display().to_string();
            let content_hash = Self::compute_content_hash(&content);

            {
                let tracker = self.incremental_tracker.lock().unwrap();
                if let Some(ref t) = *tracker {
                    let (needs, _) = t.needs_analysis(&file_path_str, &content);
                    if !needs {
                        debug!(file = %file_path_str, "Skipping unchanged file (incremental)");
                        stage.files_skipped += 1;
                        drop(tracker);
                        let mut tracker = self.incremental_tracker.lock().unwrap();
                        if let Some(ref mut t) = *tracker {
                            let prev_count = t.get_previous_findings(&file_path_str).unwrap_or(0);
                            t.record_file(
                                &file_path_str,
                                content_hash.clone(),
                                content.len() as u64,
                                prev_count,
                            );
                        }
                        continue;
                    }
                }
            }

            let mut cached_tree = parsed_files.get(&file_path_str).map(|(tree, _)| tree.clone());
            let mut l2_hit = false;

            if cached_tree.is_some() {
                ast_cache_stats.l1_hits = ast_cache_stats.l1_hits.saturating_add(1);
            } else {
                ast_cache_stats.l1_misses = ast_cache_stats.l1_misses.saturating_add(1);
            }

            if cached_tree.is_none() {
                if let Some(cache) = self.ast_cache.as_ref() {
                    match cache.get(&content_hash, &file.language).await {
                        Ok(Some(_)) => {
                            l2_hit = true;
                            Self::update_l2_cache_stats(ast_cache_stats, true)
                        }
                        Ok(None) => Self::update_l2_cache_stats(ast_cache_stats, false),
                        Err(e) => {
                            warn!(error = %e, "Failed to read L2 AST cache");
                        }
                    }
                }

                if let Ok(tree) = self.sast_engine.parse(&content, file.language).await {
                    if self.config.enable_ast_cache && !l2_hit {
                        if let Some(cache) = self.ast_cache.as_ref() {
                            let ast = convert_tree_sitter_node(tree.root_node(), &content, None);
                            if let Err(e) = cache
                                .set(&content_hash, &file.language, &ast, Some(ast_cache_ttl))
                                .await
                            {
                                warn!(error = %e, "Failed to write L2 AST cache");
                            }
                        }
                    }
                    cached_tree = Some(tree);
                }
            }

            let suppressions = FileSuppressions::parse(&content);
            let is_test_context = Self::is_test_file(&file.path, &content);
            stage.files_scanned += 1;

            let applicable_rules: Vec<&PatternRule> = all_rules
                .iter()
                .filter(|r| r.languages.contains(&file.language))
                .collect();

            if applicable_rules.is_empty() {
                continue;
            }

            if let Err(e) = self
                .execute_tree_sitter_analysis(
                    &file.path,
                    &file.language,
                    &content,
                    &applicable_rules,
                    &suppressions,
                    is_test_context,
                    cached_tree.as_ref(),
                    &mut stage.findings,
                )
                .await
            {
                warn!(file = %file.path.display(), error = %e, "Tree-sitter analysis failed");
                stage
                    .errors
                    .push(format!("Analysis failed for {}: {}", file.path.display(), e));
            }

            if self.config.enable_data_flow && effective_depth != AnalysisDepth::Quick {
                self.execute_data_flow_analysis(
                    &file.path,
                    &file.language,
                    &content,
                    cached_tree.as_ref(),
                    effective_depth,
                    &mut stage.findings,
                )
                .await;
            }

            let file_finding_count = stage
                .findings
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

            if let Some(max_total) = self.config.max_total_findings {
                if stage.findings.len() >= max_total {
                    info!(
                        total_findings = stage.findings.len(),
                        max_total,
                        "Max total findings limit reached, stopping scan early"
                    );
                    let mut tracker = self.incremental_tracker.lock().unwrap();
                    if let Some(ref mut t) = *tracker {
                        t.record_file(
                            &file_path_str,
                            content_hash,
                            content.len() as u64,
                            file_finding_count,
                        );
                    }
                    break;
                }
            }

            {
                let mut tracker = self.incremental_tracker.lock().unwrap();
                if let Some(ref mut t) = *tracker {
                    t.record_file(
                        &file_path_str,
                        content_hash,
                        content.len() as u64,
                        file_finding_count,
                    );
                }
            }
        }

        stage
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_tree_sitter_analysis(
        &self,
        file_path: &Path,
        language: &Language,
        content: &str,
        rules: &[&PatternRule],
        suppressions: &FileSuppressions,
        is_test_context: bool,
        tree: Option<&tree_sitter::Tree>,
        findings: &mut Vec<SastFinding>,
    ) -> Result<(), ScanError> {
        // Filter to pattern rules (tree-sitter, metavariables, and composites)
        let pattern_rules: Vec<&PatternRule> = rules.to_vec();

        if pattern_rules.is_empty() {
            return Ok(());
        }

        debug!(
            rule_count = pattern_rules.len(),
            file = %file_path.display(),
            "Executing pattern rules"
        );

        let semantic_context = if pattern_rules.iter().any(|r| r.semantic.is_some()) {
            let tree = if let Some(tree) = tree {
                tree.clone()
            } else {
                self.sast_engine
                    .parse(content, *language)
                    .await
                    .map_err(|e| {
                        ScanError::parse_failed(file_path, language, e.to_string(), None)
                    })?
            };
            Some(SemanticContext::from_tree(&tree, content, *language))
        } else {
            None
        };

        let results = {
            self.sast_engine
                .query_batch(content, *language, &pattern_rules)
                .await
        };

        // Get sast_engine for match_to_finding
        let sast_engine = Arc::clone(&self.sast_engine);

        for (rule_id, matches) in results {
            let rule = pattern_rules.iter().find(|r| r.id == rule_id);
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

                    if !self
                        .sast_engine
                        .metavariable_constraints_pass(
                            rule,
                            &match_result,
                            *language,
                            semantic_context.as_ref(),
                        )
                        .await
                    {
                        debug!(rule_id = %rule.id, line, "Metavariable constraints rejected");
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
        effective_depth: AnalysisDepth,
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
        let taint_config = &self.taint_config;
        let enable_interproc =
            self.config.enable_call_graph && effective_depth == AnalysisDepth::Deep;

        // Detect sources, sinks, and sanitizers using tree-sitter queries
        let matches = self
            .sast_engine
            .detect_taint(&tree, source_bytes, *language, taint_config)
            .await;

        let sanitizer_names: std::collections::HashSet<String> =
            get_sanitizer_queries(language, taint_config)
                .into_iter()
                .map(|p| p.name)
                .collect();

        let sources: Vec<_> = matches
            .iter()
            .filter(|m| !m.labels.is_empty())
            .cloned()
            .collect();
        let sanitizers: Vec<_> = matches
            .iter()
            .filter(|m| sanitizer_names.contains(&m.pattern_name))
            .cloned()
            .collect();
        let sinks: Vec<_> = matches
            .iter()
            .filter(|m| m.labels.is_empty() && !sanitizer_names.contains(&m.pattern_name))
            .cloned()
            .collect();

        let assignments = Self::extract_assignments(&tree, source_bytes, language);
        let call_assignments = if enable_interproc {
            Self::extract_call_assignments(&tree, source_bytes, language)
        } else {
            Vec::new()
        };
        let return_expressions = if enable_interproc {
            Self::extract_return_expressions(&tree, source_bytes, language)
        } else {
            Vec::new()
        };

        debug!(
            file = %file_str,
            sources = sources.len(),
            sinks = sinks.len(),
            sanitizers = sanitizers.len(),
            "Taint analysis results"
        );

        if enable_interproc {
            let function_ranges: Vec<FunctionRange> = {
                let call_graph = self.call_graph_builder.read().await;
                call_graph
                    .graph()
                    .functions()
                    .filter(|f| f.file_path == file_str)
                    .map(|f| FunctionRange {
                        id: f.id.clone(),
                        start_line: f.start_line,
                        end_line: f.end_line,
                        parameters: f.signature.parameters.clone(),
                    })
                    .collect()
            };

            if !function_ranges.is_empty() {
                let mut range_map: HashMap<String, FunctionRange> = HashMap::new();
                let mut exclusion_ranges = Vec::new();
                for range in function_ranges {
                    exclusion_ranges.push(LineRange {
                        start_line: range.start_line,
                        end_line: range.end_line,
                    });
                    range_map.insert(range.id.clone(), range);
                }

                let topo_order = {
                    let ctx = self.data_flow_context.read().await;
                    ctx.topo_order().to_vec()
                };

                let mut ctx = self.data_flow_context.write().await;
                for function_id in topo_order {
                    let Some(range) = range_map.get(&function_id) else {
                        continue;
                    };

                    let line_range = LineRange {
                        start_line: range.start_line,
                        end_line: range.end_line,
                    };

                    let scoped_sources =
                        Self::filter_matches_by_range(&sources, Some(&line_range), None);
                    let scoped_sanitizers =
                        Self::filter_matches_by_range(&sanitizers, Some(&line_range), None);
                    let scoped_sinks =
                        Self::filter_matches_by_range(&sinks, Some(&line_range), None);
                    let scoped_assignments =
                        Self::filter_assignments_by_range(&assignments, Some(&line_range), None);
                    let scoped_calls = Self::filter_call_assignments_by_range(
                        &call_assignments,
                        Some(&line_range),
                        None,
                    );
                    let scoped_returns = Self::filter_return_expressions_by_range(
                        &return_expressions,
                        Some(&line_range),
                        None,
                    );

                    ctx.enter_function(&function_id);

                    let call_edges = ctx.get_call_edges(&function_id).to_vec();
                    let mut param_states: Vec<(usize, crate::domain::finding::TaintState)> =
                        Vec::new();
                    let mut call_updates: Vec<CallUpdate> = Vec::new();
                    let mut return_state: Option<crate::domain::finding::TaintState> = None;

                    {
                        let analyzer = ctx.get_analyzer(&function_id);
                        *analyzer = DataFlowAnalyzer::new();
                        analyzer.build_symbols(&tree, content, *language, &file_str);

                        for (idx, param) in range.parameters.iter().enumerate() {
                            let param_name = if param.name.is_empty() {
                                format!("param_{}", idx)
                            } else {
                                param.name.clone()
                            };
                            analyzer.mark_tainted(
                                &param_name,
                                &format!("param:{}", idx),
                                &file_str,
                                range.start_line,
                                0,
                            );

                            if let Some(state) = analyzer.get_taint_state(&param_name).cloned() {
                                param_states.push((idx, state));
                            }
                        }

                        Self::analyze_scope(
                            analyzer,
                            &scoped_sources,
                            &scoped_sinks,
                            &scoped_sanitizers,
                            &scoped_assignments,
                            findings,
                            &file_str,
                            language,
                            taint_config.generic_validation_confidence,
                        );

                        for call in scoped_calls {
                            let target_id = call_edges
                                .iter()
                                .find(|edge| {
                                    edge.line == call.line as u32 + 1
                                        && edge.target_name == call.callee
                                })
                                .map(|edge| edge.target_id.clone());

                            if let Some(target_id) = target_id {
                                let argument_taints: Vec<
                                    Option<crate::domain::finding::TaintState>,
                                > = call
                                    .args
                                    .iter()
                                    .map(|arg| Self::resolve_taint_for_expr(analyzer, arg))
                                    .collect();
                                call_updates.push((
                                    call.target.clone(),
                                    call.line as u32 + 1,
                                    call.column as u32,
                                    target_id,
                                    argument_taints,
                                ));
                            }
                        }

                        for (expr, line, _column) in scoped_returns {
                            if let Some(state) = Self::resolve_taint_for_expr(analyzer, &expr) {
                                return_state = Some(state);
                                debug!(
                                    function_id = %function_id,
                                    line = line + 1,
                                    "Return value marked as tainted"
                                );
                                break;
                            }
                        }
                    }

                    for (idx, state) in param_states {
                        ctx.mark_param_tainted(&function_id, idx, state);
                    }

                    for (target, line, column, target_id, argument_taints) in call_updates {
                        if let Some(state) = ctx.propagate_through_call(
                            &target_id,
                            &argument_taints,
                            &file_str,
                            line,
                            column,
                        ) {
                            let analyzer = ctx.get_analyzer(&function_id);
                            analyzer.set_taint_state(&target, state, &file_str, line, column);
                        }
                    }

                    if let Some(state) = return_state {
                        ctx.mark_return_tainted(&function_id, state);
                    }

                    ctx.compute_function_summary(&function_id);
                }

                // Analyze global scope (outside of functions)
                let global_sources =
                    Self::filter_matches_by_range(&sources, None, Some(&exclusion_ranges));
                let global_sanitizers =
                    Self::filter_matches_by_range(&sanitizers, None, Some(&exclusion_ranges));
                let global_sinks =
                    Self::filter_matches_by_range(&sinks, None, Some(&exclusion_ranges));
                let global_assignments =
                    Self::filter_assignments_by_range(&assignments, None, Some(&exclusion_ranges));

                if !global_sources.is_empty()
                    || !global_sanitizers.is_empty()
                    || !global_sinks.is_empty()
                {
                    let mut analyzer = DataFlowAnalyzer::new();
                    analyzer.build_symbols(&tree, content, *language, &file_str);
                    Self::analyze_scope(
                        &mut analyzer,
                        &global_sources,
                        &global_sinks,
                        &global_sanitizers,
                        &global_assignments,
                        findings,
                        &file_str,
                        language,
                        taint_config.generic_validation_confidence,
                    );
                }

                return;
            }
        }

        // Non-interprocedural or no function ranges: analyze file as a single scope
        let mut ctx = self.data_flow_context.write().await;
        ctx.enter_function(&file_str);
        let analyzer = ctx.get_analyzer(&file_str);
        *analyzer = DataFlowAnalyzer::new();
        analyzer.build_symbols(&tree, content, *language, &file_str);
        Self::analyze_scope(
            analyzer,
            &sources,
            &sinks,
            &sanitizers,
            &assignments,
            findings,
            &file_str,
            language,
            taint_config.generic_validation_confidence,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze_scope(
        analyzer: &mut DataFlowAnalyzer,
        sources: &[TaintMatch],
        sinks: &[TaintMatch],
        sanitizers: &[TaintMatch],
        assignments: &[(String, String, usize, usize)],
        findings: &mut Vec<SastFinding>,
        file_str: &str,
        language: &Language,
        generic_confidence: f32,
    ) {
        for source in sources {
            let var_name = source
                .variable_name
                .as_deref()
                .unwrap_or(&source.matched_text);

            analyzer.mark_tainted(
                var_name,
                &source.pattern_name,
                file_str,
                source.line as u32 + 1,
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

        let sanitized_vars: std::collections::HashSet<&str> = sanitizers
            .iter()
            .filter_map(|s| s.variable_name.as_deref().or(Some(&s.matched_text)))
            .collect();

        tracing::trace!(
            sanitized_vars = ?sanitized_vars,
            "Sanitized variables blocking taint propagation"
        );

        let mut worklist: std::collections::VecDeque<usize> = (0..assignments.len()).collect();
        let mut worklist_set: std::collections::HashSet<usize> = (0..assignments.len()).collect();

        while let Some(idx) = worklist.pop_front() {
            worklist_set.remove(&idx);

            let (target, source_expr, line, column) = &assignments[idx];

            if analyzer.is_tainted(target) {
                continue;
            }

            if sanitized_vars.contains(target.as_str()) {
                continue;
            }

            let mut newly_tainted = false;

            let tainted_vars: Vec<String> = analyzer
                .symbol_table()
                .get_all_tainted_in_all_scopes()
                .into_iter()
                .map(|(name, _)| name.to_string())
                .collect();

            for tainted_var in &tainted_vars {
                let pattern = format!(r"\b{}\b", regex::escape(tainted_var));
                let re = regex_cache::get_regex(&pattern)
                    .or_else(|_| regex_cache::get_regex(tainted_var))
                    .unwrap();

                if re.is_match(source_expr) {
                    analyzer.mark_tainted(
                        target,
                        &format!("propagated from {}", tainted_var),
                        file_str,
                        *line as u32 + 1,
                        *column as u32,
                    );
                    newly_tainted = true;
                    break;
                }
            }

            if newly_tainted {
                let pattern = format!(r"\b{}\b", regex::escape(target));
                let re = regex_cache::get_regex(&pattern)
                    .or_else(|_| regex_cache::get_regex(target))
                    .unwrap();

                for (other_idx, (_, other_source_expr, _, _)) in assignments.iter().enumerate() {
                    if other_idx != idx
                        && !worklist_set.contains(&other_idx)
                        && re.is_match(other_source_expr)
                    {
                        worklist.push_back(other_idx);
                        worklist_set.insert(other_idx);
                    }
                }
            }
        }

        for sanitizer in sanitizers {
            let var_name = sanitizer
                .variable_name
                .as_deref()
                .unwrap_or(&sanitizer.matched_text);

            if sanitizer.is_known {
                analyzer.sanitize(
                    var_name,
                    &sanitizer.pattern_name,
                    file_str,
                    sanitizer.line as u32 + 1,
                    sanitizer.column as u32,
                );
                debug!(
                    var = %var_name,
                    sanitizer = %sanitizer.pattern_name,
                    "Cleared taint (known sanitizer)"
                );
            } else {
                debug!(
                    var = %var_name,
                    sanitizer = %sanitizer.pattern_name,
                    confidence = generic_confidence,
                    "Generic validation detected (confidence reduced)"
                );
            }
        }

        let ssrf_sanitized = sanitizers
            .iter()
            .any(|s| matches!(s.category.as_str(), "ssrf" | "url" | "path" | "ssti"));

        for sink in sinks {
            if (sink.category == "ssrf" || sink.category == "ssti") && ssrf_sanitized {
                debug!(
                    sink = %sink.pattern_name,
                    category = %sink.category,
                    "Skipping sink due to explicit sanitizer presence"
                );
                continue;
            }
            if matches!(
                sink.category.as_str(),
                "ssrf" | "path_traversal" | "ssti" | "sql_injection"
            ) && Self::mentions_sanitized_var(&sanitized_vars, &sink.matched_text)
            {
                debug!(
                    sink = %sink.pattern_name,
                    category = %sink.category,
                    "Skipping sink due to sanitized variable in expression"
                );
                continue;
            }

            let sink_var = sink.variable_name.as_deref().unwrap_or(&sink.matched_text);

            if analyzer.is_tainted(sink_var) {
                if let Some(data_flow_finding) = analyzer.check_sink(
                    sink_var,
                    &sink.pattern_name,
                    file_str,
                    sink.line as u32 + 1,
                    sink.column as u32,
                ) {
                    Self::add_finding(findings, &data_flow_finding, sink, file_str, language);
                    continue;
                }
            }

            let active_taints: Vec<String> = analyzer
                .symbol_table()
                .get_all_tainted_in_all_scopes()
                .into_iter()
                .map(|(name, _)| name.to_string())
                .collect();

            for tainted_var in &active_taints {
                if tainted_var == sink_var {
                    continue;
                }

                let pattern = format!(r"\b{}\b", regex::escape(tainted_var));
                let re = regex_cache::get_regex(&pattern)
                    .or_else(|_| regex_cache::get_regex(tainted_var))
                    .unwrap();

                if re.is_match(&sink.matched_text) {
                    if let Some(data_flow_finding) = analyzer.check_sink(
                        tainted_var,
                        &sink.pattern_name,
                        file_str,
                        sink.line as u32 + 1,
                        sink.column as u32,
                    ) {
                        Self::add_finding(findings, &data_flow_finding, sink, file_str, language);
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
        language: &Language,
    ) {
        let language_tag = language.to_string().to_lowercase();
        let severity = Self::data_flow_severity_for_category(&sink.category);
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

        let category_display = sink.category.replace('_', " ");
        let finding = SastFinding {
            id: uuid::Uuid::new_v4().to_string(),
            rule_id: format!("data-flow-{}-{}", language_tag, sink.category),
            location: Location {
                file_path: file_str.to_string(),
                line: sink.line as u32 + 1,
                column: Some(sink.column as u32),
                end_line: Some(sink.end_line as u32 + 1),
                end_column: Some(sink.end_column as u32),
            },
            severity,
            confidence: crate::domain::value_objects::Confidence::High,
            description: format!(
                "Tainted data from {} flows to {}: {}",
                data_flow_finding.source.expression, category_display, sink.pattern_name
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
            bindings: None,
        };
        findings.push(finding);
    }

    fn data_flow_severity_for_category(category: &str) -> Severity {
        match category.to_lowercase().as_str() {
            "deserialization" | "ssti" | "code_injection" => Severity::Critical,
            "sql_injection" | "command_injection" | "ssrf" | "path_traversal" | "xss" => {
                Severity::High
            }
            _ => Severity::High,
        }
    }

    fn mentions_sanitized_var(
        sanitized_vars: &std::collections::HashSet<&str>,
        expression: &str,
    ) -> bool {
        sanitized_vars.iter().any(|var| {
            let pattern = format!(r"\b{}\b", regex::escape(var));
            regex_cache::get_regex(&pattern)
                .map(|re| re.is_match(expression))
                .unwrap_or_else(|_| expression.contains(var))
        })
    }

    /// Adjust severity for findings confirmed by data flow analysis
    fn adjust_severity_for_data_flow(findings: &mut [SastFinding]) {
        for finding in findings.iter_mut() {
            if finding.data_flow_path.is_some() {
                // Escalate severity when data flow confirms the vulnerability
                match finding.severity {
                    Severity::Low => finding.severity = Severity::Medium,
                    Severity::Medium => finding.severity = Severity::High,
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

    fn line_in_range(line_zero: usize, range: &LineRange) -> bool {
        let line = line_zero as u32 + 1;
        line >= range.start_line && line <= range.end_line
    }

    fn line_in_any_range(line_zero: usize, ranges: &[LineRange]) -> bool {
        ranges
            .iter()
            .any(|range| Self::line_in_range(line_zero, range))
    }

    fn filter_matches_by_range(
        matches: &[TaintMatch],
        range: Option<&LineRange>,
        exclude_ranges: Option<&[LineRange]>,
    ) -> Vec<TaintMatch> {
        matches
            .iter()
            .filter(|m| {
                let in_range = range.is_none_or(|r| Self::line_in_range(m.line, r));
                let excluded = exclude_ranges
                    .map(|ranges| Self::line_in_any_range(m.line, ranges))
                    .unwrap_or(false);
                in_range && !excluded
            })
            .cloned()
            .collect()
    }

    fn filter_assignments_by_range(
        assignments: &[(String, String, usize, usize)],
        range: Option<&LineRange>,
        exclude_ranges: Option<&[LineRange]>,
    ) -> Vec<(String, String, usize, usize)> {
        assignments
            .iter()
            .filter(|(_, _, line, _)| {
                let in_range = range.is_none_or(|r| Self::line_in_range(*line, r));
                let excluded = exclude_ranges
                    .map(|ranges| Self::line_in_any_range(*line, ranges))
                    .unwrap_or(false);
                in_range && !excluded
            })
            .cloned()
            .collect()
    }

    fn filter_call_assignments_by_range(
        assignments: &[CallAssignment],
        range: Option<&LineRange>,
        exclude_ranges: Option<&[LineRange]>,
    ) -> Vec<CallAssignment> {
        assignments
            .iter()
            .filter(|assignment| {
                let in_range = range.is_none_or(|r| Self::line_in_range(assignment.line, r));
                let excluded = exclude_ranges
                    .map(|ranges| Self::line_in_any_range(assignment.line, ranges))
                    .unwrap_or(false);
                in_range && !excluded
            })
            .cloned()
            .collect()
    }

    fn filter_return_expressions_by_range(
        returns: &[(String, usize, usize)],
        range: Option<&LineRange>,
        exclude_ranges: Option<&[LineRange]>,
    ) -> Vec<(String, usize, usize)> {
        returns
            .iter()
            .filter(|(_, line, _)| {
                let in_range = range.is_none_or(|r| Self::line_in_range(*line, r));
                let excluded = exclude_ranges
                    .map(|ranges| Self::line_in_any_range(*line, ranges))
                    .unwrap_or(false);
                in_range && !excluded
            })
            .cloned()
            .collect()
    }

    fn resolve_taint_for_expr(
        analyzer: &DataFlowAnalyzer,
        expr: &str,
    ) -> Option<crate::domain::finding::TaintState> {
        if let Some(state) = analyzer.get_taint_state(expr) {
            return Some(state.clone());
        }

        let tainted_vars = analyzer.symbol_table().get_all_tainted_in_all_scopes();
        for (name, state) in tainted_vars {
            let pattern = format!(r"\b{}\b", regex::escape(name));
            let re = regex_cache::get_regex(&pattern)
                .or_else(|_| regex_cache::get_regex(name))
                .unwrap();
            if re.is_match(expr) {
                return Some(state.clone());
            }
        }

        None
    }

    fn extract_call_assignments(
        tree: &tree_sitter::Tree,
        source_code: &[u8],
        language: &Language,
    ) -> Vec<CallAssignment> {
        let mut assignments = Vec::new();

        let queries: Vec<&'static str> = match language {
            Language::Python => vec![
                r#"(assignment
                  left: (identifier) @target
                  right: (call
                    function: (identifier) @callee
                    arguments: (argument_list (_) @arg)*)
                )"#,
                r#"(assignment
                  left: (identifier) @target
                  right: (call
                    function: (attribute attribute: (identifier) @callee)
                    arguments: (argument_list (_) @arg)*)
                )"#,
            ],
            Language::JavaScript | Language::TypeScript => vec![
                r#"(variable_declarator
                  name: (identifier) @target
                  value: (call_expression
                    function: (identifier) @callee
                    arguments: (arguments (_) @arg)*)
                )"#,
                r#"(assignment_expression
                  left: (identifier) @target
                  right: (call_expression
                    function: (identifier) @callee
                    arguments: (arguments (_) @arg)*)
                )"#,
                r#"(variable_declarator
                  name: (identifier) @target
                  value: (call_expression
                    function: (member_expression property: (property_identifier) @callee)
                    arguments: (arguments (_) @arg)*)
                )"#,
            ],
            Language::Go => vec![
                r#"(short_var_declaration
                  left: (expression_list (identifier) @target)
                  right: (expression_list (call_expression
                    function: (identifier) @callee
                    arguments: (argument_list (_) @arg)*))
                )"#,
                r#"(assignment_statement
                  left: (expression_list (identifier) @target)
                  right: (expression_list (call_expression
                    function: (identifier) @callee
                    arguments: (argument_list (_) @arg)*))
                )"#,
            ],
            Language::Rust => vec![
                r#"(let_declaration
                  pattern: (identifier) @target
                  value: (call_expression
                    function: (identifier) @callee
                    arguments: (arguments (_) @arg)*)
                )"#,
            ],
            Language::C | Language::Cpp => vec![
                r#"(init_declarator
                  declarator: (identifier) @target
                  value: (call_expression
                    function: (identifier) @callee
                    arguments: (argument_list (_) @arg)*)
                )"#,
                r#"(assignment_expression
                  left: (identifier) @target
                  right: (call_expression
                    function: (identifier) @callee
                    arguments: (argument_list (_) @arg)*)
                )"#,
            ],
        };

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
                        "Failed to compile call assignment query"
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
                let mut callee: Option<String> = None;
                let mut args: Vec<String> = Vec::new();
                let mut line: Option<usize> = None;
                let mut column: Option<usize> = None;

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
                            if line.is_none() {
                                line = Some(capture.node.start_position().row);
                                column = Some(capture.node.start_position().column);
                            }
                        }
                        "callee" => {
                            callee = Some(text);
                            line = Some(capture.node.start_position().row);
                            column = Some(capture.node.start_position().column);
                        }
                        "arg" => {
                            args.push(text);
                        }
                        _ => {}
                    }
                }

                if let (Some(target), Some(callee)) = (target, callee) {
                    assignments.push(CallAssignment {
                        target,
                        callee,
                        args,
                        line: line.unwrap_or(0),
                        column: column.unwrap_or(0),
                    });
                }
            }
        }

        assignments
    }

    fn extract_return_expressions(
        tree: &tree_sitter::Tree,
        source_code: &[u8],
        language: &Language,
    ) -> Vec<(String, usize, usize)> {
        let queries: Vec<&'static str> = match language {
            Language::Rust => vec![r#"(return_expression (_) @expr)"#],
            _ => vec![r#"(return_statement (_) @expr)"#],
        };

        let ts_language = match language {
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            Language::JavaScript | Language::TypeScript => tree_sitter_javascript::LANGUAGE.into(),
            Language::Go => tree_sitter_go::LANGUAGE.into(),
            Language::Rust => tree_sitter_rust::LANGUAGE.into(),
            Language::C => tree_sitter_c::LANGUAGE.into(),
            Language::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        };

        let mut returns = Vec::new();
        for query_str in queries {
            let query = match tree_sitter::Query::new(&ts_language, query_str) {
                Ok(q) => q,
                Err(e) => {
                    debug!(
                        language = %language,
                        error = %e,
                        "Failed to compile return expression query"
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
                for capture in m.captures {
                    let capture_name = query.capture_names()[capture.index as usize];
                    if capture_name == "expr" {
                        let text = capture
                            .node
                            .utf8_text(source_code)
                            .unwrap_or_default()
                            .to_string();
                        returns.push((
                            text,
                            capture.node.start_position().row,
                            capture.node.start_position().column,
                        ));
                    }
                }
            }
        }

        returns
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

    /// Failed to scan directory or resolve file listing
    #[error("Failed to scan path '{path}': {message}")]
    ScanFailed {
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

    /// Create a scan error with context
    pub fn scan_failed(path: impl Into<std::path::PathBuf>, source: std::io::Error) -> Self {
        Self::ScanFailed {
            path: path.into(),
            message: source.to_string(),
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
