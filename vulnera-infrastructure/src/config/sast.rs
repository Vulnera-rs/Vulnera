use serde::Deserialize;

/// SAST (Static Application Security Testing) configuration
#[derive(Debug, Clone, Deserialize)]
pub struct SastConfig {
    /// Maximum directory nesting depth for file scanning
    pub max_scan_depth: usize,
    /// Glob patterns to exclude from scanning
    pub exclude_patterns: Vec<String>,
    /// Enable trace-level diagnostic logging per-file
    pub enable_logging: bool,
    /// Enable data flow / taint analysis
    pub enable_data_flow: bool,
    /// Enable call graph for inter-procedural analysis
    pub enable_call_graph: bool,
    /// Analysis depth: "quick", "standard", or "deep"
    pub analysis_depth: String,
    /// Enable AST caching via Dragonfly
    pub enable_ast_cache: bool,
    /// AST cache TTL in hours
    pub ast_cache_ttl_hours: u64,
    /// Maximum concurrent file analysis workers
    pub max_concurrent_files: usize,
    /// Auto-detect depth based on repository size
    pub dynamic_depth_enabled: bool,
    /// Downgrade depth above this file count
    pub dynamic_depth_file_count_threshold: u64,
    /// Downgrade depth above this byte threshold
    pub dynamic_depth_total_bytes_threshold: u64,
    /// Max parsed trees cached per worker
    pub tree_cache_max_entries: usize,
    /// JS/TS parser frontend preference
    pub js_ts_frontend: String,
    /// Minimum finding severity to report
    pub min_finding_severity: String,
    /// Minimum finding confidence to report
    pub min_finding_confidence: String,
    /// Require data-flow evidence for dataflow-based rules
    pub require_data_flow_evidence_for_dataflow: bool,
    /// Require actionable recommendations on every finding
    pub require_recommendation: bool,
}

impl Default for SastConfig {
    fn default() -> Self {
        Self {
            max_scan_depth: 20,
            exclude_patterns: vec![
                "node_modules".into(),
                ".git".into(),
                "target".into(),
                "__pycache__".into(),
                ".venv".into(),
                "venv".into(),
                "dist".into(),
                "build".into(),
                "docs".into(),
                "doc".into(),
                "examples".into(),
                "example".into(),
                "test".into(),
                "tests".into(),
                "vendor".into(),
                "third_party".into(),
                "fixtures".into(),
            ],
            enable_logging: true,
            enable_data_flow: true,
            enable_call_graph: true,
            analysis_depth: "standard".into(),
            enable_ast_cache: true,
            ast_cache_ttl_hours: 4,
            max_concurrent_files: 4,
            dynamic_depth_enabled: true,
            dynamic_depth_file_count_threshold: 500,
            dynamic_depth_total_bytes_threshold: 52_428_800,
            tree_cache_max_entries: 1024,
            js_ts_frontend: "oxc_preferred".into(),
            min_finding_severity: "info".into(),
            min_finding_confidence: "low".into(),
            require_data_flow_evidence_for_dataflow: false,
            require_recommendation: false,
        }
    }
}
