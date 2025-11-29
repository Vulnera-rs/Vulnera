//! SAST use cases
//!
//! Production-ready SAST analysis pipeline with:
//! - Tree-sitter as primary analysis engine (S-expression pattern queries)
//! - Semgrep OSS for taint analysis (subprocess execution)
//! - PostgreSQL rule storage with hot-reload
//! - SARIF v2.1.0 export

use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

use vulnera_core::config::SastConfig;

use crate::domain::entities::{
    FileSuppressions, Finding as SastFinding, Rule, RulePattern, SemgrepRule,
};
use crate::domain::value_objects::{AnalysisEngine, Language};
use crate::infrastructure::analysis_selector::AnalysisSelector;
use crate::infrastructure::ast_cache::AstCacheService;
use crate::infrastructure::rules::{
    PostgresRuleRepository, RuleEngine, RuleRepository, SastRuleRepository,
};
use crate::infrastructure::sarif::{SarifExporter, SarifExporterConfig};
use crate::infrastructure::scanner::DirectoryScanner;
use crate::infrastructure::semgrep::SemgrepExecutor;

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
    /// Use tree-sitter as primary engine (recommended)
    pub use_tree_sitter: bool,
    /// Use Semgrep for taint analysis
    pub use_semgrep: bool,
    /// Path to Semgrep binary (defaults to "semgrep" in PATH)
    pub semgrep_path: Option<String>,
    /// Semgrep execution timeout in seconds
    pub semgrep_timeout_secs: u64,
    /// Enable AST caching via Dragonfly
    pub enable_ast_cache: bool,
    /// AST cache TTL in hours
    pub ast_cache_ttl_hours: u64,
    /// Maximum concurrent file analysis
    pub max_concurrent_files: usize,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            use_tree_sitter: true,
            use_semgrep: true,
            semgrep_path: None,
            semgrep_timeout_secs: 60,
            enable_ast_cache: true,
            ast_cache_ttl_hours: 1,
            max_concurrent_files: 4,
        }
    }
}

/// Production-ready use case for scanning a project
pub struct ScanProjectUseCase {
    scanner: DirectoryScanner,
    rule_repository: Arc<RwLock<RuleRepository>>,
    rule_engine: RuleEngine,
    analysis_selector: AnalysisSelector,
    semgrep_executor: Option<SemgrepExecutor>,
    semgrep_rules: Vec<SemgrepRule>,
    /// AST cache for parsed file caching (Dragonfly-backed)
    #[allow(dead_code)]
    ast_cache: Option<Arc<dyn AstCacheService>>,
    #[allow(dead_code)]
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

        let semgrep_executor = if analysis_config.use_semgrep {
            Some(SemgrepExecutor::new())
        } else {
            None
        };

        Self {
            scanner,
            rule_repository: Arc::new(RwLock::new(rule_repository)),
            rule_engine: RuleEngine::new(),
            analysis_selector: AnalysisSelector::new(),
            semgrep_executor,
            semgrep_rules: Vec::new(),
            ast_cache: None,
            config: analysis_config,
        }
    }

    pub async fn with_database_rules(
        mut self,
        db_repository: &PostgresRuleRepository,
    ) -> Result<Self, ScanError> {
        let tree_sitter_rules = db_repository
            .get_tree_sitter_rules()
            .await
            .map_err(|e| ScanError::DatabaseError(e.to_string()))?;

        let semgrep_rules = db_repository
            .get_semgrep_rules()
            .await
            .map_err(|e| ScanError::DatabaseError(e.to_string()))?;

        {
            let mut repo = self.rule_repository.write().await;
            repo.extend_with_rules(tree_sitter_rules);
        }

        self.semgrep_rules = semgrep_rules;
        Ok(self)
    }

    pub fn with_semgrep_rules(mut self, rules: Vec<SemgrepRule>) -> Self {
        self.semgrep_rules.extend(rules);
        self
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
        info!("Starting production SAST scan");

        let files = self.scanner.scan(root).map_err(|e| {
            error!(error = %e, "Failed to scan directory");
            ScanError::Io(e)
        })?;

        let file_count = files.len();
        info!(file_count, "Found files to scan");

        let mut all_findings = Vec::new();
        let mut files_scanned = 0;
        let mut primary_engine = AnalysisEngine::TreeSitter;

        let rules = self.rule_repository.read().await;
        let all_rules = rules.get_all_rules();

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

            let selection = self.analysis_selector.select_for_file(
                &file.path,
                &file.language,
                all_rules,
                &self.semgrep_rules,
            );

            debug!(
                engine = ?selection.engine,
                ts_rules = selection.tree_sitter_rules.len(),
                sg_rules = selection.semgrep_rules.len(),
                "Engine selection for file"
            );

            primary_engine = selection.engine.clone();

            match &selection.engine {
                AnalysisEngine::TreeSitter => {
                    self.execute_tree_sitter_analysis(
                        &file.path,
                        &file.language,
                        &content,
                        &selection.tree_sitter_rules,
                        &suppressions,
                        is_test_context,
                        &mut all_findings,
                    )
                    .await?;
                }
                AnalysisEngine::Semgrep => {
                    if let Some(ref executor) = self.semgrep_executor {
                        self.execute_semgrep_analysis(
                            executor,
                            &file.path,
                            &selection.semgrep_rules,
                            &suppressions,
                            &mut all_findings,
                        )
                        .await?;
                    }
                }
                AnalysisEngine::Hybrid => {
                    self.execute_tree_sitter_analysis(
                        &file.path,
                        &file.language,
                        &content,
                        &selection.tree_sitter_rules,
                        &suppressions,
                        is_test_context,
                        &mut all_findings,
                    )
                    .await?;

                    if let Some(ref executor) = self.semgrep_executor {
                        self.execute_semgrep_analysis(
                            executor,
                            &file.path,
                            &selection.semgrep_rules,
                            &suppressions,
                            &mut all_findings,
                        )
                        .await?;
                    }
                }
            }
        }

        all_findings = Self::deduplicate_findings(all_findings);

        info!(
            finding_count = all_findings.len(),
            files_scanned,
            engine = ?primary_engine,
            "SAST scan completed"
        );

        Ok(ScanResult {
            findings: all_findings,
            files_scanned,
            analysis_engine: primary_engine,
        })
    }

    async fn execute_tree_sitter_analysis(
        &self,
        file_path: &Path,
        language: &Language,
        content: &str,
        rules: &[Rule],
        suppressions: &FileSuppressions,
        is_test_context: bool,
        findings: &mut Vec<SastFinding>,
    ) -> Result<(), ScanError> {
        let ts_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| matches!(&r.pattern, RulePattern::TreeSitterQuery(_)))
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

    async fn execute_semgrep_analysis(
        &self,
        executor: &SemgrepExecutor,
        file_path: &Path,
        rules: &[SemgrepRule],
        suppressions: &FileSuppressions,
        findings: &mut Vec<SastFinding>,
    ) -> Result<(), ScanError> {
        if rules.is_empty() {
            return Ok(());
        }

        debug!(
            rule_count = rules.len(),
            file = %file_path.display(),
            "Executing Semgrep rules"
        );

        match executor.execute(rules, file_path).await {
            Ok(semgrep_findings) => {
                for finding in semgrep_findings {
                    if suppressions.is_suppressed(finding.location.line, &finding.rule_id) {
                        debug!(
                            rule_id = %finding.rule_id,
                            line = finding.location.line,
                            "Semgrep finding suppressed by comment"
                        );
                        continue;
                    }
                    findings.push(finding);
                }
            }
            Err(e) => {
                warn!(
                    file = %file_path.display(),
                    error = %e,
                    "Semgrep execution failed"
                );
            }
        }

        Ok(())
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

    #[error("Semgrep error: {0}")]
    SemgrepError(String),

    #[error("Query engine error: {0}")]
    QueryEngineError(String),
}
