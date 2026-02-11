//! SAST module implementation

use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;

use vulnera_core::config::SastConfig;
use vulnera_core::domain::module::{
    AnalysisModule, Finding, FindingConfidence, FindingSeverity, FindingType, Location,
    ModuleConfig, ModuleExecutionError, ModuleResult, ModuleResultMetadata, ModuleType,
};

use crate::application::use_cases::{AnalysisConfig, ScanProjectUseCase};
use crate::domain::finding::Severity as SastSeverity;
use crate::infrastructure::ast_cache::AstCacheService;

/// SAST analysis module.
///
/// Construct via the builder:
/// ```rust
/// use vulnera_sast::SastModule;
/// let module = SastModule::builder().build();
/// ```
pub struct SastModule {
    use_case: Arc<ScanProjectUseCase>,
}

/// Builder for [`SastModule`].
///
/// All fields are optional — omitting everything yields a sensible default
/// configuration (zero-config UX).
pub struct SastModuleBuilder {
    sast_config: Option<SastConfig>,
    analysis_config: Option<AnalysisConfig>,
    ast_cache: Option<Arc<dyn AstCacheService>>,
    use_case_override: Option<Arc<ScanProjectUseCase>>,
}

impl SastModuleBuilder {
    /// Override the SAST config (scanning depth, excludes, rule file, etc.).
    pub fn sast_config(mut self, config: &SastConfig) -> Self {
        self.sast_config = Some(config.clone());
        self
    }

    /// Override the analysis config (concurrency, timeouts, cache, etc.).
    ///
    /// If omitted and a `SastConfig` is set, `AnalysisConfig::from(&sast_config)` is used.
    /// If both are omitted, `AnalysisConfig::default()` applies.
    pub fn analysis_config(mut self, config: AnalysisConfig) -> Self {
        self.analysis_config = Some(config);
        self
    }

    /// Attach a Dragonfly-backed AST cache for parsed file caching.
    pub fn ast_cache(mut self, cache: Arc<dyn AstCacheService>) -> Self {
        self.ast_cache = Some(cache);
        self
    }

    /// Inject a fully-constructed `ScanProjectUseCase` (overrides all other settings).
    ///
    /// Use this from the composition root when you need full control.
    pub fn use_case(mut self, use_case: Arc<ScanProjectUseCase>) -> Self {
        self.use_case_override = Some(use_case);
        self
    }

    /// Build the `SastModule`.
    pub fn build(self) -> SastModule {
        let use_case = if let Some(uc) = self.use_case_override {
            uc
        } else {
            let sast_cfg = self.sast_config.unwrap_or_default();
            let analysis_cfg = self
                .analysis_config
                .unwrap_or_else(|| AnalysisConfig::from(&sast_cfg));

            let uc = ScanProjectUseCase::with_config(&sast_cfg, analysis_cfg);
            let uc = if let Some(cache) = self.ast_cache {
                uc.with_ast_cache(cache)
            } else {
                uc
            };
            Arc::new(uc)
        };

        SastModule { use_case }
    }
}

impl SastModule {
    /// Create a builder for configuring and constructing a `SastModule`.
    pub fn builder() -> SastModuleBuilder {
        SastModuleBuilder {
            sast_config: None,
            analysis_config: None,
            ast_cache: None,
            use_case_override: None,
        }
    }

    // ── Convenience constructors (thin wrappers around the builder) ──

    /// Zero-config constructor — sensible defaults, auto-detect depth.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Construct from a `SastConfig` (derives `AnalysisConfig` automatically).
    pub fn with_config(config: &SastConfig) -> Self {
        Self::builder().sast_config(config).build()
    }
}

#[async_trait]
impl AnalysisModule for SastModule {
    fn module_type(&self) -> ModuleType {
        ModuleType::SAST
    }

    async fn execute(&self, config: &ModuleConfig) -> Result<ModuleResult, ModuleExecutionError> {
        let start_time = std::time::Instant::now();

        // Get source path from config
        let source_path = Path::new(&config.source_uri);
        if !source_path.exists() {
            return Err(ModuleExecutionError::InvalidConfig(format!(
                "Source path does not exist: {}",
                config.source_uri
            )));
        }

        // Execute scan
        let scan_result = self
            .use_case
            .execute(source_path)
            .await
            .map_err(|e| ModuleExecutionError::ExecutionFailed(e.to_string()))?;

        // Convert SAST findings to orchestrator findings
        let findings: Vec<Finding> = scan_result
            .findings
            .into_iter()
            .map(|f| Finding {
                id: f.id,
                r#type: FindingType::Vulnerability,
                rule_id: Some(f.rule_id),
                location: Location {
                    path: f.location.file_path,
                    line: Some(f.location.line),
                    column: f.location.column,
                    end_line: f.location.end_line,
                    end_column: f.location.end_column,
                },
                severity: match f.severity {
                    SastSeverity::Critical => FindingSeverity::Critical,
                    SastSeverity::High => FindingSeverity::High,
                    SastSeverity::Medium => FindingSeverity::Medium,
                    SastSeverity::Low => FindingSeverity::Low,
                    SastSeverity::Info => FindingSeverity::Info,
                },
                confidence: match f.confidence {
                    crate::domain::value_objects::Confidence::High => FindingConfidence::High,
                    crate::domain::value_objects::Confidence::Medium => FindingConfidence::Medium,
                    crate::domain::value_objects::Confidence::Low => FindingConfidence::Low,
                },
                description: f.description,
                recommendation: f.recommendation,
                enrichment: None,
            })
            .collect();

        let duration = start_time.elapsed();

        Ok(ModuleResult {
            job_id: config.job_id,
            module_type: ModuleType::SAST,
            findings,
            metadata: ModuleResultMetadata {
                files_scanned: scan_result.files_scanned,
                duration_ms: duration.as_millis() as u64,
                additional_info: std::collections::HashMap::new(),
            },
            error: None,
        })
    }
}

impl Default for SastModule {
    fn default() -> Self {
        Self::new()
    }
}
