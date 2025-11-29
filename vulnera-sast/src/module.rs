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
use crate::domain::entities::Severity as SastSeverity;

/// SAST analysis module
pub struct SastModule {
    use_case: Arc<ScanProjectUseCase>,
}

impl SastModule {
    pub fn new() -> Self {
        Self::with_config(&SastConfig::default())
    }

    pub fn with_config(config: &SastConfig) -> Self {
        Self {
            use_case: Arc::new(ScanProjectUseCase::with_config(
                config,
                AnalysisConfig::default(),
            )),
        }
    }

    /// Create with custom analysis config
    pub fn with_full_config(sast_config: &SastConfig, analysis_config: AnalysisConfig) -> Self {
        Self {
            use_case: Arc::new(ScanProjectUseCase::with_config(
                sast_config,
                analysis_config,
            )),
        }
    }

    /// Create with a pre-built use case (dependency injection)
    ///
    /// Use this when you want to inject a fully-configured ScanProjectUseCase,
    /// e.g., one with database rules loaded and AST cache configured.
    ///
    /// # Example
    /// ```ignore
    /// let use_case = ScanProjectUseCase::with_config(&config, analysis_config)
    ///     .with_database_rules(&db_repo).await?
    ///     .with_ast_cache(cache);
    /// let module = SastModule::with_use_case(Arc::new(use_case));
    /// ```
    pub fn with_use_case(use_case: Arc<ScanProjectUseCase>) -> Self {
        Self { use_case }
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
