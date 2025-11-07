//! SAST module implementation

use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;

use vulnera_orchestrator::domain::entities::{
    Finding, FindingConfidence, FindingSeverity, FindingType, Location, ModuleResult,
    ModuleResultMetadata,
};
use vulnera_orchestrator::domain::module::{AnalysisModule, ModuleConfig, ModuleExecutionError};
use vulnera_orchestrator::domain::value_objects::ModuleType;

use crate::application::use_cases::ScanProjectUseCase;
use crate::domain::entities::Severity as SastSeverity;

/// SAST analysis module
pub struct SastModule {
    use_case: Arc<ScanProjectUseCase>,
}

impl SastModule {
    pub fn new() -> Self {
        Self {
            use_case: Arc::new(ScanProjectUseCase::new()),
        }
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
        let sast_findings = self
            .use_case
            .execute(source_path)
            .await
            .map_err(|e| ModuleExecutionError::ExecutionFailed(e.to_string()))?;

        // Convert SAST findings to orchestrator findings
        let findings: Vec<Finding> = sast_findings
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
            })
            .collect();

        let duration = start_time.elapsed();

        Ok(ModuleResult {
            job_id: config.job_id,
            module_type: ModuleType::SAST,
            findings,
            metadata: ModuleResultMetadata {
                files_scanned: 0, // TODO: track this
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
