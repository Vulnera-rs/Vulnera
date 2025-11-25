//! Secret detection module implementation

use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;

use vulnera_core::config::SecretDetectionConfig;
use vulnera_core::domain::module::{
    AnalysisModule, Finding, FindingConfidence, FindingSeverity, FindingType, Location,
    ModuleConfig, ModuleExecutionError, ModuleResult, ModuleResultMetadata, ModuleType,
};

use crate::application::use_cases::ScanForSecretsUseCase;
use crate::domain::entities::Severity as SecretSeverity;

/// Secret detection analysis module
pub struct SecretDetectionModule {
    use_case: Arc<ScanForSecretsUseCase>,
}

impl SecretDetectionModule {
    pub fn new() -> Self {
        Self::with_config(&SecretDetectionConfig::default())
    }

    pub fn with_config(config: &SecretDetectionConfig) -> Self {
        Self {
            use_case: Arc::new(ScanForSecretsUseCase::with_config(config)),
        }
    }
}

#[async_trait]
impl AnalysisModule for SecretDetectionModule {
    fn module_type(&self) -> ModuleType {
        ModuleType::SecretDetection
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

        // Convert secret findings to orchestrator findings
        let findings: Vec<Finding> = scan_result
            .findings
            .into_iter()
            .map(|f| Finding {
                id: f.id,
                r#type: FindingType::Secret,
                rule_id: Some(f.rule_id),
                location: Location {
                    path: f.location.file_path,
                    line: Some(f.location.line),
                    column: f.location.column,
                    end_line: f.location.end_line,
                    end_column: f.location.end_column,
                },
                severity: match f.severity {
                    SecretSeverity::Critical => FindingSeverity::Critical,
                    SecretSeverity::High => FindingSeverity::High,
                    SecretSeverity::Medium => FindingSeverity::Medium,
                    SecretSeverity::Low => FindingSeverity::Low,
                    SecretSeverity::Info => FindingSeverity::Info,
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
            module_type: ModuleType::SecretDetection,
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

impl Default for SecretDetectionModule {
    fn default() -> Self {
        Self::new()
    }
}
