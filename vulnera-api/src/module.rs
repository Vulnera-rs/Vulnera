//! API security module implementation

use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;

use vulnera_core::config::ApiSecurityConfig;
use vulnera_core::domain::module::{
    AnalysisModule, Finding, FindingConfidence, FindingSeverity, FindingType, Location,
    ModuleConfig, ModuleExecutionError, ModuleResult, ModuleResultMetadata, ModuleType,
};

use crate::application::use_cases::ScanApiSpecificationUseCase;
use crate::domain::entities::FindingSeverity as ApiSeverity;

/// API security analysis module
pub struct ApiSecurityModule {
    use_case: Arc<ScanApiSpecificationUseCase>,
}

impl ApiSecurityModule {
    pub fn new() -> Self {
        Self::with_config(&ApiSecurityConfig::default())
    }

    pub fn with_config(config: &ApiSecurityConfig) -> Self {
        Self {
            use_case: Arc::new(ScanApiSpecificationUseCase::with_config(config)),
        }
    }
}

#[async_trait]
impl AnalysisModule for ApiSecurityModule {
    fn module_type(&self) -> ModuleType {
        ModuleType::ApiSecurity
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
            .map_err(|e| ModuleExecutionError::ExecutionFailed(e.to_string()))?;

        // Convert API findings to orchestrator findings
        let findings: Vec<Finding> = scan_result
            .findings
            .into_iter()
            .map(|f| Finding {
                id: f.id,
                r#type: FindingType::Vulnerability, // API security issues are vulnerabilities
                rule_id: None,
                location: Location {
                    path: f.location.file_path,
                    line: f.location.line,
                    column: None,
                    end_line: None,
                    end_column: None,
                },
                severity: match f.severity {
                    ApiSeverity::Critical => FindingSeverity::Critical,
                    ApiSeverity::High => FindingSeverity::High,
                    ApiSeverity::Medium => FindingSeverity::Medium,
                    ApiSeverity::Low => FindingSeverity::Low,
                    ApiSeverity::Info => FindingSeverity::Info,
                },
                confidence: FindingConfidence::High, // API spec findings are high confidence
                description: f.description,
                recommendation: Some(f.recommendation),
            })
            .collect();

        let duration = start_time.elapsed();

        Ok(ModuleResult {
            job_id: config.job_id,
            module_type: self.module_type(),
            findings,
            metadata: ModuleResultMetadata {
                files_scanned: 1, // Single OpenAPI spec file
                duration_ms: duration.as_millis() as u64,
                additional_info: std::collections::HashMap::new(),
            },
            error: None,
        })
    }
}

impl Default for ApiSecurityModule {
    fn default() -> Self {
        Self::new()
    }
}

