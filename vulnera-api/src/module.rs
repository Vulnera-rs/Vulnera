//! API security module implementation

use async_trait::async_trait;
use std::path::{Path, PathBuf};
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

    /// Discover OpenAPI specification file in a directory
    fn discover_openapi_spec(&self, dir: &Path) -> Option<PathBuf> {
        let candidates = vec![
            "openapi.yaml",
            "openapi.yml",
            "openapi.json",
            "swagger.yaml",
            "swagger.yml",
            "swagger.json",
            "api/openapi.yaml",
            "api/openapi.yml",
            "api/openapi.json",
            "docs/openapi.yaml",
            "docs/openapi.yml",
            "docs/openapi.json",
            "spec/openapi.yaml",
            "spec/openapi.yml",
            "spec/openapi.json",
        ];

        for candidate in candidates {
            let spec_path = dir.join(candidate);
            if spec_path.exists() && spec_path.is_file() {
                tracing::info!("Discovered OpenAPI specification: {}", spec_path.display());
                return Some(spec_path);
            }
        }

        None
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

        // Discover OpenAPI spec file
        let spec_file = if source_path.is_file() {
            source_path.to_path_buf()
        } else if source_path.is_dir() {
            match self.discover_openapi_spec(source_path) {
                Some(path) => path,
                None => {
                    // No OpenAPI spec found - gracefully skip
                    tracing::warn!(
                        "No OpenAPI specification found in directory: {}",
                        config.source_uri
                    );
                    return Ok(ModuleResult {
                        job_id: config.job_id,
                        module_type: self.module_type(),
                        findings: Vec::new(),
                        metadata: ModuleResultMetadata {
                            files_scanned: 0,
                            duration_ms: start_time.elapsed().as_millis() as u64,
                            additional_info: std::collections::HashMap::new(),
                        },
                        error: None,
                    });
                }
            }
        } else {
            return Err(ModuleExecutionError::InvalidConfig(format!(
                "Source path is neither a file nor a directory: {}",
                config.source_uri
            )));
        };

        // Execute scan
        let scan_result = self
            .use_case
            .execute(&spec_file)
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
                secret_metadata: None,
                enrichment: None,
            })
            .collect();

        let duration = start_time.elapsed();

        // Expose score in metadata
        let mut additional_info = std::collections::HashMap::new();
        additional_info.insert(
            "contract_integrity_score".to_string(),
            scan_result.score.to_string(),
        );

        Ok(ModuleResult {
            job_id: config.job_id,
            module_type: self.module_type(),
            findings,
            metadata: ModuleResultMetadata {
                files_scanned: 1, // Single OpenAPI spec file
                duration_ms: duration.as_millis() as u64,
                additional_info,
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
