//! Dependency analyzer module implementation

use async_trait::async_trait;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use vulnera_core::domain::vulnerability::repositories::IVulnerabilityRepository;
use vulnera_core::infrastructure::cache::CacheServiceImpl;
use vulnera_core::infrastructure::parsers::ParserFactory;

use vulnera_core::domain::module::{
    AnalysisModule, Finding, FindingConfidence, FindingSeverity, FindingType, Location,
    ModuleConfig, ModuleExecutionError, ModuleResult, ModuleResultMetadata, ModuleType,
};

use crate::use_cases::AnalyzeDependenciesUseCase;

/// Dependency analyzer module
pub struct DependencyAnalyzerModule {
    use_case: Arc<AnalyzeDependenciesUseCase<CacheServiceImpl>>,
    parser_factory: Arc<ParserFactory>,
}

impl DependencyAnalyzerModule {
    pub fn new(
        parser_factory: Arc<ParserFactory>,
        vulnerability_repository: Arc<dyn IVulnerabilityRepository>,
        cache_service: Arc<CacheServiceImpl>,
        max_concurrent_requests: usize,
        max_concurrent_registry_queries: usize,
    ) -> Self {
        let use_case = Arc::new(AnalyzeDependenciesUseCase::new_with_config(
            parser_factory.clone(),
            vulnerability_repository,
            cache_service,
            max_concurrent_requests,
            max_concurrent_registry_queries,
        ));

        Self {
            use_case,
            parser_factory,
        }
    }

    /// Create a new module with analysis context for workspace-aware analysis
    pub fn new_with_context(
        parser_factory: Arc<ParserFactory>,
        vulnerability_repository: Arc<dyn IVulnerabilityRepository>,
        cache_service: Arc<CacheServiceImpl>,
        max_concurrent_requests: usize,
        max_concurrent_registry_queries: usize,
        project_root: Option<std::path::PathBuf>,
    ) -> Self {
        let use_case = Arc::new(AnalyzeDependenciesUseCase::new_with_context(
            parser_factory.clone(),
            vulnerability_repository,
            cache_service,
            max_concurrent_requests,
            max_concurrent_registry_queries,
            project_root,
        ));

        Self {
            use_case,
            parser_factory,
        }
    }
}

#[async_trait]
impl AnalysisModule for DependencyAnalyzerModule {
    fn module_type(&self) -> ModuleType {
        ModuleType::DependencyAnalyzer
    }

    async fn prepare_config(
        &self,
        project: &vulnera_core::domain::project::Project,
    ) -> Result<std::collections::HashMap<String, serde_json::Value>, ModuleExecutionError> {
        let mut config_map = std::collections::HashMap::new();

        if let Some(manifest_path) = project.metadata.dependency_files.first() {
            match tokio::fs::read_to_string(manifest_path).await {
                Ok(content) => {
                    config_map.insert(
                        "file_content".to_string(),
                        serde_json::Value::String(content),
                    );
                    config_map.insert(
                        "filename".to_string(),
                        serde_json::Value::String(
                            PathBuf::from(manifest_path)
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("unknown")
                                .to_string(),
                        ),
                    );
                    if let Some(ecosystem) = self.parser_factory.detect_ecosystem(manifest_path) {
                        config_map.insert(
                            "ecosystem".to_string(),
                            serde_json::Value::String(ecosystem.to_string()),
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        manifest = %manifest_path,
                        error = %e,
                        "Failed to load dependency manifest"
                    );
                }
            }
        }

        Ok(config_map)
    }

    async fn execute(&self, config: &ModuleConfig) -> Result<ModuleResult, ModuleExecutionError> {
        let start_time = std::time::Instant::now();

        // Extract file content and ecosystem from config
        // If no dependency file was provided, return an empty result (not an error)
        // This can happen when the project detection didn't find any dependency files
        let file_content = match config.config.get("file_content").and_then(|v| v.as_str()) {
            Some(content) => content,
            None => {
                // No dependency file found - return empty result instead of failing
                let duration = start_time.elapsed();
                return Ok(ModuleResult {
                    job_id: config.job_id,
                    module_type: ModuleType::DependencyAnalyzer,
                    findings: Vec::new(),
                    metadata: ModuleResultMetadata {
                        files_scanned: 0,
                        duration_ms: duration.as_millis() as u64,
                        additional_info: {
                            let mut info = std::collections::HashMap::new();
                            info.insert(
                                "skip_reason".to_string(),
                                "No dependency manifest files found in project".to_string(),
                            );
                            info
                        },
                    },
                    error: None,
                });
            }
        };

        let ecosystem_str = match config.config.get("ecosystem").and_then(|v| v.as_str()) {
            Some(eco) => eco,
            None => {
                // No ecosystem detected - return empty result instead of failing
                let duration = start_time.elapsed();
                return Ok(ModuleResult {
                    job_id: config.job_id,
                    module_type: ModuleType::DependencyAnalyzer,
                    findings: Vec::new(),
                    metadata: ModuleResultMetadata {
                        files_scanned: 0,
                        duration_ms: duration.as_millis() as u64,
                        additional_info: {
                            let mut info = std::collections::HashMap::new();
                            info.insert(
                                "skip_reason".to_string(),
                                "Could not determine ecosystem for dependency file".to_string(),
                            );
                            info
                        },
                    },
                    error: None,
                });
            }
        };

        let ecosystem = vulnera_core::domain::vulnerability::value_objects::Ecosystem::from_str(
            ecosystem_str,
        )
        .map_err(ModuleExecutionError::InvalidConfig)?;

        let filename = config.config.get("filename").and_then(|v| v.as_str());

        // Execute analysis - catch errors and return partial result instead of failing
        let analysis_result = self
            .use_case
            .execute(file_content, ecosystem, filename)
            .await;

        let (analysis_report, _dependency_graph) = match analysis_result {
            Ok(result) => result,
            Err(e) => {
                let error_message = e.to_string();
                tracing::warn!(
                    error = %error_message,
                    ecosystem = %ecosystem_str,
                    "Dependency analysis failed"
                );
                return Err(ModuleExecutionError::ExecutionFailed(error_message));
            }
        };

        // Convert vulnerabilities to findings
        let mut findings = Vec::new();
        for vuln in &analysis_report.vulnerabilities {
            for affected_pkg in &vuln.affected_packages {
                let finding = Finding {
                    id: format!("{}-{}", vuln.id.as_str(), affected_pkg.package.identifier()),
                    r#type: FindingType::Vulnerability,
                    rule_id: Some(vuln.id.as_str().to_string()),
                    location: Location {
                        path: format!(
                            "{}:{}",
                            affected_pkg.package.ecosystem.canonical_name(),
                            affected_pkg.package.name
                        ),
                        line: None,
                        column: None,
                        end_line: None,
                        end_column: None,
                    },
                    severity: match vuln.severity {
                        vulnera_core::domain::vulnerability::value_objects::Severity::Critical => {
                            FindingSeverity::Critical
                        }
                        vulnera_core::domain::vulnerability::value_objects::Severity::High => {
                            FindingSeverity::High
                        }
                        vulnera_core::domain::vulnerability::value_objects::Severity::Medium => {
                            FindingSeverity::Medium
                        }
                        vulnera_core::domain::vulnerability::value_objects::Severity::Low => {
                            FindingSeverity::Low
                        }
                    },
                    confidence: FindingConfidence::High,
                    description: vuln.description.clone(),
                    recommendation: {
                        let current_version = &affected_pkg.package.version;
                        let latest_safe = affected_pkg.recommended_fix();
                        let nearest_safe = affected_pkg
                            .fixed_versions
                            .iter()
                            .filter(|v| *v > current_version)
                            .min();

                        if latest_safe.is_some() || nearest_safe.is_some() {
                            let json = serde_json::json!({
                                "nearest_safe": nearest_safe.map(|v| v.to_string()),
                                "latest_safe": latest_safe.map(|v| v.to_string())
                            });
                            Some(json.to_string())
                        } else {
                            None
                        }
                    },
                    enrichment: None,
                };
                findings.push(finding);
            }
        }

        let duration = start_time.elapsed();

        Ok(ModuleResult {
            job_id: config.job_id,
            module_type: ModuleType::DependencyAnalyzer,
            findings,
            metadata: ModuleResultMetadata {
                files_scanned: analysis_report.packages.len(),
                duration_ms: duration.as_millis() as u64,
                additional_info: std::collections::HashMap::from([
                    (
                        "total_packages".to_string(),
                        analysis_report.packages.len().to_string(),
                    ),
                    (
                        "total_vulnerabilities".to_string(),
                        analysis_report.vulnerabilities.len().to_string(),
                    ),
                ]),
            },
            error: None,
        })
    }
}
