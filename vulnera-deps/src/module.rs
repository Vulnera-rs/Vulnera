//! Dependency analyzer module implementation

use async_trait::async_trait;
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
            parser_factory,
            vulnerability_repository,
            cache_service,
            max_concurrent_requests,
            max_concurrent_registry_queries,
        ));

        Self { use_case }
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
            parser_factory,
            vulnerability_repository,
            cache_service,
            max_concurrent_requests,
            max_concurrent_registry_queries,
            project_root,
        ));

        Self { use_case }
    }
}

#[async_trait]
impl AnalysisModule for DependencyAnalyzerModule {
    fn module_type(&self) -> ModuleType {
        ModuleType::DependencyAnalyzer
    }

    async fn execute(&self, config: &ModuleConfig) -> Result<ModuleResult, ModuleExecutionError> {
        let start_time = std::time::Instant::now();

        // For now, we need to extract file content and ecosystem from config
        // In a real implementation, we'd read the file from source_uri
        // For now, return an error if file_content is not in config
        let file_content = config
            .config
            .get("file_content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ModuleExecutionError::InvalidConfig("file_content not found in config".to_string())
            })?;

        let ecosystem_str = config
            .config
            .get("ecosystem")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ModuleExecutionError::InvalidConfig("ecosystem not found in config".to_string())
            })?;

        let ecosystem = match ecosystem_str.to_lowercase().as_str() {
            "npm" => vulnera_core::domain::vulnerability::value_objects::Ecosystem::Npm,
            "pypi" | "pip" | "python" => {
                vulnera_core::domain::vulnerability::value_objects::Ecosystem::PyPI
            }
            "maven" => vulnera_core::domain::vulnerability::value_objects::Ecosystem::Maven,
            "cargo" | "rust" => {
                vulnera_core::domain::vulnerability::value_objects::Ecosystem::Cargo
            }
            "go" => vulnera_core::domain::vulnerability::value_objects::Ecosystem::Go,
            "packagist" | "composer" | "php" => {
                vulnera_core::domain::vulnerability::value_objects::Ecosystem::Packagist
            }
            _ => {
                return Err(ModuleExecutionError::InvalidConfig(format!(
                    "Invalid ecosystem: {}",
                    ecosystem_str
                )));
            }
        };

        let filename = config.config.get("filename").and_then(|v| v.as_str());

        // Execute analysis
        let (analysis_report, _dependency_graph) = self
            .use_case
            .execute(file_content, ecosystem, filename)
            .await
            .map_err(|e| ModuleExecutionError::ExecutionFailed(e.to_string()))?;

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
                        let nearest_safe = affected_pkg.fixed_versions.iter()
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
