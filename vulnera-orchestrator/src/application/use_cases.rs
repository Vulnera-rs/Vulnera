//! Orchestrator use cases

use std::path::PathBuf;
use std::sync::Arc;

use tokio::task::JoinSet;
use tracing::{debug, error, info, instrument, warn};
use vulnera_core::domain::module::{
    FindingSeverity, ModuleConfig, ModuleExecutionError, ModuleResult,
};

use crate::domain::entities::{AggregatedReport, AnalysisJob, Project, ReportSummary};
use crate::domain::services::{ModuleSelector, ProjectDetectionError, ProjectDetector};
use crate::domain::value_objects::{AnalysisDepth, JobStatus, SourceType};
use crate::infrastructure::ModuleRegistry;

/// Infer ecosystem from dependency file path.
fn infer_ecosystem_from_path(path: &str) -> Option<&'static str> {
    let lower = path.to_lowercase();
    if lower.ends_with("package.json")
        || lower.ends_with("package-lock.json")
        || lower.ends_with("yarn.lock")
    {
        Some("npm")
    } else if lower.ends_with("requirements.txt")
        || lower.ends_with("pipfile")
        || lower.ends_with("pyproject.toml")
        || lower.ends_with("poetry.lock")
        || lower.ends_with("uv.lock")
    {
        Some("pypi")
    } else if lower.ends_with("cargo.toml") || lower.ends_with("cargo.lock") {
        Some("cargo")
    } else if lower.ends_with("go.mod") || lower.ends_with("go.sum") {
        Some("go")
    } else if lower.ends_with("pom.xml") || lower.ends_with("build.gradle") {
        Some("maven")
    } else if lower.ends_with("composer.json") || lower.ends_with("composer.lock") {
        Some("packagist")
    } else {
        None
    }
}

/// Use case for creating a new analysis job
pub struct CreateAnalysisJobUseCase {
    project_detector: Arc<dyn ProjectDetector>,
    module_selector: Arc<dyn ModuleSelector>,
}

impl CreateAnalysisJobUseCase {
    pub fn new(
        project_detector: Arc<dyn ProjectDetector>,
        module_selector: Arc<dyn ModuleSelector>,
    ) -> Self {
        Self {
            project_detector,
            module_selector,
        }
    }

    pub async fn execute(
        &self,
        source_type: SourceType,
        source_uri: String,
        analysis_depth: AnalysisDepth,
    ) -> Result<(AnalysisJob, Project), ProjectDetectionError> {
        // Detect project characteristics
        let project = self
            .project_detector
            .detect_project(&source_type, &source_uri)
            .await?;

        // Select modules to run
        let modules_to_run = self
            .module_selector
            .select_modules(&project, &analysis_depth);

        // Create job
        let job = AnalysisJob::new(project.id.clone(), modules_to_run, analysis_depth);
        Ok((job, project))
    }
}

/// Use case for executing an analysis job
pub struct ExecuteAnalysisJobUseCase {
    module_registry: Arc<ModuleRegistry>,
}

impl ExecuteAnalysisJobUseCase {
    pub fn new(module_registry: Arc<ModuleRegistry>) -> Self {
        Self { module_registry }
    }

    #[instrument(skip(self, job, project), fields(job_id = %job.job_id, module_count = job.modules_to_run.len()))]
    pub async fn execute(
        &self,
        job: &mut AnalysisJob,
        project: &Project,
    ) -> Result<Vec<ModuleResult>, ModuleExecutionError> {
        let start_time = std::time::Instant::now();
        job.status = JobStatus::Running;
        job.started_at = Some(chrono::Utc::now());

        let effective_source_uri = project
            .metadata
            .root_path
            .clone()
            .unwrap_or_else(|| project.source_uri.clone());

        info!(
            job_id = %job.job_id,
            module_count = job.modules_to_run.len(),
            "Starting parallel execution of analysis modules"
        );

        // Create JoinSet for parallel execution
        // We always return Ok from spawned tasks (errors are converted to ModuleResult with error field)
        let mut join_set: JoinSet<(vulnera_core::domain::module::ModuleType, ModuleResult)> =
            JoinSet::new();

        // Spawn all module execution tasks concurrently
        for module_type in &job.modules_to_run {
            if let Some(module) = self.module_registry.get_module(module_type) {
                let mut config_map = std::collections::HashMap::new();

                // For DependencyAnalyzer, load manifest content from metadata
                if *module_type == vulnera_core::domain::module::ModuleType::DependencyAnalyzer {
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
                                if let Some(ecosystem) = infer_ecosystem_from_path(manifest_path) {
                                    config_map.insert(
                                        "ecosystem".to_string(),
                                        serde_json::Value::String(ecosystem.to_string()),
                                    );
                                }
                            }
                            Err(e) => {
                                warn!(
                                    job_id = %job.job_id,
                                    manifest = %manifest_path,
                                    error = %e,
                                    "Failed to load dependency manifest"
                                );
                            }
                        }
                    }
                }

                let config = ModuleConfig {
                    job_id: job.job_id,
                    project_id: job.project_id.clone(),
                    source_uri: effective_source_uri.clone(),
                    config: config_map,
                };
                let module_type_clone = module_type.clone();
                let module_arc = Arc::clone(&module);

                debug!(
                    job_id = %job.job_id,
                    module = ?module_type_clone,
                    "Spawning module execution task"
                );

                join_set.spawn(async move {
                    let module_start = std::time::Instant::now();
                    let result = module_arc.execute(&config).await;
                    let module_duration = module_start.elapsed();

                    match &result {
                        Ok(_) => {
                            debug!(
                                module = ?module_type_clone,
                                duration_ms = module_duration.as_millis(),
                                "Module execution completed successfully"
                            );
                        }
                        Err(e) => {
                            error!(
                                module = ?module_type_clone,
                                duration_ms = module_duration.as_millis(),
                                error = %e,
                                "Module execution failed"
                            );
                        }
                    }

                    // Convert error to ModuleResult with error field set
                    // Always return a ModuleResult (either success or error)
                    match result {
                        Ok(r) => (module_type_clone, r),
                        Err(e) => {
                            // Create error result
                            let error_result = ModuleResult {
                                job_id: config.job_id,
                                module_type: module_type_clone.clone(),
                                findings: vec![],
                                metadata: Default::default(),
                                error: Some(e.to_string()),
                            };
                            (module_type_clone, error_result)
                        }
                    }
                });
            } else {
                warn!(
                    job_id = %job.job_id,
                    module = ?module_type,
                    "Module not found in registry"
                );
            }
        }

        // Collect results as they complete (in completion order)
        let mut results = Vec::new();
        let mut completed_count = 0;
        let total_modules = join_set.len();

        while let Some(res) = join_set.join_next().await {
            completed_count += 1;
            match res {
                Ok((module_type, result)) => {
                    if result.error.is_none() {
                        info!(
                            job_id = %job.job_id,
                            module = ?module_type,
                            completed = completed_count,
                            total = total_modules,
                            "Module completed successfully"
                        );
                    } else {
                        warn!(
                            job_id = %job.job_id,
                            module = ?module_type,
                            completed = completed_count,
                            total = total_modules,
                            error = result.error.as_deref().unwrap_or("unknown"),
                            "Module completed with error"
                        );
                    }
                    results.push(result);
                }
                Err(e) => {
                    // Task panicked - this is a critical error
                    error!(
                        job_id = %job.job_id,
                        completed = completed_count,
                        total = total_modules,
                        error = %e,
                        "Module execution task panicked"
                    );
                    // We can't create a proper ModuleResult here without knowing which module panicked
                    // This should be extremely rare - log it and continue with other modules
                }
            }
        }

        // Handle modules that weren't found in registry
        // We need to create error results for them
        let executed_module_types: std::collections::HashSet<_> =
            results.iter().map(|r| r.module_type.clone()).collect();

        for module_type in &job.modules_to_run {
            if !executed_module_types.contains(module_type) {
                warn!(
                    job_id = %job.job_id,
                    module = ?module_type,
                    "Creating error result for module not found in registry"
                );
                results.push(ModuleResult {
                    job_id: job.job_id,
                    module_type: module_type.clone(),
                    findings: vec![],
                    metadata: Default::default(),
                    error: Some("Module not found in registry".to_string()),
                });
            }
        }

        let total_duration = start_time.elapsed();
        info!(
            job_id = %job.job_id,
            total_modules = total_modules,
            completed_modules = results.len(),
            duration_ms = total_duration.as_millis(),
            "All modules completed"
        );

        job.status = JobStatus::Completed;
        job.completed_at = Some(chrono::Utc::now());

        Ok(results)
    }
}

/// Use case for aggregating results from multiple modules
pub struct AggregateResultsUseCase;

impl AggregateResultsUseCase {
    pub fn new() -> Self {
        Self
    }

    pub fn execute(
        &self,
        job: &AnalysisJob,
        module_results: Vec<ModuleResult>,
    ) -> AggregatedReport {
        let mut all_findings = Vec::new();
        let mut modules_completed = 0;
        let mut modules_failed = 0;

        for result in &module_results {
            if result.error.is_none() {
                modules_completed += 1;
                all_findings.extend(result.findings.clone());
            } else {
                modules_failed += 1;
            }
        }

        // Deduplicate findings (simple approach - by ID)
        let mut seen = std::collections::HashSet::new();
        let mut deduplicated = Vec::new();
        for finding in all_findings {
            if seen.insert(finding.id.clone()) {
                deduplicated.push(finding);
            }
        }

        // Calculate summary
        let mut summary = ReportSummary::default();
        summary.total_findings = deduplicated.len();
        summary.modules_completed = modules_completed;
        summary.modules_failed = modules_failed;

        for finding in &deduplicated {
            match finding.severity {
                FindingSeverity::Critical => summary.critical += 1,
                FindingSeverity::High => summary.high += 1,
                FindingSeverity::Medium => summary.medium += 1,
                FindingSeverity::Low => summary.low += 1,
                FindingSeverity::Info => summary.info += 1,
            }
        }

        AggregatedReport {
            job_id: job.job_id,
            project_id: job.project_id.clone(),
            status: job.status.clone(),
            summary,
            findings: deduplicated,
            module_results,
            created_at: chrono::Utc::now(),
        }
    }
}

impl Default for AggregateResultsUseCase {
    fn default() -> Self {
        Self::new()
    }
}
