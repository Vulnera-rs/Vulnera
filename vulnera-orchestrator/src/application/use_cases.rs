//! Orchestrator use cases

use std::sync::Arc;

use vulnera_core::domain::module::{FindingSeverity, ModuleConfig, ModuleExecutionError, ModuleResult};

use crate::domain::entities::{AggregatedReport, AnalysisJob, ReportSummary};
use crate::domain::services::{ModuleSelector, ProjectDetectionError, ProjectDetector};
use crate::domain::value_objects::{AnalysisDepth, JobStatus, SourceType};
use crate::infrastructure::ModuleRegistry;

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
    ) -> Result<AnalysisJob, ProjectDetectionError> {
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
        Ok(AnalysisJob::new(project.id, modules_to_run, analysis_depth))
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

    pub async fn execute(
        &self,
        job: &mut AnalysisJob,
        source_uri: String,
    ) -> Result<Vec<ModuleResult>, ModuleExecutionError> {
        job.status = JobStatus::Running;
        job.started_at = Some(chrono::Utc::now());

        let mut results = Vec::new();

        for module_type in &job.modules_to_run {
            if let Some(module) = self.module_registry.get_module(module_type) {
                let config = ModuleConfig {
                    job_id: job.job_id,
                    project_id: job.project_id.clone(),
                    source_uri: source_uri.clone(),
                    config: std::collections::HashMap::new(),
                };

                match module.execute(&config).await {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        tracing::error!(
                            module = ?module_type,
                            error = %e,
                            "Module execution failed"
                        );
                        results.push(ModuleResult {
                            job_id: job.job_id,
                            module_type: module_type.clone(),
                            findings: vec![],
                            metadata: Default::default(),
                            error: Some(e.to_string()),
                        });
                    }
                }
            } else {
                tracing::warn!(module = ?module_type, "Module not found in registry");
            }
        }

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
