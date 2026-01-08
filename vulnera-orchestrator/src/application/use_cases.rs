//! Orchestrator use cases

use std::sync::Arc;

use tokio::task::JoinSet;
use tracing::{debug, error, info, instrument, warn};
use vulnera_core::domain::module::{
    FindingSeverity, ModuleConfig, ModuleExecutionError, ModuleResult,
};

use crate::domain::entities::{
    AggregatedReport, AnalysisJob, CveInfo, DependencyRecommendations, FindingsByType,
    GroupedDependencyFinding, Project, SeverityBreakdown, Summary, TypeBreakdown,
};
use crate::domain::services::{ModuleSelector, ProjectDetectionError, ProjectDetector};
use crate::domain::value_objects::{AnalysisDepth, JobStatus, SourceType};
use crate::infrastructure::ModuleRegistry;
use vulnera_core::config::SandboxConfig;
use vulnera_sandbox::{SandboxExecutor, SandboxPolicy, SandboxSelector};

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
        aws_credentials: Option<&crate::domain::value_objects::AwsCredentials>,
    ) -> Result<(AnalysisJob, Project), ProjectDetectionError> {
        // Detect project characteristics
        let project = self
            .project_detector
            .detect_project(&source_type, &source_uri, aws_credentials)
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
    executor: Arc<SandboxExecutor>,
    config: SandboxConfig,
}

impl ExecuteAnalysisJobUseCase {
    pub fn new(module_registry: Arc<ModuleRegistry>, config: SandboxConfig) -> Self {
        // Select backend based on config (auto, landlock, process, wasm)
        let backend = SandboxSelector::select_by_name(&config.backend)
            .unwrap_or_else(|| SandboxSelector::select());

        Self {
            module_registry,
            executor: Arc::new(SandboxExecutor::new(backend)),
            config,
        }
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
                // Prepare module-specific configuration from project metadata
                let config_map = match module.prepare_config(project).await {
                    Ok(map) => map,
                    Err(e) => {
                        warn!(
                            job_id = %job.job_id,
                            module = ?module_type,
                            error = %e,
                            "Failed to prepare module configuration"
                        );
                        std::collections::HashMap::new()
                    }
                };

                let config = ModuleConfig {
                    job_id: job.job_id,
                    project_id: job.project_id.clone(),
                    source_uri: effective_source_uri.clone(),
                    config: config_map,
                };
                let module_type_clone = module_type.clone();
                let module_arc = Arc::clone(&module);

                let executor = self.executor.clone();
                let sandbox_timeout = std::time::Duration::from_millis(self.config.timeout_ms);
                let sandbox_mem_bytes = self.config.max_memory_bytes;
                let sandbox_config = self.config.clone();

                debug!(
                    job_id = %job.job_id,
                    module = ?module_type_clone,
                    "Spawning sandboxed module execution task"
                );

                join_set.spawn(async move {
                    let module_start = std::time::Instant::now();

                    // Build sandbox policy
                    let mut policy = SandboxPolicy::default()
                        .with_timeout(sandbox_timeout)
                        .with_memory_limit(sandbox_mem_bytes);

                    // Add read-only access to source URI (if it's a file path)
                    if std::path::Path::new(&config.source_uri).exists() {
                        policy = policy.with_readonly_path(&config.source_uri);
                    }

                    // Configure network access if enabled
                    if sandbox_config.allow_network {
                        // Allow common ports for now if network is enabled
                        policy.allowed_ports = vec![80, 443, 8080];
                    }

                    // Execute within sandbox
                    let result = executor
                        .execute_module(&*module_arc, &config, &policy)
                        .await
                        .map_err(|e| match e {
                            // Convert sandboxed error to generic execution error string
                            vulnera_sandbox::SandboxedExecutionError::Timeout(_) => {
                                ModuleExecutionError::ExecutionFailed(
                                    "Module execution timed out".to_string(),
                                )
                            }
                            vulnera_sandbox::SandboxedExecutionError::ModuleFailed(e) => e,
                            vulnera_sandbox::SandboxedExecutionError::Sandbox(e) => {
                                ModuleExecutionError::ExecutionFailed(format!(
                                    "Sandbox error: {}",
                                    e
                                ))
                            }
                        });

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
        let mut modules_completed = 0;
        let mut modules_failed = 0;

        let mut sast_findings = Vec::new();
        let mut secret_findings = Vec::new();
        let mut dependency_findings_raw = Vec::new();
        let mut api_findings = Vec::new();

        for result in &module_results {
            if result.error.is_none() {
                modules_completed += 1;
                match result.module_type {
                    vulnera_core::domain::module::ModuleType::SAST => {
                        sast_findings.extend(result.findings.clone());
                    }
                    vulnera_core::domain::module::ModuleType::SecretDetection => {
                        secret_findings.extend(result.findings.clone());
                    }
                    vulnera_core::domain::module::ModuleType::DependencyAnalyzer => {
                        dependency_findings_raw.extend(result.findings.clone());
                    }
                    vulnera_core::domain::module::ModuleType::ApiSecurity => {
                        api_findings.extend(result.findings.clone());
                    }
                    _ => {
                        sast_findings.extend(result.findings.clone());
                    }
                }
            } else {
                modules_failed += 1;
            }
        }

        // Deduplicate each list
        let deduplicate = |findings: Vec<vulnera_core::domain::module::Finding>| -> Vec<vulnera_core::domain::module::Finding> {
            let mut seen = std::collections::HashSet::new();
            let mut dedup = Vec::new();
            for f in findings {
                if seen.insert(f.id.clone()) {
                    dedup.push(f);
                }
            }
            dedup
        };

        let sast_findings = deduplicate(sast_findings);
        let secret_findings = deduplicate(secret_findings);
        let dependency_findings_raw = deduplicate(dependency_findings_raw);
        let api_findings = deduplicate(api_findings);

        // Group dependency findings
        let grouped_dependencies = Self::group_dependency_findings(&dependency_findings_raw);

        // Calculate summary
        let mut summary = Summary {
            total_findings: sast_findings.len()
                + secret_findings.len()
                + dependency_findings_raw.len()
                + api_findings.len(),
            by_severity: SeverityBreakdown::default(),
            by_type: TypeBreakdown {
                sast: sast_findings.len(),
                secrets: secret_findings.len(),
                dependencies: grouped_dependencies.len(),
                api: api_findings.len(),
            },
            modules_completed,
            modules_failed,
        };

        // Calculate severity breakdown (across all findings)
        for finding in sast_findings
            .iter()
            .chain(secret_findings.iter())
            .chain(dependency_findings_raw.iter())
            .chain(api_findings.iter())
        {
            match finding.severity {
                FindingSeverity::Critical => summary.by_severity.critical += 1,
                FindingSeverity::High => summary.by_severity.high += 1,
                FindingSeverity::Medium => summary.by_severity.medium += 1,
                FindingSeverity::Low => summary.by_severity.low += 1,
                FindingSeverity::Info => summary.by_severity.info += 1,
            }
        }

        AggregatedReport {
            job_id: job.job_id,
            project_id: job.project_id.clone(),
            status: job.status.clone(),
            summary,
            findings_by_type: FindingsByType {
                sast: sast_findings,
                secrets: secret_findings,
                dependencies: grouped_dependencies,
                api: api_findings,
            },
            module_results,
            created_at: chrono::Utc::now(),
        }
    }

    fn group_dependency_findings(
        findings: &[vulnera_core::domain::module::Finding],
    ) -> std::collections::HashMap<String, GroupedDependencyFinding> {
        let mut grouped: std::collections::HashMap<String, GroupedDependencyFinding> =
            std::collections::HashMap::new();

        for finding in findings {
            let (ecosystem, package, version) =
                Self::parse_dependency_location(&finding.location.path);

            let entry =
                grouped
                    .entry(package.clone())
                    .or_insert_with(|| GroupedDependencyFinding {
                        package_name: package.clone(),
                        ecosystem: ecosystem.clone(),
                        current_version: version.clone(),
                        recommendations: DependencyRecommendations {
                            nearest_safe: None,
                            latest_safe: None,
                        },
                        severity: format!("{:?}", finding.severity),
                        cves: Vec::new(),
                        summary: String::new(),
                    });

            if Self::is_higher_severity(&finding.severity, &entry.severity) {
                entry.severity = format!("{:?}", finding.severity);
            }

            entry.cves.push(CveInfo {
                id: finding
                    .rule_id
                    .clone()
                    .unwrap_or_else(|| finding.id.clone()),
                severity: format!("{:?}", finding.severity),
                description: finding.description.clone(),
            });

            if let Some(rec) = &finding.recommendation {
                // Try to parse as JSON
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(rec) {
                    if let Some(nearest) = json.get("nearest_safe").and_then(|v| v.as_str()) {
                        entry.recommendations.nearest_safe = Some(nearest.to_string());
                    }
                    if let Some(latest) = json.get("latest_safe").and_then(|v| v.as_str()) {
                        entry.recommendations.latest_safe = Some(latest.to_string());
                    }
                } else {
                    // Fallback for legacy or non-JSON recommendations
                    if entry.recommendations.nearest_safe.is_none() {
                        entry.recommendations.nearest_safe = Some(rec.clone());
                    }
                }
            }
        }

        for entry in grouped.values_mut() {
            entry.summary = format!("{} vulnerabilities found", entry.cves.len());
        }

        grouped
    }

    fn parse_dependency_location(path: &str) -> (String, String, String) {
        if let Some((eco_rest, _)) = path.split_once(':') {
            let ecosystem = eco_rest.to_string();
            let rest = path
                .strip_prefix(&format!("{}:", ecosystem))
                .unwrap_or(path);
            if let Some((pkg, ver)) = rest.split_once('@') {
                return (ecosystem, pkg.to_string(), ver.to_string());
            }
        }
        (
            "unknown".to_string(),
            path.to_string(),
            "unknown".to_string(),
        )
    }

    fn is_higher_severity(new_severity: &FindingSeverity, current_severity_str: &str) -> bool {
        let current = match current_severity_str {
            "Critical" => FindingSeverity::Critical,
            "High" => FindingSeverity::High,
            "Medium" => FindingSeverity::Medium,
            "Low" => FindingSeverity::Low,
            _ => FindingSeverity::Info,
        };
        new_severity < &current
    }
}

impl Default for AggregateResultsUseCase {
    fn default() -> Self {
        Self::new()
    }
}
