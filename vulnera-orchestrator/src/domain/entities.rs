//! Orchestrator domain entities

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use vulnera_core::domain::auth::value_objects::{ApiKeyId, Email, UserId};
use vulnera_core::domain::module::{Finding, ModuleResult};

use super::value_objects::{AnalysisDepth, JobStatus, SourceType};

/// Represents a project to analyze
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub source_type: SourceType,
    pub source_uri: String,
    pub metadata: ProjectMetadata,
}

/// How the job request was authenticated
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum JobAuthStrategy {
    Jwt,
    ApiKey,
}

/// Optional metadata describing who triggered the job
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JobInvocationContext {
    pub user_id: Option<UserId>,
    pub email: Option<Email>,
    pub auth_strategy: Option<JobAuthStrategy>,
    pub api_key_id: Option<ApiKeyId>,
}

/// Project metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectMetadata {
    /// Detected languages in the project
    pub languages: Vec<String>,
    /// Detected frameworks (e.g., "django", "react", "spring")
    pub frameworks: Vec<String>,
    /// Detected dependency files
    pub dependency_files: Vec<String>,
    /// All detected configuration files of interest
    pub detected_config_files: Vec<String>,
    /// Project root path (for directory-based sources)
    pub root_path: Option<String>,
    /// Git revision (HEAD commit) when the source comes from a repository clone
    pub git_revision: Option<String>,
}

/// Analysis job tracking overall analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisJob {
    pub job_id: Uuid,
    pub project_id: String,
    pub status: JobStatus,
    pub modules_to_run: Vec<vulnera_core::domain::module::ModuleType>,
    pub analysis_depth: AnalysisDepth,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

impl AnalysisJob {
    pub fn new(
        project_id: String,
        modules_to_run: Vec<vulnera_core::domain::module::ModuleType>,
        analysis_depth: AnalysisDepth,
    ) -> Self {
        Self {
            job_id: Uuid::new_v4(),
            project_id,
            status: JobStatus::Pending,
            modules_to_run,
            analysis_depth,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            error: None,
        }
    }
}

/// Aggregated report from all modules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedReport {
    pub job_id: Uuid,
    pub project_id: String,
    pub status: JobStatus,
    pub summary: Summary,
    pub findings_by_type: FindingsByType,
    pub module_results: Vec<ModuleResult>,
    pub created_at: DateTime<Utc>,
}

/// Report summary statistics
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Default)]
pub struct ReportSummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub modules_completed: usize,
    pub modules_failed: usize,
}

/// Grouped dependency finding
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GroupedDependencyFinding {
    pub package_name: String,
    pub ecosystem: String,
    pub current_version: String,
    pub recommendations: DependencyRecommendations,
    pub severity: String,
    pub cves: Vec<CveInfo>,
    pub summary: String,
}

/// Dependency recommendations
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DependencyRecommendations {
    pub nearest_safe: Option<String>,
    pub latest_safe: Option<String>,
}

/// CVE information
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CveInfo {
    pub id: String,
    pub severity: String,
    pub description: String,
}

/// Findings breakdown by type
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TypeBreakdown {
    pub sast: usize,
    pub secrets: usize,
    pub dependencies: usize,
    pub api: usize,
}

/// Findings grouped by type
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FindingsByType {
    pub sast: Vec<Finding>,
    pub secrets: Vec<Finding>,
    pub dependencies: std::collections::HashMap<String, GroupedDependencyFinding>,
    pub api: Vec<Finding>,
}

/// Severity breakdown
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Default)]
pub struct SeverityBreakdown {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

/// Enhanced summary
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Summary {
    pub total_findings: usize,
    pub by_severity: SeverityBreakdown,
    pub by_type: TypeBreakdown,
    pub modules_completed: usize,
    pub modules_failed: usize,
}
