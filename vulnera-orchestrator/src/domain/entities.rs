//! Orchestrator domain entities

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

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

/// Project metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectMetadata {
    /// Detected languages in the project
    pub languages: Vec<String>,
    /// Detected dependency files
    pub dependency_files: Vec<String>,
    /// Project root path (for directory-based sources)
    pub root_path: Option<String>,
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
    pub summary: ReportSummary,
    pub findings: Vec<Finding>,
    pub module_results: Vec<ModuleResult>,
    pub created_at: DateTime<Utc>,
}

/// Report summary statistics
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[derive(Default)]
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

