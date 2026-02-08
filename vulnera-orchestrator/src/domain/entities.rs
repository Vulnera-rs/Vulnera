//! Orchestrator domain entities

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use vulnera_core::domain::auth::value_objects::{ApiKeyId, Email, UserId};
use vulnera_core::domain::module::{Finding, ModuleResult};
use vulnera_core::domain::organization::value_objects::OrganizationId;
pub use vulnera_core::domain::project::{Project, ProjectMetadata};

use super::value_objects::{AnalysisDepth, JobStatus, JobTransition, JobTransitionError};

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
    /// Organization context for the job (if user is part of an organization)
    pub organization_id: Option<OrganizationId>,
    /// Whether this job was triggered via master key (skip analytics)
    #[serde(default)]
    pub is_master_key: bool,
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
    /// Ordered history of state transitions (audit trail).
    #[serde(default)]
    pub transitions: Vec<JobTransition>,
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
            transitions: Vec::new(),
        }
    }

    /// Attempt a validated state transition.
    ///
    /// Returns `Ok(())` if the transition is valid, recording the change in
    /// the audit trail. Returns `Err` if the transition violates the state machine.
    pub fn transition(
        &mut self,
        to: JobStatus,
        reason: Option<String>,
    ) -> Result<(), JobTransitionError> {
        if !self.status.can_transition_to(&to) {
            return Err(JobTransitionError {
                from: self.status.clone(),
                to,
            });
        }

        let now = Utc::now();

        self.transitions.push(JobTransition {
            from: self.status.clone(),
            to: to.clone(),
            timestamp: now,
            reason,
        });

        // Update lifecycle timestamps based on target state
        match &to {
            JobStatus::Running => {
                self.started_at = Some(now);
            }
            JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled => {
                self.completed_at = Some(now);
            }
            _ => {}
        }

        self.status = to;
        Ok(())
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
