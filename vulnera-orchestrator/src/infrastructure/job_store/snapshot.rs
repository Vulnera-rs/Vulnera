use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use vulnera_core::domain::module::ModuleResult;

use crate::domain::entities::{FindingsByType, JobInvocationContext, ProjectMetadata, Summary};
use crate::domain::value_objects::{JobStatus, JobTransition};

/// Snapshot of job execution state for replay and retrieval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSnapshot {
    pub job_id: Uuid,
    pub project_id: String,
    pub status: JobStatus,
    pub module_results: Vec<ModuleResult>,
    pub project_metadata: ProjectMetadata,
    pub created_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub error: Option<String>,
    pub module_configs: HashMap<String, serde_json::Value>,
    pub callback_url: Option<String>,
    /// Secret for webhook signature verification (HMAC-SHA256).
    /// Not persisted to database, only used during job execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_secret: Option<String>,
    pub invocation_context: Option<JobInvocationContext>,
    pub summary: Option<Summary>,
    pub findings_by_type: Option<FindingsByType>,
    /// Ordered history of state transitions (audit trail).
    #[serde(default)]
    pub transitions: Vec<JobTransition>,
}
