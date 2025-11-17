use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use vulnera_core::domain::module::ModuleResult;

use crate::domain::entities::ProjectMetadata;
use crate::domain::value_objects::JobStatus;

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
}
