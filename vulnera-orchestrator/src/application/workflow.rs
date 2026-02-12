//! Job Workflow — centralised state-machine controller for analysis jobs.
//!
//! Every status transition goes through [`JobWorkflow`] which validates the
//! transition against the state machine defined on [`JobStatus`], persists a
//! snapshot, and records an audit-trail entry on the [`AnalysisJob`].
//!
//! ```text
//! Controller          JobWorkflow          JobStore       JobQueue
//!     │                   │                   │              │
//!     ├─ create_job() ───►│                   │              │
//!     │◄── Job(Pending) ──┤                   │              │
//!     │                   │                   │              │
//!     ├─ enqueue_job() ──►│── save_snapshot ─►│              │
//!     │                   │── enqueue ───────►│─────────────►│
//!     │◄── Ok ────────────┤                   │              │
//!     │                   │                   │              │
//!     │  (worker picks)   │                   │              │
//!     ├─ start_job() ────►│── save_snapshot ─►│              │
//!     │◄── Ok ────────────┤                   │              │
//!     │                   │                   │              │
//!     ├─ complete_job() ─►│── save_snapshot ─►│              │
//!     │◄── Ok ────────────┤                   │              │
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{info, warn};
use uuid::Uuid;

use vulnera_core::domain::module::ModuleResult;

use crate::domain::entities::{
    AggregatedReport, AnalysisJob, FindingsByType, JobInvocationContext, Project, Summary,
};
use crate::domain::value_objects::JobStatus;
use crate::infrastructure::job_store::{JobSnapshot, JobStore, JobStoreError};

/// Errors from the workflow layer.
#[derive(Debug, thiserror::Error)]
pub enum WorkflowError {
    #[error("Invalid state transition: {0}")]
    InvalidTransition(#[from] crate::domain::value_objects::JobTransitionError),

    #[error("Persistence error: {0}")]
    Store(#[from] JobStoreError),
}

/// Centralised job lifecycle controller.
///
/// All state transitions are validated, persisted, and logged through this
/// service.  Use-cases and workers call `JobWorkflow` instead of mutating
/// [`AnalysisJob`] directly.
#[derive(Clone)]
pub struct JobWorkflow {
    job_store: Arc<dyn JobStore>,
}

impl JobWorkflow {
    pub fn new(job_store: Arc<dyn JobStore>) -> Self {
        Self { job_store }
    }

    // ── Transition helpers ───────────────────────────────────────────

    /// Transition a job to [`JobStatus::Queued`] and persist an initial snapshot.
    pub async fn enqueue_job(
        &self,
        job: &mut AnalysisJob,
        project: &Project,
        callback_url: Option<String>,
        invocation_context: Option<JobInvocationContext>,
    ) -> Result<(), WorkflowError> {
        job.transition(
            JobStatus::Queued,
            Some("Enqueued for background processing".into()),
        )?;

        self.persist(
            job,
            project,
            &[],
            None,
            None,
            callback_url,
            invocation_context,
        )
        .await?;

        info!(job_id = %job.job_id, "Job transitioned to Queued");
        Ok(())
    }

    /// Transition a job to [`JobStatus::Running`] and persist.
    pub async fn start_job(
        &self,
        job: &mut AnalysisJob,
        project: &Project,
        callback_url: Option<String>,
        invocation_context: Option<JobInvocationContext>,
    ) -> Result<(), WorkflowError> {
        job.transition(JobStatus::Running, Some("Worker started execution".into()))?;

        self.persist(
            job,
            project,
            &[],
            None,
            None,
            callback_url,
            invocation_context,
        )
        .await?;

        info!(job_id = %job.job_id, "Job transitioned to Running");
        Ok(())
    }

    /// Transition a job to [`JobStatus::Completed`] with full results and persist.
    pub async fn complete_job(
        &self,
        job: &mut AnalysisJob,
        project: &Project,
        module_results: &[ModuleResult],
        report: &AggregatedReport,
        callback_url: Option<String>,
        invocation_context: Option<JobInvocationContext>,
    ) -> Result<(), WorkflowError> {
        job.transition(
            JobStatus::Completed,
            Some(format!(
                "Completed with {} findings",
                report.summary.total_findings
            )),
        )?;

        self.persist(
            job,
            project,
            module_results,
            Some(report.summary.clone()),
            Some(report.findings_by_type.clone()),
            callback_url,
            invocation_context,
        )
        .await?;

        info!(job_id = %job.job_id, "Job transitioned to Completed");
        Ok(())
    }

    /// Transition a job to [`JobStatus::Failed`] with an error message and persist.
    pub async fn fail_job(
        &self,
        job: &mut AnalysisJob,
        project: &Project,
        error: &str,
        callback_url: Option<String>,
        invocation_context: Option<JobInvocationContext>,
    ) -> Result<(), WorkflowError> {
        job.error = Some(error.to_string());
        job.transition(
            JobStatus::Failed,
            Some(format!("Execution failed: {}", error)),
        )?;

        self.persist(
            job,
            project,
            &[],
            None,
            None,
            callback_url,
            invocation_context,
        )
        .await?;

        warn!(job_id = %job.job_id, error, "Job transitioned to Failed");
        Ok(())
    }

    /// Transition a job to [`JobStatus::Cancelled`] and persist.
    pub async fn cancel_job(
        &self,
        job: &mut AnalysisJob,
        project: &Project,
        reason: &str,
    ) -> Result<(), WorkflowError> {
        job.transition(JobStatus::Cancelled, Some(format!("Cancelled: {}", reason)))?;

        self.persist(job, project, &[], None, None, None, None)
            .await?;

        info!(job_id = %job.job_id, reason, "Job transitioned to Cancelled");
        Ok(())
    }

    /// Retrieve a job snapshot by ID (delegates to store).
    pub async fn get_job(&self, job_id: Uuid) -> Result<Option<JobSnapshot>, JobStoreError> {
        self.job_store.get_snapshot(job_id).await
    }

    // ── Internal ─────────────────────────────────────────────────────

    async fn persist(
        &self,
        job: &AnalysisJob,
        project: &Project,
        module_results: &[ModuleResult],
        summary: Option<Summary>,
        findings_by_type: Option<FindingsByType>,
        callback_url: Option<String>,
        invocation_context: Option<JobInvocationContext>,
    ) -> Result<(), JobStoreError> {
        self.job_store
            .save_snapshot(JobSnapshot {
                job_id: job.job_id,
                project_id: job.project_id.clone(),
                status: job.status.clone(),
                module_results: module_results.to_vec(),
                project_metadata: project.metadata.clone(),
                created_at: job.created_at.to_rfc3339(),
                started_at: job.started_at.map(|t| t.to_rfc3339()),
                completed_at: job.completed_at.map(|t| t.to_rfc3339()),
                error: job.error.clone(),
                module_configs: HashMap::new(),
                callback_url,
                webhook_secret: None,
                invocation_context,
                summary,
                findings_by_type,
                transitions: job.transitions.clone(),
            })
            .await
    }
}
