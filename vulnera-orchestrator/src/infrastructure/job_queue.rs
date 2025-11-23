use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::{Semaphore, mpsc};
use tracing::{error, info, warn};

use crate::application::use_cases::{AggregateResultsUseCase, ExecuteAnalysisJobUseCase};
use crate::domain::entities::{AnalysisJob, JobInvocationContext, Project};
use crate::domain::value_objects::JobStatus;
use crate::infrastructure::git::GitService;
use crate::infrastructure::job_store::{JobSnapshot, JobStore, JobStoreError};

/// Message delivered to the background worker pool when a new analysis job is queued.
pub struct QueuedAnalysisJob {
    pub job: AnalysisJob,
    pub project: Project,
    pub callback_url: Option<String>,
    pub invocation_context: Option<JobInvocationContext>,
}

/// Handle that allows HTTP handlers to push jobs into the background worker queue.
#[derive(Clone)]
pub struct JobQueueHandle {
    sender: mpsc::Sender<QueuedAnalysisJob>,
}

impl JobQueueHandle {
    pub fn new(sender: mpsc::Sender<QueuedAnalysisJob>) -> Self {
        Self { sender }
    }

    pub async fn enqueue(&self, job: QueuedAnalysisJob) -> Result<(), JobQueueError> {
        self.sender
            .send(job)
            .await
            .map_err(|_| JobQueueError::QueueClosed)
    }
}

/// Errors that can occur when enqueuing a job.
#[derive(thiserror::Error, Debug)]
pub enum JobQueueError {
    #[error("Job queue is closed")]
    QueueClosed,
}

/// Shared dependencies required by the job workers.
#[derive(Clone)]
pub struct JobWorkerContext {
    pub execute_job_use_case: Arc<ExecuteAnalysisJobUseCase>,
    pub aggregate_results_use_case: Arc<AggregateResultsUseCase>,
    pub job_store: Arc<dyn JobStore>,
    pub git_service: Arc<GitService>,
}

/// Spawn a worker pool that consumes queued jobs and processes them in the background.
pub fn spawn_job_worker_pool(
    mut receiver: mpsc::Receiver<QueuedAnalysisJob>,
    context: JobWorkerContext,
    max_concurrent_jobs: usize,
) {
    let concurrency = max_concurrent_jobs.max(1);
    let semaphore = Arc::new(Semaphore::new(concurrency));

    tokio::spawn(async move {
        while let Some(job) = receiver.recv().await {
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(err) => {
                    error!(error = %err, "Failed to acquire concurrency permit for job processing");
                    break;
                }
            };

            let ctx = context.clone();
            tokio::spawn(async move {
                if let Err(err) = process_job(ctx, job).await {
                    error!(error = %err, "Background job processing failed");
                }
                drop(permit);
            });
        }

        warn!("Job queue receiver closed; worker loop exiting");
    });
}

async fn process_job(
    ctx: JobWorkerContext,
    mut payload: QueuedAnalysisJob,
) -> Result<(), JobProcessingError> {
    let job_id = payload.job.job_id;

    // Execute modules via orchestrator use case
    match ctx
        .execute_job_use_case
        .execute(&mut payload.job, &payload.project)
        .await
    {
        Ok(module_results) => {
            let report = ctx
                .aggregate_results_use_case
                .execute(&payload.job, module_results.clone());

            persist_snapshot(
                &ctx,
                JobSnapshot {
                    job_id,
                    project_id: payload.job.project_id.clone(),
                    status: payload.job.status.clone(),
                    module_results,
                    project_metadata: payload.project.metadata.clone(),
                    created_at: payload.job.created_at.to_rfc3339(),
                    started_at: payload.job.started_at.map(|t| t.to_rfc3339()),
                    completed_at: payload.job.completed_at.map(|t| t.to_rfc3339()),
                    error: payload.job.error.clone(),
                    module_configs: HashMap::new(),
                    callback_url: payload.callback_url.clone(),
                    invocation_context: payload.invocation_context.clone(),
                    summary: Some(report.summary.clone()),
                    findings: Some(report.findings.clone()),
                },
            )
            .await?;

            if let Some(callback_url) = payload.callback_url.as_deref() {
                info!(
                    job_id = %job_id,
                    callback_url,
                    "Job completed; callback delivery pending transport implementation"
                );
            }

            info!(job_id = %job_id, "Analysis job finished successfully");
        }
        Err(err) => {
            payload.job.status = JobStatus::Failed;
            payload.job.error = Some(err.to_string());
            payload.job.completed_at = Some(Utc::now());

            persist_snapshot(
                &ctx,
                JobSnapshot {
                    job_id,
                    project_id: payload.job.project_id.clone(),
                    status: payload.job.status.clone(),
                    module_results: Vec::new(),
                    project_metadata: payload.project.metadata.clone(),
                    created_at: payload.job.created_at.to_rfc3339(),
                    started_at: payload.job.started_at.map(|t| t.to_rfc3339()),
                    completed_at: payload.job.completed_at.map(|t| t.to_rfc3339()),
                    error: payload.job.error.clone(),
                    module_configs: HashMap::new(),
                    callback_url: payload.callback_url.clone(),
                    invocation_context: payload.invocation_context.clone(),
                    summary: None,
                    findings: None,
                },
            )
            .await?;

            warn!(job_id = %job_id, error = %err, "Analysis job failed");
        }
    }

    if !ctx.git_service.cleanup_project(&payload.project.id).await {
        warn!(project_id = %payload.project.id, "Git project cleanup reported no checkout");
    }

    Ok(())
}

async fn persist_snapshot(
    ctx: &JobWorkerContext,
    snapshot: JobSnapshot,
) -> Result<(), JobProcessingError> {
    ctx.job_store
        .save_snapshot(snapshot)
        .await
        .map_err(JobProcessingError::Snapshot)
}

/// Errors surfaced while executing background jobs.
#[derive(thiserror::Error, Debug)]
pub enum JobProcessingError {
    #[error("Failed to persist job snapshot: {0}")]
    Snapshot(JobStoreError),
}
