use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use vulnera_core::application::analytics::AnalyticsRecorder;
use vulnera_core::domain::organization::value_objects::StatsSubject;
use vulnera_core::infrastructure::cache::CacheServiceImpl;

use crate::application::use_cases::{AggregateResultsUseCase, ExecuteAnalysisJobUseCase};
use crate::domain::entities::{AnalysisJob, JobInvocationContext, Project};
use crate::domain::value_objects::JobStatus;
use crate::infrastructure::git::GitService;
use crate::infrastructure::job_store::{JobSnapshot, JobStore, JobStoreError};

const JOB_QUEUE_KEY: &str = "vulnera:orchestrator:job_queue";

/// Message delivered to the background worker pool when a new analysis job is queued.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct QueuedAnalysisJob {
    pub job: AnalysisJob,
    pub project: Project,
    pub callback_url: Option<String>,
    pub invocation_context: Option<JobInvocationContext>,
}

/// Handle that allows HTTP handlers to push jobs into the background worker queue.
#[derive(Clone)]
pub struct JobQueueHandle {
    cache_service: Arc<CacheServiceImpl>,
}

impl JobQueueHandle {
    pub fn new(cache_service: Arc<CacheServiceImpl>) -> Self {
        Self { cache_service }
    }

    pub async fn enqueue(&self, job: QueuedAnalysisJob) -> Result<(), JobQueueError> {
        self.cache_service
            .lpush(JOB_QUEUE_KEY, &job)
            .await
            .map_err(|e| {
                error!("Failed to enqueue job: {}", e);
                JobQueueError::EnqueueFailed(e.to_string())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entities::{AnalysisJob, Project, ProjectMetadata};
    use crate::domain::value_objects::{AnalysisDepth, SourceType};
    use vulnera_core::domain::module::ModuleType;

    #[test]
    fn test_queued_job_serialization() {
        let project = Project {
            id: "project_123".to_string(),
            source_type: SourceType::Directory,
            source_uri: "/tmp/test".to_string(),
            metadata: ProjectMetadata::default(),
        };

        let job = AnalysisJob::new(
            project.id.clone(),
            vec![ModuleType::SAST, ModuleType::DependencyAnalyzer],
            AnalysisDepth::Full,
        );

        let queued_job = QueuedAnalysisJob {
            job: job.clone(),
            project: project.clone(),
            callback_url: Some("http://example.com/callback".to_string()),
            invocation_context: None,
        };

        let serialized = serde_json::to_string(&queued_job).unwrap();
        let deserialized: QueuedAnalysisJob = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.job.job_id, job.job_id);
        assert_eq!(deserialized.project.id, project.id);
        assert_eq!(
            deserialized.callback_url,
            Some("http://example.com/callback".to_string())
        );
    }
}

/// Errors that can occur when enqueuing a job.
#[derive(thiserror::Error, Debug)]
pub enum JobQueueError {
    #[error("Failed to enqueue job: {0}")]
    EnqueueFailed(String),
}

/// Shared dependencies required by the job workers.
#[derive(Clone)]
pub struct JobWorkerContext {
    pub execute_job_use_case: Arc<ExecuteAnalysisJobUseCase>,
    pub aggregate_results_use_case: Arc<AggregateResultsUseCase>,
    pub job_store: Arc<dyn JobStore>,
    pub git_service: Arc<GitService>,
    pub cache_service: Arc<CacheServiceImpl>,
    pub analytics_recorder: Arc<dyn AnalyticsRecorder>,
}

/// Spawn a worker pool that consumes queued jobs and processes them in the background.
pub fn spawn_job_worker_pool(context: JobWorkerContext, max_concurrent_jobs: usize) {
    let concurrency = max_concurrent_jobs.max(1);
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let cache_service = context.cache_service.clone();

    tokio::spawn(async move {
        info!("Job worker pool started with concurrency: {}", concurrency);

        loop {
            // Wait for a permit before polling for a job
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(err) => {
                    error!(error = %err, "Failed to acquire concurrency permit for job processing");
                    break;
                }
            };

            // Poll for a job with a timeout (e.g., 5 seconds) to allow graceful shutdown checks if needed
            // Using a loop here to keep trying until we get a job or shut down
            let job_opt = match cache_service
                .brpop::<QueuedAnalysisJob>(JOB_QUEUE_KEY, 5.0)
                .await
            {
                Ok(job) => job,
                Err(e) => {
                    error!("Failed to poll job queue: {}", e);
                    // Sleep a bit before retrying to avoid tight loop on error
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    None
                }
            };

            if let Some(job) = job_opt {
                let ctx = context.clone();
                tokio::spawn(async move {
                    if let Err(err) = process_job(ctx, job).await {
                        error!(error = %err, "Background job processing failed");
                    }
                    drop(permit);
                });
            } else {
                // No job received within timeout, release permit and loop again
                drop(permit);
            }
        }

        warn!("Job worker pool exiting");
    });
}

async fn process_job(
    ctx: JobWorkerContext,
    mut payload: QueuedAnalysisJob,
) -> Result<(), JobProcessingError> {
    let job_id = payload.job.job_id;

    info!(job_id = %job_id, "Processing analysis job");

    // Determine analytics subject from invocation context
    let analytics_subject = payload
        .invocation_context
        .as_ref()
        .and_then(|ctx| {
            // Prefer organization_id if present, otherwise use user_id for personal stats
            if let Some(org_id) = ctx.organization_id {
                Some(StatsSubject::Organization(org_id))
            } else {
                ctx.user_id.map(StatsSubject::User)
            }
        });

    let user_id = payload
        .invocation_context
        .as_ref()
        .and_then(|ctx| ctx.user_id);

    // Record scan started event (if we have analytics context)
    if let Some(ref subject) = analytics_subject {
        if let Err(e) = ctx
            .analytics_recorder
            .on_scan_started(subject.clone(), user_id, job_id)
            .await
        {
            warn!(job_id = %job_id, error = %e, "Failed to record scan started analytics");
        }
    }

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
                    findings_by_type: Some(report.findings_by_type.clone()),
                },
            )
            .await?;

            // Record scan completed with findings breakdown
            if let Some(ref subject) = analytics_subject {
                let severity = &report.summary.by_severity;
                if let Err(e) = ctx
                    .analytics_recorder
                    .on_scan_completed(
                        subject.clone(),
                        user_id,
                        job_id,
                        severity.critical as u32,
                        severity.high as u32,
                        severity.medium as u32,
                        severity.low as u32,
                        severity.info as u32,
                    )
                    .await
                {
                    warn!(job_id = %job_id, error = %e, "Failed to record scan completed analytics");
                }
            }

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
                    findings_by_type: None,
                },
            )
            .await?;

            // Record scan failed (with zero findings)
            if let Some(ref subject) = analytics_subject {
                if let Err(e) = ctx
                    .analytics_recorder
                    .on_scan_completed(
                        subject.clone(),
                        user_id,
                        job_id,
                        0, 0, 0, 0, 0, // No findings on failure
                    )
                    .await
                {
                    warn!(job_id = %job_id, error = %e, "Failed to record scan failed analytics");
                }
            }

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
