use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use vulnera_core::application::analytics::{AnalyticsRecorder, FindingsSummary};
use vulnera_core::domain::organization::value_objects::StatsSubject;
use vulnera_core::infrastructure::cache::CacheServiceImpl;

use crate::application::use_cases::{AggregateResultsUseCase, ExecuteAnalysisJobUseCase};
use crate::application::workflow::{JobWorkflow, WorkflowError};
use crate::domain::entities::{AnalysisJob, JobInvocationContext, Project};
use crate::infrastructure::git::GitService;
use crate::infrastructure::job_store::JobStore;

const JOB_QUEUE_KEY: &str = "vulnera:orchestrator:job_queue";

/// Message delivered to the background worker pool when a new analysis job is queued.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct QueuedAnalysisJob {
    pub job: AnalysisJob,
    pub project: Project,
    pub callback_url: Option<String>,
    /// Secret for webhook signature verification (HMAC-SHA256).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_secret: Option<String>,
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
            webhook_secret: Some("test_secret".to_string()),
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
    pub workflow: Arc<JobWorkflow>,
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
    let analytics_subject = payload.invocation_context.as_ref().and_then(|inv| {
        if inv.is_master_key {
            return None;
        }
        if let Some(org_id) = inv.organization_id {
            Some(StatsSubject::Organization(org_id))
        } else {
            inv.user_id.map(StatsSubject::User)
        }
    });

    let user_id = payload
        .invocation_context
        .as_ref()
        .and_then(|inv| inv.user_id);

    // Record scan started event (if we have analytics context)
    if let Some(ref subject) = analytics_subject
        && let Err(e) = ctx
            .analytics_recorder
            .on_scan_started(subject.clone(), user_id, job_id)
            .await
    {
        warn!(job_id = %job_id, error = %e, "Failed to record scan started analytics");
    }

    // ── Workflow: Pending → Running ──────────────────────────────────
    if let Err(e) = ctx
        .workflow
        .start_job(
            &mut payload.job,
            &payload.project,
            payload.callback_url.clone(),
            payload.invocation_context.clone(),
        )
        .await
    {
        error!(job_id = %job_id, error = %e, "Failed to transition job to Running");
        return Err(JobProcessingError::Workflow(e));
    }

    // ── Execute modules (pure computation, no status mutation) ───────
    match ctx
        .execute_job_use_case
        .execute(&payload.job, &payload.project)
        .await
    {
        Ok(module_results) => {
            let report = ctx
                .aggregate_results_use_case
                .execute(&payload.job, module_results.clone());

            // ── Workflow: Running → Completed ────────────────────────
            if let Err(e) = ctx
                .workflow
                .complete_job(
                    &mut payload.job,
                    &payload.project,
                    &module_results,
                    &report,
                    payload.callback_url.clone(),
                    payload.invocation_context.clone(),
                )
                .await
            {
                error!(job_id = %job_id, error = %e, "Failed to transition job to Completed");
                return Err(JobProcessingError::Workflow(e));
            }

            // Record scan completed with findings breakdown
            if let Some(ref subject) = analytics_subject {
                let severity = &report.summary.by_severity;
                if let Err(e) = ctx
                    .analytics_recorder
                    .on_scan_completed(
                        subject.clone(),
                        user_id,
                        job_id,
                        FindingsSummary {
                            critical: severity.critical as u32,
                            high: severity.high as u32,
                            medium: severity.medium as u32,
                            low: severity.low as u32,
                            info: severity.info as u32,
                        },
                    )
                    .await
                {
                    warn!(job_id = %job_id, error = %e, "Failed to record scan completed analytics");
                }
            }

            if let Some(callback_url) = payload.callback_url.as_deref() {
                let webhook_payload = WebhookPayload {
                    job_id,
                    status: payload.job.status.to_string(),
                    summary: Some(report.summary.clone()),
                    findings_by_type: Some(report.findings_by_type.clone()),
                    error: None,
                    completed_at: payload.job.completed_at.map(|t| t.to_rfc3339()),
                };

                deliver_webhook(
                    callback_url,
                    payload.webhook_secret.as_deref(),
                    &webhook_payload,
                )
                .await;
            }

            info!(job_id = %job_id, "Analysis job finished successfully");
        }
        Err(err) => {
            // ── Workflow: Running → Failed ───────────────────────────
            if let Err(e) = ctx
                .workflow
                .fail_job(
                    &mut payload.job,
                    &payload.project,
                    &err.to_string(),
                    payload.callback_url.clone(),
                    payload.invocation_context.clone(),
                )
                .await
            {
                error!(job_id = %job_id, error = %e, "Failed to transition job to Failed");
                return Err(JobProcessingError::Workflow(e));
            }

            // Record scan failed (with zero findings)
            if let Some(ref subject) = analytics_subject
                && let Err(e) = ctx
                    .analytics_recorder
                    .on_scan_completed(subject.clone(), user_id, job_id, FindingsSummary::default())
                    .await
            {
                warn!(job_id = %job_id, error = %e, "Failed to record scan failed analytics");
            }

            // Deliver webhook for failed jobs too
            if let Some(callback_url) = payload.callback_url.as_deref() {
                let webhook_payload = WebhookPayload {
                    job_id,
                    status: payload.job.status.to_string(),
                    summary: None,
                    findings_by_type: None,
                    error: payload.job.error.clone(),
                    completed_at: payload.job.completed_at.map(|t| t.to_rfc3339()),
                };

                deliver_webhook(
                    callback_url,
                    payload.webhook_secret.as_deref(),
                    &webhook_payload,
                )
                .await;
            }

            warn!(job_id = %job_id, error = %err, "Analysis job failed");
        }
    }

    if !ctx.git_service.cleanup_project(&payload.project.id).await {
        warn!(project_id = %payload.project.id, "Git project cleanup reported no checkout");
    }

    // Clean up S3 temporary directories
    cleanup_s3_project(&payload.project).await;

    Ok(())
}

/// Clean up S3 temporary directories after job completion
///
/// Removes the temporary directory created during S3 bucket download.
/// Directory pattern: /tmp/vulnera-s3-{uuid}
async fn cleanup_s3_project(project: &Project) {
    use crate::domain::value_objects::SourceType;

    // Only clean up if the project source is S3Bucket
    if project.source_type != SourceType::S3Bucket {
        return;
    }

    // Extract the temp directory UUID from the source_uri (s3://bucket-name/prefix or path)
    // The root_path in metadata should point to /tmp/vulnera-s3-{uuid}
    if let Some(root_path) = &project.metadata.root_path {
        match tokio::fs::remove_dir_all(root_path).await {
            Ok(_) => {
                info!(project_id = %project.id, root_path = %root_path, "Cleaned up S3 temporary directory");
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!(project_id = %project.id, root_path = %root_path, "S3 temporary directory already removed");
            }
            Err(e) => {
                warn!(project_id = %project.id, root_path = %root_path, error = %e, "Failed to clean up S3 temporary directory");
            }
        }
    }
}

/// Errors surfaced while executing background jobs.
#[derive(thiserror::Error, Debug)]
pub enum JobProcessingError {
    #[error("Workflow error: {0}")]
    Workflow(#[from] WorkflowError),
}

// =============================================================================
// Webhook Delivery
// =============================================================================

type HmacSha256 = Hmac<Sha256>;

/// Payload sent to webhook callback URLs
#[derive(serde::Serialize)]
pub struct WebhookPayload {
    pub job_id: Uuid,
    pub status: String,
    pub summary: Option<crate::domain::entities::Summary>,
    pub findings_by_type: Option<crate::domain::entities::FindingsByType>,
    pub error: Option<String>,
    pub completed_at: Option<String>,
}

/// Deliver webhook to callback URL with optional HMAC-SHA256 signature.
///
/// # Headers
/// - `Content-Type: application/json`
/// - `X-Vulnera-Event: job.completed`
/// - `X-Vulnera-Timestamp: <unix_timestamp>` (for replay protection)
/// - `X-Vulnera-Signature: sha256=<hex_signature>` (if webhook_secret provided)
///
/// The signature is computed as: HMAC-SHA256(timestamp + "." + payload_json, secret)
async fn deliver_webhook(
    callback_url: &str,
    webhook_secret: Option<&str>,
    payload: &WebhookPayload,
) {
    let job_id = payload.job_id;
    let timestamp = Utc::now().timestamp();

    // Serialize payload
    let payload_json = match serde_json::to_string(payload) {
        Ok(json) => json,
        Err(e) => {
            error!(job_id = %job_id, error = %e, "Failed to serialize webhook payload");
            return;
        }
    };

    // Build HTTP client with timeout
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!(job_id = %job_id, error = %e, "Failed to build HTTP client for webhook");
            return;
        }
    };

    // Build request
    let mut request = client
        .post(callback_url)
        .header("Content-Type", "application/json")
        .header("X-Vulnera-Event", "job.completed")
        .header("X-Vulnera-Timestamp", timestamp.to_string());

    // Add HMAC signature if secret is provided
    if let Some(secret) = webhook_secret {
        let signature_payload = format!("{}.{}", timestamp, payload_json);
        match HmacSha256::new_from_slice(secret.as_bytes()) {
            Ok(mut mac) => {
                mac.update(signature_payload.as_bytes());
                let signature = hex::encode(mac.finalize().into_bytes());
                request = request.header("X-Vulnera-Signature", format!("sha256={}", signature));
            }
            Err(e) => {
                warn!(job_id = %job_id, error = %e, "Failed to create HMAC for webhook signature");
            }
        }
    }

    // Send webhook with retry logic
    let max_retries = 3;
    let mut last_error: Option<String> = None;

    for attempt in 1..=max_retries {
        let Some(cloned_request) = request.try_clone() else {
            last_error = Some("Failed to clone webhook request for retry".to_string());
            error!(job_id = %job_id, callback_url, "Webhook request could not be cloned");
            break;
        };

        match cloned_request.body(payload_json.clone()).send().await {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    info!(
                        job_id = %job_id,
                        callback_url,
                        status = %status,
                        "Webhook delivered successfully"
                    );
                    return;
                } else {
                    let body = response.text().await.unwrap_or_default();
                    last_error = Some(format!("HTTP {}: {}", status, body));
                    warn!(
                        job_id = %job_id,
                        callback_url,
                        status = %status,
                        attempt,
                        "Webhook delivery failed with non-success status"
                    );
                }
            }
            Err(e) => {
                last_error = Some(e.to_string());
                warn!(
                    job_id = %job_id,
                    callback_url,
                    error = %e,
                    attempt,
                    "Webhook delivery request failed"
                );
            }
        }

        // Exponential backoff before retry
        if attempt < max_retries {
            tokio::time::sleep(Duration::from_millis(500 * (1 << attempt))).await;
        }
    }

    error!(
        job_id = %job_id,
        callback_url,
        error = ?last_error,
        "Webhook delivery failed after {} attempts",
        max_retries
    );
}
