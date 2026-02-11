//! Integration tests for the `JobWorkflow` state-machine controller.
//!
//! Uses an in-memory `JobStore` so no Dragonfly instance is needed.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use uuid::Uuid;

use vulnera_core::domain::module::ModuleType;
use vulnera_orchestrator::application::workflow::{JobWorkflow, WorkflowError};
use vulnera_orchestrator::domain::entities::{
    AggregatedReport, AnalysisJob, FindingsByType, Project, ProjectMetadata, SeverityBreakdown,
    Summary, TypeBreakdown,
};
use vulnera_orchestrator::domain::value_objects::{AnalysisDepth, JobStatus, SourceType};
use vulnera_orchestrator::infrastructure::job_store::{JobSnapshot, JobStore, JobStoreError};

// ── In-memory job store (test double) ────────────────────────────────────────

#[derive(Default)]
struct InMemoryJobStore {
    snapshots: Mutex<HashMap<Uuid, JobSnapshot>>,
}

#[async_trait]
impl JobStore for InMemoryJobStore {
    async fn save_snapshot(&self, snapshot: JobSnapshot) -> Result<(), JobStoreError> {
        self.snapshots
            .lock()
            .await
            .insert(snapshot.job_id, snapshot);
        Ok(())
    }

    async fn get_snapshot(&self, job_id: Uuid) -> Result<Option<JobSnapshot>, JobStoreError> {
        Ok(self.snapshots.lock().await.get(&job_id).cloned())
    }

    async fn delete_snapshot(&self, job_id: Uuid) -> Result<(), JobStoreError> {
        self.snapshots.lock().await.remove(&job_id);
        Ok(())
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn test_project() -> Project {
    Project {
        id: "test-project".into(),
        source_type: SourceType::Directory,
        source_uri: "/tmp/test".into(),
        metadata: ProjectMetadata::default(),
    }
}

fn test_job() -> AnalysisJob {
    AnalysisJob::new(
        "test-project".into(),
        vec![ModuleType::SAST, ModuleType::DependencyAnalyzer],
        AnalysisDepth::Full,
    )
}

fn empty_report(job: &AnalysisJob) -> AggregatedReport {
    AggregatedReport {
        job_id: job.job_id,
        project_id: job.project_id.clone(),
        status: JobStatus::Completed,
        findings_by_type: FindingsByType {
            sast: Vec::new(),
            secrets: Vec::new(),
            dependencies: HashMap::new(),
            api: Vec::new(),
        },
        summary: Summary {
            total_findings: 0,
            by_severity: SeverityBreakdown::default(),
            by_type: TypeBreakdown {
                sast: 0,
                secrets: 0,
                dependencies: 0,
                api: 0,
            },
            modules_completed: 2,
            modules_failed: 0,
        },
        module_results: Vec::new(),
        created_at: chrono::Utc::now(),
    }
}

fn make_workflow() -> (Arc<InMemoryJobStore>, JobWorkflow) {
    let store = Arc::new(InMemoryJobStore::default());
    let workflow = JobWorkflow::new(store.clone() as Arc<dyn JobStore>);
    (store, workflow)
}

// ── State-machine transition tests ──────────────────────────────────────────

#[tokio::test]
async fn test_happy_path_lifecycle() {
    let (store, workflow) = make_workflow();
    let mut job = test_job();
    let project = test_project();
    let job_id = job.job_id;

    // Pending → Queued
    workflow
        .enqueue_job(&mut job, &project, None, None)
        .await
        .expect("enqueue should succeed");
    assert_eq!(job.status, JobStatus::Queued);
    assert_eq!(job.transitions.len(), 1);

    // Snapshot persisted with Queued status
    let snap = store
        .snapshots
        .lock()
        .await
        .get(&job_id)
        .cloned()
        .expect("snapshot must exist");
    assert_eq!(snap.status, JobStatus::Queued);

    // Queued → Running
    workflow
        .start_job(&mut job, &project, None, None)
        .await
        .expect("start should succeed");
    assert_eq!(job.status, JobStatus::Running);
    assert!(job.started_at.is_some());
    assert_eq!(job.transitions.len(), 2);

    // Running → Completed
    let report = empty_report(&job);
    workflow
        .complete_job(&mut job, &project, &[], &report, None, None)
        .await
        .expect("complete should succeed");
    assert_eq!(job.status, JobStatus::Completed);
    assert!(job.completed_at.is_some());
    assert_eq!(job.transitions.len(), 3);
}

#[tokio::test]
async fn test_failure_path() {
    let (_store, workflow) = make_workflow();
    let mut job = test_job();
    let project = test_project();

    // Pending → Queued → Running → Failed
    workflow
        .enqueue_job(&mut job, &project, None, None)
        .await
        .unwrap();
    workflow
        .start_job(&mut job, &project, None, None)
        .await
        .unwrap();
    workflow
        .fail_job(&mut job, &project, "module panicked", None, None)
        .await
        .expect("fail should succeed");

    assert_eq!(job.status, JobStatus::Failed);
    assert!(job.error.as_deref() == Some("module panicked"));
    assert!(job.completed_at.is_some());
    assert_eq!(job.transitions.len(), 3);
}

#[tokio::test]
async fn test_cancel_from_pending() {
    let (_store, workflow) = make_workflow();
    let mut job = test_job();
    let project = test_project();

    workflow
        .cancel_job(&mut job, &project, "user requested cancellation")
        .await
        .expect("cancel from Pending should succeed");

    assert_eq!(job.status, JobStatus::Cancelled);
    assert!(job.status.is_terminal());
    assert_eq!(job.transitions.len(), 1);
    assert_eq!(
        job.transitions[0].reason.as_deref(),
        Some("Cancelled: user requested cancellation")
    );
}

#[tokio::test]
async fn test_cancel_from_queued() {
    let (_store, workflow) = make_workflow();
    let mut job = test_job();
    let project = test_project();

    workflow
        .enqueue_job(&mut job, &project, None, None)
        .await
        .unwrap();
    workflow
        .cancel_job(&mut job, &project, "timeout")
        .await
        .expect("cancel from Queued should succeed");

    assert_eq!(job.status, JobStatus::Cancelled);
    assert_eq!(job.transitions.len(), 2);
}

// ── Invalid transition tests ────────────────────────────────────────────────

#[tokio::test]
async fn test_invalid_pending_to_running() {
    let (_store, workflow) = make_workflow();
    let mut job = test_job();
    let project = test_project();

    // Pending → Running should fail (must go through Queued)
    let err = workflow
        .start_job(&mut job, &project, None, None)
        .await
        .expect_err("Pending→Running should be invalid");

    assert!(matches!(err, WorkflowError::InvalidTransition(_)));
    assert_eq!(
        job.status,
        JobStatus::Pending,
        "status should not change on error"
    );
}

#[tokio::test]
async fn test_invalid_pending_to_completed() {
    let (_store, workflow) = make_workflow();
    let mut job = test_job();
    let project = test_project();
    let report = empty_report(&job);

    let err = workflow
        .complete_job(&mut job, &project, &[], &report, None, None)
        .await
        .expect_err("Pending→Completed should be invalid");

    assert!(matches!(err, WorkflowError::InvalidTransition(_)));
    assert_eq!(job.status, JobStatus::Pending);
}

#[tokio::test]
async fn test_invalid_completed_to_running() {
    let (_store, workflow) = make_workflow();
    let mut job = test_job();
    let project = test_project();

    // Drive to Completed
    workflow
        .enqueue_job(&mut job, &project, None, None)
        .await
        .unwrap();
    workflow
        .start_job(&mut job, &project, None, None)
        .await
        .unwrap();
    let report = empty_report(&job);
    workflow
        .complete_job(&mut job, &project, &[], &report, None, None)
        .await
        .unwrap();

    // Completed → Running should fail
    let err = workflow
        .start_job(&mut job, &project, None, None)
        .await
        .expect_err("Completed is terminal");

    assert!(matches!(err, WorkflowError::InvalidTransition(_)));
}

#[tokio::test]
async fn test_invalid_running_to_cancelled() {
    let (_store, workflow) = make_workflow();
    let mut job = test_job();
    let project = test_project();

    workflow
        .enqueue_job(&mut job, &project, None, None)
        .await
        .unwrap();
    workflow
        .start_job(&mut job, &project, None, None)
        .await
        .unwrap();

    // Running → Cancelled should fail per state machine
    let err = workflow
        .cancel_job(&mut job, &project, "nope")
        .await
        .expect_err("Running→Cancelled is not allowed");

    assert!(matches!(err, WorkflowError::InvalidTransition(_)));
    assert_eq!(job.status, JobStatus::Running);
}

// ── Snapshot persistence tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_get_job_returns_latest_snapshot() {
    let (_store, workflow) = make_workflow();
    let mut job = test_job();
    let project = test_project();
    let job_id = job.job_id;

    workflow
        .enqueue_job(&mut job, &project, None, None)
        .await
        .unwrap();
    workflow
        .start_job(&mut job, &project, None, None)
        .await
        .unwrap();

    let snap = workflow
        .get_job(job_id)
        .await
        .unwrap()
        .expect("snapshot should exist");
    assert_eq!(snap.status, JobStatus::Running);
    assert!(snap.started_at.is_some());

    // Transitions should be persisted
    assert_eq!(snap.transitions.len(), 2);
}

#[tokio::test]
async fn test_get_nonexistent_job() {
    let (_store, workflow) = make_workflow();
    let result = workflow.get_job(Uuid::new_v4()).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_callback_url_persisted() {
    let (_store, workflow) = make_workflow();
    let mut job = test_job();
    let project = test_project();
    let job_id = job.job_id;

    workflow
        .enqueue_job(
            &mut job,
            &project,
            Some("https://example.com/webhook".into()),
            None,
        )
        .await
        .unwrap();

    let snap = _store.snapshots.lock().await.get(&job_id).cloned().unwrap();
    assert_eq!(
        snap.callback_url.as_deref(),
        Some("https://example.com/webhook")
    );
}

// ── Domain entity transition tests ──────────────────────────────────────────

#[test]
fn test_job_status_valid_transitions() {
    assert!(JobStatus::Pending.can_transition_to(&JobStatus::Queued));
    assert!(JobStatus::Pending.can_transition_to(&JobStatus::Cancelled));
    assert!(JobStatus::Queued.can_transition_to(&JobStatus::Running));
    assert!(JobStatus::Queued.can_transition_to(&JobStatus::Cancelled));
    assert!(JobStatus::Running.can_transition_to(&JobStatus::Completed));
    assert!(JobStatus::Running.can_transition_to(&JobStatus::Failed));
}

#[test]
fn test_job_status_invalid_transitions() {
    assert!(!JobStatus::Pending.can_transition_to(&JobStatus::Running));
    assert!(!JobStatus::Pending.can_transition_to(&JobStatus::Completed));
    assert!(!JobStatus::Pending.can_transition_to(&JobStatus::Failed));
    assert!(!JobStatus::Running.can_transition_to(&JobStatus::Cancelled));
    assert!(!JobStatus::Running.can_transition_to(&JobStatus::Queued));
    assert!(!JobStatus::Completed.can_transition_to(&JobStatus::Running));
    assert!(!JobStatus::Failed.can_transition_to(&JobStatus::Running));
    assert!(!JobStatus::Cancelled.can_transition_to(&JobStatus::Queued));
}

#[test]
fn test_terminal_states() {
    assert!(JobStatus::Completed.is_terminal());
    assert!(JobStatus::Failed.is_terminal());
    assert!(JobStatus::Cancelled.is_terminal());
    assert!(!JobStatus::Pending.is_terminal());
    assert!(!JobStatus::Queued.is_terminal());
    assert!(!JobStatus::Running.is_terminal());
}

#[test]
fn test_job_status_display() {
    assert_eq!(JobStatus::Pending.to_string(), "Pending");
    assert_eq!(JobStatus::Queued.to_string(), "Queued");
    assert_eq!(JobStatus::Running.to_string(), "Running");
    assert_eq!(JobStatus::Completed.to_string(), "Completed");
    assert_eq!(JobStatus::Failed.to_string(), "Failed");
    assert_eq!(JobStatus::Cancelled.to_string(), "Cancelled");
}

#[test]
fn test_entity_transition_records_audit_trail() {
    let mut job = test_job();
    job.transition(JobStatus::Queued, Some("test enqueue".into()))
        .unwrap();

    assert_eq!(job.transitions.len(), 1);
    let t = &job.transitions[0];
    assert_eq!(t.from, JobStatus::Pending);
    assert_eq!(t.to, JobStatus::Queued);
    assert_eq!(t.reason.as_deref(), Some("test enqueue"));
}

#[test]
fn test_entity_transition_rejects_invalid() {
    let mut job = test_job(); // Pending
    let err = job
        .transition(JobStatus::Completed, None)
        .expect_err("Pending→Completed is invalid");

    assert_eq!(err.from, JobStatus::Pending);
    assert_eq!(err.to, JobStatus::Completed);
    // Status unchanged
    assert_eq!(job.status, JobStatus::Pending);
    assert!(job.transitions.is_empty());
}
