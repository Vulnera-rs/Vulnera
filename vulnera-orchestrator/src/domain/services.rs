//! Orchestrator domain services

use async_trait::async_trait;

use vulnera_core::domain::module::ModuleType;

use super::entities::Project;
use super::value_objects::{AnalysisDepth, AwsCredentials, SourceType};

/// Service for detecting project characteristics
#[async_trait]
pub trait ProjectDetector: Send + Sync {
    /// Detect project type and languages from source
    async fn detect_project(
        &self,
        source_type: &SourceType,
        source_uri: &str,
        aws_credentials: Option<&AwsCredentials>,
    ) -> Result<Project, ProjectDetectionError>;
}

/// Service for selecting which modules to run
#[async_trait]
pub trait ModuleSelector: Send + Sync {
    /// Determine which modules to run based on project characteristics
    fn select_modules(&self, project: &Project, analysis_depth: &AnalysisDepth) -> Vec<ModuleType>;
}

/// Abstract job queue interface.
///
/// Allows swapping the backing store (Dragonfly list, DB-backed queue, etc.)
/// without changing application logic.
#[async_trait]
pub trait IJobQueue: Send + Sync {
    /// Push a serialised job onto the queue.
    async fn enqueue_raw(&self, payload: &[u8]) -> Result<(), JobQueueError>;

    /// Blocking pop with timeout. Returns `None` if no job arrives within `timeout`.
    async fn dequeue_raw(
        &self,
        timeout: std::time::Duration,
    ) -> Result<Option<Vec<u8>>, JobQueueError>;
}

/// Errors that can occur during queue operations.
#[derive(thiserror::Error, Debug)]
pub enum JobQueueError {
    #[error("Failed to enqueue job: {0}")]
    EnqueueFailed(String),

    #[error("Failed to dequeue job: {0}")]
    DequeueFailed(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Project detection error
#[derive(Debug, thiserror::Error)]
pub enum ProjectDetectionError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid source URI: {0}")]
    InvalidUri(String),

    #[error("Project not found: {0}")]
    NotFound(String),

    #[error("Detection failed: {0}")]
    DetectionFailed(String),

    #[error("S3 error: {0}")]
    S3Error(String),

    #[error("Missing AWS credentials for S3 bucket source")]
    MissingAwsCredentials,

    #[error("Invalid S3 bucket URI: {0}")]
    InvalidS3Uri(String),
}
