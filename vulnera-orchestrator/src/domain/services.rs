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
