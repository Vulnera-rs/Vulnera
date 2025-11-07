//! Orchestrator value objects

use serde::{Deserialize, Serialize};

/// Source type for analysis input
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceType {
    /// Git repository URL
    Git,
    /// File upload
    FileUpload,
    /// S3 bucket path
    S3Bucket,
    /// Local directory path
    Directory,
}

/// Analysis depth configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalysisDepth {
    /// Full analysis with all modules
    Full,
    /// Dependencies only
    DependenciesOnly,
    /// Fast scan with minimal modules
    FastScan,
}

// ModuleType is now imported from vulnera_core::domain::module

/// Job status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    /// Job is pending execution
    Pending,
    /// Job is currently running
    Running,
    /// Job completed successfully
    Completed,
    /// Job failed
    Failed,
}


