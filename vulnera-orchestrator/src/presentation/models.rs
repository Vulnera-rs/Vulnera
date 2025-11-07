//! API request and response models

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::domain::value_objects::{AnalysisDepth, SourceType};

/// Request model for analysis
#[derive(Deserialize, ToSchema)]
pub struct AnalysisRequest {
    /// Source type (git, file_upload, s3_bucket, directory)
    #[schema(example = "git")]
    pub source_type: String,

    /// Source URI (repository URL, file path, etc.)
    #[schema(example = "https://github.com/my-org/my-project.git")]
    pub source_uri: String,

    /// Analysis depth
    #[schema(example = "full")]
    pub analysis_depth: String,

    /// Optional callback URL for async results
    #[schema(example = "https://my-ci-cd.com/webhook/123")]
    pub callback_url: Option<String>,
}

/// Response model for analysis job creation
#[derive(Serialize, ToSchema)]
pub struct AnalysisResponse {
    /// Job ID for tracking
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub job_id: Uuid,

    /// Job status
    #[schema(example = "Pending")]
    pub status: String,

    /// Message
    #[schema(example = "Analysis job created")]
    pub message: String,
}

/// Job status response
#[derive(Serialize, ToSchema)]
pub struct JobStatusResponse {
    pub job_id: Uuid,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Final report response
#[derive(Serialize, ToSchema)]
pub struct FinalReportResponse {
    pub job_id: Uuid,
    pub status: String,
    pub summary: crate::domain::entities::ReportSummary,
    pub findings: Vec<crate::domain::entities::Finding>,
}

impl AnalysisRequest {
    pub fn parse_source_type(&self) -> Result<SourceType, String> {
        match self.source_type.to_lowercase().as_str() {
            "git" => Ok(SourceType::Git),
            "file_upload" => Ok(SourceType::FileUpload),
            "s3_bucket" => Ok(SourceType::S3Bucket),
            "directory" => Ok(SourceType::Directory),
            _ => Err(format!("Invalid source_type: {}", self.source_type)),
        }
    }

    pub fn parse_analysis_depth(&self) -> Result<AnalysisDepth, String> {
        match self.analysis_depth.to_lowercase().as_str() {
            "full" => Ok(AnalysisDepth::Full),
            "dependencies_only" => Ok(AnalysisDepth::DependenciesOnly),
            "fast_scan" => Ok(AnalysisDepth::FastScan),
            _ => Err(format!("Invalid analysis_depth: {}", self.analysis_depth)),
        }
    }
}
