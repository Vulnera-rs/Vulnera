//! API request and response models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::domain::value_objects::{AnalysisDepth, SourceType};

/// Request model for orchestrator job-based analysis
#[derive(Deserialize, ToSchema)]
pub struct AnalysisRequest {
    /// Source type. Allowed values:
    /// - `git`: Git repository URL
    /// - `file_upload`: File upload (single dependency file)
    /// - `s3_bucket`: S3 bucket path
    /// - `directory`: Local directory path
    #[schema(example = "git")]
    pub source_type: String,

    /// Source URI (repository URL, file path, etc.)
    #[schema(example = "https://github.com/my-org/my-project.git")]
    pub source_uri: String,

    /// Analysis depth. Allowed values:
    /// - `full`: Full analysis with all modules
    /// - `dependencies_only`: Only dependency analysis
    /// - `fast_scan`: Fast scan (dependencies + basic SAST)
    #[schema(example = "full")]
    pub analysis_depth: String,

    /// Optional callback URL for async results
    #[schema(example = "https://my-ci-cd.com/webhook/123")]
    pub callback_url: Option<String>,

    /// Optional secret for webhook signature verification (HMAC-SHA256).
    /// If provided, webhook payloads will include X-Vulnera-Signature header.
    #[schema(example = "whsec_abc123...")]
    pub webhook_secret: Option<String>,
}

/// Response model for dependency analysis results
#[derive(Serialize, ToSchema)]
pub struct AnalysisResponse {
    /// Unique analysis ID for tracking and retrieval
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub id: Uuid,

    /// Current analysis status
    pub status: String,
}

/// Module execution result
#[derive(Serialize, ToSchema)]
pub struct ModuleResultDto {
    pub module_type: String,
    pub status: String,
    pub files_scanned: usize,
    pub duration_ms: u64,
    pub findings_count: usize,
    pub metadata: Option<serde_json::Value>,
    pub error: Option<String>,
}

/// Job status response
#[derive(Serialize)]
pub struct JobStatusResponse {
    pub job_id: Uuid,
    pub project_id: String,
    pub status: String,
    pub summary: crate::domain::entities::Summary,
    pub created_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub error: Option<String>,
    pub callback_url: Option<String>,
    pub invocation_context: Option<JobInvocationContextDto>,

    pub modules: Vec<ModuleResultDto>,
    pub findings_by_type: crate::domain::entities::FindingsByType,
}

/// Response returned when a job is accepted for asynchronous processing
#[derive(Serialize, ToSchema)]
pub struct JobAcceptedResponse {
    pub job_id: Uuid,
    pub status: String,
    pub callback_url: Option<String>,
    pub message: String,
}

/// Sanitized view of the invocation context for API responses
#[derive(Serialize, ToSchema)]
pub struct JobInvocationContextDto {
    pub is_master_key: bool,
}

impl From<crate::domain::entities::JobInvocationContext> for JobInvocationContextDto {
    fn from(context: crate::domain::entities::JobInvocationContext) -> Self {
        Self {
            is_master_key: context.is_master_key,
        }
    }
}

impl From<vulnera_contract::domain::module::ModuleResult> for ModuleResultDto {
    fn from(result: vulnera_contract::domain::module::ModuleResult) -> Self {
        Self {
            module_type: format!("{:?}", result.module_type),
            status: if result.error.is_none() {
                "Completed".to_string()
            } else {
                "Failed".to_string()
            },
            files_scanned: result.metadata.files_scanned,
            duration_ms: result.metadata.duration_ms,
            findings_count: result.findings.len(),
            metadata: Some(serde_json::to_value(&result.metadata).unwrap_or_default()),
            error: result.error,
        }
    }
}

impl From<crate::infrastructure::JobSnapshot> for JobStatusResponse {
    fn from(snapshot: crate::infrastructure::JobSnapshot) -> Self {
        Self {
            job_id: snapshot.job_id,
            project_id: snapshot.project_id,
            status: format!("{:?}", snapshot.status),
            created_at: snapshot.created_at,
            started_at: snapshot.started_at,
            completed_at: snapshot.completed_at,
            error: snapshot.error,
            callback_url: snapshot.callback_url,
            invocation_context: snapshot
                .invocation_context
                .map(JobInvocationContextDto::from),
            summary: snapshot
                .summary
                .unwrap_or_else(|| crate::domain::entities::Summary {
                    total_findings: 0,
                    by_severity: Default::default(),
                    by_type: crate::domain::entities::TypeBreakdown {
                        sast: 0,
                        secrets: 0,
                        dependencies: 0,
                        api: 0,
                    },
                    modules_completed: 0,
                    modules_failed: 0,
                }),
            modules: snapshot
                .module_results
                .into_iter()
                .map(ModuleResultDto::from)
                .collect(),
            findings_by_type: snapshot.findings_by_type.unwrap_or_else(|| {
                crate::domain::entities::FindingsByType {
                    sast: vec![],
                    secrets: vec![],
                    dependencies: std::collections::HashMap::new(),
                    api: vec![],
                }
            }),
        }
    }
}

/// Final report response
#[derive(Serialize)]
pub struct FinalReportResponse {
    pub job_id: Uuid,
    pub status: String,
    pub summary: crate::domain::entities::Summary,
    pub findings_by_type: crate::domain::entities::FindingsByType,
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

/// Error response model
#[derive(Serialize, ToSchema)]
pub struct ErrorResponse {
    /// Machine-readable error code
    #[schema(example = "PARSE_ERROR")]
    pub code: String,

    /// Human-readable error message
    #[schema(example = "Failed to parse dependency file: Invalid JSON format")]
    pub message: String,

    /// Additional error context and debugging information
    #[schema(example = r#"{"field": "file_content", "line": 5, "column": 12}"#)]
    pub details: Option<serde_json::Value>,

    /// Unique request identifier for tracking and support
    #[schema(example = "req_550e8400-e29b-41d4-a716-446655440000")]
    pub request_id: Uuid,

    /// Error occurrence timestamp
    #[schema(example = "2024-01-15T10:30:00Z")]
    pub timestamp: DateTime<Utc>,
}

/// Health check response
#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    /// Overall service health status
    #[schema(example = "healthy")]
    pub status: String,

    /// Current service version
    #[schema(example = "1.0.0")]
    pub version: String,

    /// Health check timestamp
    #[schema(example = "2024-01-15T10:30:00Z")]
    pub timestamp: DateTime<Utc>,

    /// Detailed health information and dependency status
    #[schema(
        example = r#"{"dependencies": {"cache": {"status": "healthy"}, "external_apis": {"osv": "healthy", "nvd": "healthy"}}}"#
    )]
    pub details: Option<serde_json::Value>,
}
