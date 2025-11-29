//! Orchestrator value objects

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

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

/// AWS credentials for S3 bucket access
///
/// Passed via `X-AWS-Credentials` header as Base64-encoded JSON.
/// Supports both long-term credentials and STS temporary credentials.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AwsCredentials {
    /// AWS access key ID
    #[schema(example = "AKIAIOSFODNN7EXAMPLE")]
    pub access_key_id: String,

    /// AWS secret access key
    #[schema(example = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")]
    pub secret_access_key: String,

    /// Optional session token for STS temporary credentials
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,

    /// AWS region (e.g., "us-east-1", "eu-west-1")
    /// If not provided, will be extracted from bucket URI or default to us-east-1
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "us-east-1")]
    pub region: Option<String>,
}

impl AwsCredentials {
    /// Create new AWS credentials with required fields
    pub fn new(access_key_id: String, secret_access_key: String) -> Self {
        Self {
            access_key_id,
            secret_access_key,
            session_token: None,
            region: None,
        }
    }

    /// Set session token for STS temporary credentials
    pub fn with_session_token(mut self, token: String) -> Self {
        self.session_token = Some(token);
        self
    }

    /// Set AWS region
    pub fn with_region(mut self, region: String) -> Self {
        self.region = Some(region);
        self
    }

    /// Get the effective region, defaulting to us-east-1 if not specified
    pub fn effective_region(&self) -> &str {
        self.region.as_deref().unwrap_or("us-east-1")
    }
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
