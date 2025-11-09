//! Module plugin value objects

use serde::{Deserialize, Serialize};

/// Module type identifier
///
/// Each analysis module type has a unique identifier that is used for registration,
/// selection, and routing within the orchestrator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModuleType {
    /// Dependency analyzer module
    DependencyAnalyzer,
    /// SAST module
    SAST,
    /// Secret detection module
    SecretDetection,
    /// Malicious package detection module
    MaliciousPackageDetection,
    /// License compliance module
    LicenseCompliance,
    /// SBOM generation module
    SBOM,
    /// DAST module
    DAST,
    /// API security module
    ApiSecurity,
    /// Fuzz testing module
    FuzzTesting,
    /// IaC/Container security module
    IaC,
    /// CSPM module
    CSPM,
}

/// Configuration for module execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    /// Unique job identifier
    pub job_id: uuid::Uuid,
    /// Project identifier
    pub project_id: String,
    /// Source URI (file path, git URL, etc.)
    pub source_uri: String,
    /// Module-specific configuration parameters
    pub config: std::collections::HashMap<String, serde_json::Value>,
}

/// Module execution error
#[derive(Debug, thiserror::Error)]
pub enum ModuleExecutionError {
    #[error("Module execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Other error: {0}")]
    Other(String),
}
