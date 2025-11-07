//! Analysis module trait definition

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::entities::ModuleResult;
use super::value_objects::ModuleType;

/// Configuration for module execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    pub job_id: uuid::Uuid,
    pub project_id: String,
    pub source_uri: String,
    pub config: std::collections::HashMap<String, serde_json::Value>,
}

/// Trait that all analysis modules must implement
#[async_trait]
pub trait AnalysisModule: Send + Sync {
    /// Get the module type identifier
    fn module_type(&self) -> ModuleType;

    /// Execute the analysis module
    async fn execute(&self, config: &ModuleConfig) -> Result<ModuleResult, ModuleExecutionError>;
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
