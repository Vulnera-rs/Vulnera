//! Analysis module trait definition

use async_trait::async_trait;

use super::entities::ModuleResult;
use super::value_objects::{ModuleConfig, ModuleExecutionError, ModuleType};
use crate::domain::project::Project;

/// Trait that all analysis modules must implement
///
/// This trait provides a unified interface for executing different types of analysis modules.
/// Each module (dependency analysis, SAST, etc.) implements this trait to integrate with
/// the orchestrator's job-based execution system.
#[async_trait]
pub trait AnalysisModule: Send + Sync {
    /// Get the module type identifier
    fn module_type(&self) -> ModuleType;

    /// Prepare module-specific configuration from project metadata
    ///
    /// This allows modules to extract necessary information (like manifest contents)
    /// without the orchestrator needing to know module-specific details.
    async fn prepare_config(
        &self,
        _project: &Project,
    ) -> Result<std::collections::HashMap<String, serde_json::Value>, ModuleExecutionError> {
        Ok(std::collections::HashMap::new())
    }

    /// Execute the analysis module
    ///
    /// # Arguments
    /// * `config` - Configuration for module execution, including job ID, project ID, source URI, and module-specific config
    ///
    /// # Returns
    /// * `Ok(ModuleResult)` - Analysis results with findings and metadata
    /// * `Err(ModuleExecutionError)` - Error during module execution
    async fn execute(&self, config: &ModuleConfig) -> Result<ModuleResult, ModuleExecutionError>;
}
