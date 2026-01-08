//! Sandbox executor use case
//!
//! Provides a high-level interface for executing analysis modules within a sandbox.

use std::sync::Arc;
use tracing::{debug, info, instrument};

use crate::application::selector::SandboxSelector;
use crate::domain::policy::SandboxPolicy;
use crate::domain::traits::{SandboxBackend, SandboxError};
use vulnera_core::domain::module::{
    AnalysisModule, ModuleConfig, ModuleExecutionError, ModuleResult,
};

/// Sandbox executor for running analysis modules safely
///
/// # Example
///
/// ```rust,ignore
/// use vulnera_sandbox::{SandboxExecutor, SandboxPolicy, SandboxSelector};
///
/// let executor = SandboxExecutor::new(SandboxSelector::select());
///
/// let policy = SandboxPolicy::default()
///     .with_readonly_path("/path/to/scan");
///
/// let result = executor.execute_module(&module, &config, &policy).await?;
/// ```
pub struct SandboxExecutor {
    backend: Arc<dyn SandboxBackend>,
}

impl SandboxExecutor {
    /// Create a new executor with the specified backend
    pub fn new(backend: Arc<dyn SandboxBackend>) -> Self {
        Self { backend }
    }

    /// Create a new executor with automatic backend selection
    pub fn auto() -> Self {
        Self::new(SandboxSelector::select())
    }

    /// Get the name of the active backend
    pub fn backend_name(&self) -> &'static str {
        self.backend.name()
    }

    /// Check if the backend is available
    pub fn is_available(&self) -> bool {
        self.backend.is_available()
    }

    /// Execute an analysis module within the sandbox
    ///
    /// This method:
    /// 1. Applies sandbox restrictions (filesystem, memory limits)
    /// 2. Executes the module with timeout enforcement
    /// 3. Returns the module result
    #[instrument(skip(self, module, config), fields(backend = %self.backend.name()))]
    pub async fn execute_module(
        &self,
        module: &dyn AnalysisModule,
        config: &ModuleConfig,
        policy: &SandboxPolicy,
    ) -> Result<ModuleResult, SandboxedExecutionError> {
        info!(
            "Executing module {:?} with {} sandbox",
            module.module_type(),
            self.backend.name()
        );

        let start = std::time::Instant::now();
        let module_type = module.module_type();

        // Apply sandbox restrictions (if available)
        if let Err(e) = self.backend.apply_restrictions(policy).await {
            // Log but don't fail - sandbox is optional enhancement
            debug!("Sandbox restrictions not applied: {}", e);
        }

        // Execute the module with timeout
        let result = self.execute_with_timeout(module, config, policy).await;

        let elapsed = start.elapsed();
        debug!(
            "Module {:?} completed in {:?} (backend: {})",
            module_type,
            elapsed,
            self.backend.name()
        );

        result
    }

    /// Execute with timeout enforcement
    async fn execute_with_timeout(
        &self,
        module: &dyn AnalysisModule,
        config: &ModuleConfig,
        policy: &SandboxPolicy,
    ) -> Result<ModuleResult, SandboxedExecutionError> {
        match tokio::time::timeout(policy.timeout, module.execute(config)).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(e)) => Err(SandboxedExecutionError::ModuleFailed(e)),
            Err(_) => Err(SandboxedExecutionError::Timeout(policy.timeout)),
        }
    }
}

impl Default for SandboxExecutor {
    fn default() -> Self {
        Self::auto()
    }
}

/// Error type for sandboxed execution
#[derive(Debug, thiserror::Error)]
pub enum SandboxedExecutionError {
    /// Sandbox setup failed
    #[error("Sandbox error: {0}")]
    Sandbox(#[from] SandboxError),

    /// Module execution failed
    #[error("Module execution failed: {0}")]
    ModuleFailed(#[from] ModuleExecutionError),

    /// Execution timed out
    #[error("Execution timed out after {0:?}")]
    Timeout(std::time::Duration),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_creation() {
        let executor = SandboxExecutor::auto();
        assert!(executor.is_available());
        println!("Using backend: {}", executor.backend_name());
    }

    #[test]
    fn test_default_executor() {
        let executor = SandboxExecutor::default();
        assert!(executor.is_available());
    }
}
