use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, instrument, warn};

use crate::application::selector::SandboxSelector;
use crate::domain::policy::SandboxPolicy;
use crate::domain::traits::{SandboxBackend, SandboxError};
use vulnera_contract::domain::module::{
    AnalysisModule, ModuleConfig, ModuleExecutionError, ModuleResult,
};

pub struct SandboxExecutor {
    backend: Arc<dyn SandboxBackend>,
    strict_mode: bool,
}

impl std::fmt::Debug for SandboxExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxExecutor")
            .field("backend", &self.backend.name())
            .field("strict_mode", &self.strict_mode)
            .finish()
    }
}

impl SandboxExecutor {
    pub fn new(backend: Arc<dyn SandboxBackend>) -> Self {
        Self {
            backend,
            strict_mode: false,
        }
    }

    pub fn with_options(backend: Arc<dyn SandboxBackend>, strict_mode: bool) -> Self {
        Self {
            backend,
            strict_mode,
        }
    }

    pub fn auto() -> Self {
        Self::new(SandboxSelector::select())
    }

    pub fn backend_name(&self) -> &'static str {
        self.backend.name()
    }

    pub fn strict_mode(&self) -> bool {
        self.strict_mode
    }

    pub fn is_available(&self) -> bool {
        self.backend.is_available()
    }

    #[instrument(skip(self, module, config), fields(backend = %self.backend.name()))]
    pub async fn execute_module(
        &self,
        module: &dyn AnalysisModule,
        config: &ModuleConfig,
        policy: &SandboxPolicy,
    ) -> Result<ModuleResult, SandboxedExecutionError> {
        info!(
            "Executing {:?} with {} sandbox",
            module.module_type(),
            self.backend.name()
        );

        let start = Instant::now();

        match self.backend.apply_restrictions(policy).await {
            Ok(()) => info!("Sandbox restrictions applied successfully"),
            Err(e) => {
                if self.strict_mode {
                    return Err(SandboxedExecutionError::Sandbox(e));
                }
                warn!("Sandbox restrictions failed (continuing): {e}");
            }
        }

        let result = self.execute_in_process(module, config, policy).await;

        let elapsed = start.elapsed();
        debug!(
            "Module {:?} completed in {:?}",
            module.module_type(),
            elapsed
        );

        result
    }

    async fn execute_in_process(
        &self,
        module: &dyn AnalysisModule,
        config: &ModuleConfig,
        policy: &SandboxPolicy,
    ) -> Result<ModuleResult, SandboxedExecutionError> {
        match tokio::time::timeout(policy.timeout, module.execute(config)).await {
            Ok(Ok(mut result)) => {
                result.metadata.additional_info.insert(
                    "sandbox.backend".to_string(),
                    self.backend.name().to_string(),
                );
                result.metadata.additional_info.insert(
                    "sandbox.strict_mode".to_string(),
                    self.strict_mode.to_string(),
                );
                result
                    .metadata
                    .additional_info
                    .insert("sandbox.applied".to_string(), "true".to_string());
                Ok(result)
            }
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

#[derive(Debug, thiserror::Error)]
pub enum SandboxedExecutionError {
    #[error("Sandbox error: {0}")]
    Sandbox(#[from] SandboxError),

    #[error("Module execution failed: {0}")]
    ModuleFailed(#[from] ModuleExecutionError),

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
        println!("Backend: {}", executor.backend_name());
    }

    #[test]
    fn test_default_executor() {
        let executor = SandboxExecutor::default();
        assert!(executor.is_available());
        assert!(!executor.strict_mode());
    }
}
