//! Sandbox executor use case
//!
//! Provides a high-level interface for executing analysis modules within a
//! sandboxed worker process.
//!
//! # Architecture
//!
//! The executor spawns a separate `vulnera-worker` binary for each module
//! execution. The worker process:
//!
//! 1. Applies Landlock + seccomp + rlimit restrictions to itself
//! 2. Executes the analysis module
//! 3. Returns results via JSON over stdout
//!
//! This out-of-process model ensures the orchestrator is never affected
//! by sandbox restrictions.

use std::process::Stdio;
use std::sync::Arc;

use tokio::process::Command;
use tracing::{debug, error, info, instrument, warn};

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
    /// Path to the worker binary (auto-discovered or configured)
    worker_path: Option<String>,
}

impl SandboxExecutor {
    /// Create a new executor with the specified backend
    pub fn new(backend: Arc<dyn SandboxBackend>) -> Self {
        Self {
            backend,
            worker_path: Self::discover_worker_path(),
        }
    }

    /// Create a new executor with automatic backend selection
    pub fn auto() -> Self {
        Self::new(SandboxSelector::select())
    }

    /// Discover the worker binary path
    fn discover_worker_path() -> Option<String> {
        // Check common locations
        let candidates = [
            // Cargo target directory (development)
            "./target/debug/vulnera-worker",
            "./target/release/vulnera-worker",
            // Installed location
            "/usr/local/bin/vulnera-worker",
            // Same directory as current executable
            "vulnera-worker",
        ];

        for path in candidates {
            if std::path::Path::new(path).exists() {
                debug!("Found worker binary at: {}", path);
                return Some(path.to_string());
            }
        }

        // Try to find in PATH
        if which::which("vulnera-worker").is_ok() {
            return Some("vulnera-worker".to_string());
        }

        None
    }

    /// Get the name of the active backend
    pub fn backend_name(&self) -> &'static str {
        self.backend.name()
    }

    /// Check if the backend is available
    pub fn is_available(&self) -> bool {
        self.backend.is_available()
    }

    /// Check if out-of-process execution is available
    pub fn is_worker_available(&self) -> bool {
        self.worker_path.is_some()
    }

    /// Execute an analysis module within the sandbox
    ///
    /// This method:
    /// 1. Spawns a worker process with sandbox restrictions
    /// 2. Passes the module config and policy to the worker
    /// 3. Returns the module result from the worker
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

        // Try out-of-process execution if worker is available
        let result = if let Some(ref worker_path) = self.worker_path {
            self.execute_via_worker(worker_path, module, config, policy)
                .await
        } else {
            // Fallback to in-process (with warning)
            warn!("Worker binary not found, falling back to in-process execution (less secure)");
            self.execute_in_process(module, config, policy).await
        };

        let elapsed = start.elapsed();
        debug!(
            "Module {:?} completed in {:?}",
            module.module_type(),
            elapsed
        );

        result
    }

    /// Execute via worker process (secure, out-of-process)
    async fn execute_via_worker(
        &self,
        worker_path: &str,
        module: &dyn AnalysisModule,
        config: &ModuleConfig,
        policy: &SandboxPolicy,
    ) -> Result<ModuleResult, SandboxedExecutionError> {
        let policy_json = serde_json::to_string(policy).map_err(|e| {
            SandboxedExecutionError::Sandbox(SandboxError::CreationFailed(format!(
                "Failed to serialize policy: {}",
                e
            )))
        })?;

        let module_type = format!("{:?}", module.module_type());
        let config_json = serde_json::to_string(&config.config).map_err(|e| {
            SandboxedExecutionError::Sandbox(SandboxError::CreationFailed(format!(
                "Failed to serialize module config: {}",
                e
            )))
        })?;

        debug!(
            "Spawning worker: {} --module {} --source-uri {}",
            worker_path, module_type, config.source_uri
        );

        let mut command = Command::new(worker_path);
        command
            .arg("--module")
            .arg(&module_type)
            .arg("--source-uri")
            .arg(&config.source_uri)
            .arg("--project-id")
            .arg(&config.project_id)
            .arg("--job-id")
            .arg(&config.job_id.to_string())
            .arg("--module-config")
            .arg(&config_json)
            .arg("--policy")
            .arg(&policy_json);

        if self.backend.name() == "noop" {
            command.arg("--no-sandbox");
        }

        let child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                SandboxedExecutionError::Sandbox(SandboxError::CreationFailed(format!(
                    "Failed to spawn worker: {}",
                    e
                )))
            })?;

        // Wait with timeout
        let output = tokio::time::timeout(policy.timeout, child.wait_with_output())
            .await
            .map_err(|_| SandboxedExecutionError::Timeout(policy.timeout))?
            .map_err(|e| {
                SandboxedExecutionError::Sandbox(SandboxError::CreationFailed(format!(
                    "Worker failed: {}",
                    e
                )))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("Worker failed with status {}: {}", output.status, stderr);
            return Err(SandboxedExecutionError::Sandbox(
                SandboxError::CreationFailed(format!(
                    "Worker exited with {}: {}",
                    output.status, stderr
                )),
            ));
        }

        // Parse worker result
        let worker_result: WorkerResult = serde_json::from_slice(&output.stdout).map_err(|e| {
            SandboxedExecutionError::Sandbox(SandboxError::CreationFailed(format!(
                "Invalid worker output: {}",
                e
            )))
        })?;

        if !worker_result.success {
            return Err(SandboxedExecutionError::ModuleFailed(
                ModuleExecutionError::ExecutionFailed(
                    worker_result
                        .error
                        .unwrap_or_else(|| "Unknown error".to_string()),
                ),
            ));
        }

        // Convert worker result to ModuleResult
        let module_result = worker_result.result.ok_or_else(|| {
            SandboxedExecutionError::Sandbox(SandboxError::CreationFailed(
                "Worker returned no result".to_string(),
            ))
        })?;

        // Parse the inner result as ModuleResult
        let result: ModuleResult =
            serde_json::from_value(module_result).unwrap_or_else(|_| ModuleResult {
                job_id: config.job_id,
                module_type: module.module_type(),
                findings: vec![],
                metadata: Default::default(),
                error: None,
            });

        Ok(result)
    }

    /// Fallback: Execute in-process (less secure but still functional)
    async fn execute_in_process(
        &self,
        module: &dyn AnalysisModule,
        config: &ModuleConfig,
        policy: &SandboxPolicy,
    ) -> Result<ModuleResult, SandboxedExecutionError> {
        // Note: This does NOT apply actual sandbox restrictions to the current process
        // as that would affect the orchestrator. This is a compatibility fallback.

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

/// Worker result structure (matches worker.rs)
#[derive(Debug, serde::Deserialize)]
struct WorkerResult {
    success: bool,
    result: Option<serde_json::Value>,
    error: Option<String>,
    #[allow(dead_code)]
    execution_time_ms: u64,
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
        println!("Worker available: {}", executor.is_worker_available());
    }

    #[test]
    fn test_default_executor() {
        let executor = SandboxExecutor::default();
        assert!(executor.is_available());
    }

    #[test]
    fn test_worker_discovery() {
        let path = SandboxExecutor::discover_worker_path();
        println!("Discovered worker: {:?}", path);
        // Worker may or may not be present depending on build state
    }
}
