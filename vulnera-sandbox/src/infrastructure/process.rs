//! Process-based sandbox fallback
//!
//! Uses resource limits for sandboxing on older Linux
//! systems that don't support Landlock.

use async_trait::async_trait;
use nix::sys::resource::{Resource, setrlimit};
use tracing::debug;

use crate::domain::policy::SandboxPolicy;
use crate::domain::traits::{SandboxBackend, SandboxError, SandboxResult};

/// Process-based sandbox using resource limits
///
/// This is a fallback for systems without Landlock support.
/// Less secure than Landlock but still provides useful isolation.
#[derive(Debug, Default)]
pub struct ProcessSandbox;

impl ProcessSandbox {
    /// Create a new process sandbox
    pub fn new() -> Self {
        Self
    }

    /// Apply resource limits to the current process
    fn apply_resource_limits(policy: &SandboxPolicy) -> SandboxResult<()> {
        // Memory limit (both virtual and resident)
        setrlimit(Resource::RLIMIT_AS, policy.max_memory, policy.max_memory).map_err(|e| {
            SandboxError::CreationFailed(format!("Failed to set memory limit: {}", e))
        })?;

        // CPU time limit (soft limit = timeout, hard limit = timeout + 5s)
        let cpu_secs = policy.timeout.as_secs();
        setrlimit(Resource::RLIMIT_CPU, cpu_secs, cpu_secs + 5)
            .map_err(|e| SandboxError::CreationFailed(format!("Failed to set CPU limit: {}", e)))?;

        // Disable core dumps
        setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(|e| {
            SandboxError::CreationFailed(format!("Failed to disable core dumps: {}", e))
        })?;

        // Limit file descriptors
        setrlimit(Resource::RLIMIT_NOFILE, 256, 512)
            .map_err(|e| SandboxError::CreationFailed(format!("Failed to limit fds: {}", e)))?;

        // Limit number of processes/threads
        setrlimit(Resource::RLIMIT_NPROC, 32, 64)
            .map_err(|e| SandboxError::CreationFailed(format!("Failed to limit procs: {}", e)))?;

        debug!("Resource limits applied successfully");
        Ok(())
    }
}

#[async_trait]
impl SandboxBackend for ProcessSandbox {
    fn name(&self) -> &'static str {
        "process"
    }

    fn is_available(&self) -> bool {
        // Process sandboxing is always available on Unix-like systems
        cfg!(unix)
    }

    async fn apply_restrictions(&self, policy: &SandboxPolicy) -> SandboxResult<()> {
        Self::apply_resource_limits(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_sandbox_available() {
        let sandbox = ProcessSandbox::new();
        assert!(sandbox.is_available());
        assert_eq!(sandbox.name(), "process");
    }
}
