use async_trait::async_trait;
use thiserror::Error;

use super::policy::SandboxPolicy;

pub type SandboxResult<T> = Result<T, SandboxError>;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("Sandbox not supported: {0}")]
    NotSupported(String),

    #[error("Failed to create sandbox: {0}")]
    CreationFailed(String),

    #[error("Policy violation by backend: {0}")]
    PolicyViolation(String),

    #[error("Execution timed out after {0:?}")]
    Timeout(std::time::Duration),

    #[error("Module execution failed: {0}")]
    ModuleExecution(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Platform error: {0}")]
    Platform(String),
}

#[async_trait]
pub trait SandboxBackend: Send + Sync {
    fn name(&self) -> &'static str;

    fn is_available(&self) -> bool;

    async fn apply_restrictions(&self, policy: &SandboxPolicy) -> SandboxResult<()>;
}

#[derive(Debug, Clone, Default)]
pub struct SandboxStats {
    pub setup_time_us: u64,
    pub execution_time_us: u64,
    pub peak_memory_bytes: u64,
    pub blocked_syscalls: u32,
    pub fully_enforced: bool,
}

pub trait SandboxMetrics: Send + Sync {
    fn record_execution(&self, backend: &str, stats: &SandboxStats);
    fn record_error(&self, backend: &str, error: &SandboxError);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = SandboxError::Timeout(std::time::Duration::from_secs(30));
        assert!(err.to_string().contains("30"));

        let err = SandboxError::NotSupported("no kernel support".to_string());
        assert!(err.to_string().contains("kernel"));
    }
}
