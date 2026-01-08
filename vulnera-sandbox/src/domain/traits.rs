//! Sandbox traits and error types

use async_trait::async_trait;
use thiserror::Error;

use super::policy::SandboxPolicy;

/// Result type for sandbox operations
pub type SandboxResult<T> = Result<T, SandboxError>;

/// Errors that can occur during sandboxed execution
#[derive(Debug, Error)]
pub enum SandboxError {
    /// Sandbox backend not supported on this platform
    #[error("Sandbox not supported: {0}")]
    NotSupported(String),

    /// Failed to create sandbox
    #[error("Failed to create sandbox: {0}")]
    CreationFailed(String),

    /// Policy violation during execution
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// Execution timed out
    #[error("Execution timed out after {0:?}")]
    Timeout(std::time::Duration),

    /// Memory limit exceeded
    #[error("Memory limit exceeded: used {used} bytes, limit {limit} bytes")]
    MemoryExceeded { used: u64, limit: u64 },

    /// I/O error during sandbox setup
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Sandbox-specific platform error
    #[error("Platform error: {0}")]
    Platform(String),
}

/// Type alias for boxed futures in trait objects
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Trait for sandbox backend implementations
///
/// Each platform provides its own implementation:
/// - Linux 5.13+: `LandlockSandbox` (fastest)
/// - Older Linux: `ProcessSandbox` (fork-based)
/// - Windows/macOS: `WasmSandbox` (fallback)
///
/// Note: This trait is dyn-compatible for runtime polymorphism.
#[async_trait]
pub trait SandboxBackend: Send + Sync {
    /// Get the backend name for logging/debugging
    fn name(&self) -> &'static str;

    /// Check if this backend is available on the current system
    fn is_available(&self) -> bool;

    /// Apply sandbox restrictions before running a module
    ///
    /// This configures the isolation environment. The actual module
    /// execution is handled by the caller after restrictions are applied.
    ///
    /// Returns Ok(()) if sandbox was successfully configured, or an error if
    /// the sandbox could not be set up.
    async fn apply_restrictions(&self, policy: &SandboxPolicy) -> SandboxResult<()>;
}

/// Statistics about sandbox execution
#[derive(Debug, Clone, Default)]
pub struct SandboxStats {
    /// Time spent in sandbox setup
    pub setup_time_us: u64,
    /// Time spent executing the module
    pub execution_time_us: u64,
    /// Peak memory usage in bytes
    pub peak_memory_bytes: u64,
    /// Number of syscalls blocked
    pub blocked_syscalls: u32,
    /// Whether the sandbox was fully enforced
    pub fully_enforced: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = SandboxError::Timeout(std::time::Duration::from_secs(30));
        assert!(err.to_string().contains("30"));

        let err = SandboxError::MemoryExceeded {
            used: 512,
            limit: 256,
        };
        assert!(err.to_string().contains("512"));
        assert!(err.to_string().contains("256"));
    }
}
