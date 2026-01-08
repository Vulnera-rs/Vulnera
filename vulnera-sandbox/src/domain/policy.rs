//! Sandbox policy value objects

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Sandbox policy defining allowed operations for module execution
///
/// # Security Model
///
/// By default, the policy is maximally restrictive:
/// - No filesystem access (except explicitly allowed paths)
/// - No network access
/// - 30 second timeout
/// - 256MB memory limit
///
/// # Example
///
/// ```rust
/// use vulnera_sandbox::SandboxPolicy;
/// use std::path::PathBuf;
///
/// let policy = SandboxPolicy::default()
///     .with_readonly_path("/path/to/scan")
///     .with_timeout_secs(60);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Directories with read-only access
    pub readonly_paths: Vec<PathBuf>,
    /// Directories with read-write access (use sparingly!)
    pub readwrite_paths: Vec<PathBuf>,
    /// Allowed network ports for outbound connections (empty = no network)
    pub allowed_ports: Vec<u16>,
    /// Maximum execution time before termination
    pub timeout: Duration,
    /// Memory limit in bytes
    pub max_memory: u64,
    /// Allow executing binaries within sandbox
    pub allow_exec: bool,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            readonly_paths: vec![],
            readwrite_paths: vec![],
            allowed_ports: vec![],
            timeout: Duration::from_secs(30),
            max_memory: 256 * 1024 * 1024, // 256MB
            allow_exec: false,
        }
    }
}

/// Builder for constructing sandbox policies fluently
#[derive(Debug, Default)]
pub struct SandboxPolicyBuilder {
    policy: SandboxPolicy,
}

impl SandboxPolicyBuilder {
    /// Create a new policy builder with default (restrictive) settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a read-only path to the sandbox
    pub fn readonly_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.policy.readonly_paths.push(path.into());
        self
    }

    /// Add multiple read-only paths
    pub fn readonly_paths(mut self, paths: impl IntoIterator<Item = PathBuf>) -> Self {
        self.policy.readonly_paths.extend(paths);
        self
    }

    /// Add a read-write path (use sparingly for security)
    pub fn readwrite_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.policy.readwrite_paths.push(path.into());
        self
    }

    /// Allow outbound network connection to a specific port
    pub fn allow_port(mut self, port: u16) -> Self {
        self.policy.allowed_ports.push(port);
        self
    }

    /// Set execution timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.policy.timeout = timeout;
        self
    }

    /// Set timeout in seconds
    pub fn timeout_secs(mut self, secs: u64) -> Self {
        self.policy.timeout = Duration::from_secs(secs);
        self
    }

    /// Set memory limit in bytes
    pub fn max_memory(mut self, bytes: u64) -> Self {
        self.policy.max_memory = bytes;
        self
    }

    /// Set memory limit in megabytes
    pub fn max_memory_mb(mut self, mb: u64) -> Self {
        self.policy.max_memory = mb * 1024 * 1024;
        self
    }

    /// Allow executing binaries within the sandbox
    pub fn allow_exec(mut self) -> Self {
        self.policy.allow_exec = true;
        self
    }

    /// Build the final policy
    pub fn build(self) -> SandboxPolicy {
        self.policy
    }
}

impl SandboxPolicy {
    /// Create a policy builder
    pub fn builder() -> SandboxPolicyBuilder {
        SandboxPolicyBuilder::new()
    }

    /// Add a read-only path (chainable)
    pub fn with_readonly_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.readonly_paths.push(path.into());
        self
    }

    /// Set timeout (chainable)
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set timeout in seconds (chainable)
    pub fn with_timeout_secs(mut self, secs: u64) -> Self {
        self.timeout = Duration::from_secs(secs);
        self
    }

    /// Set memory limit in bytes (chainable)
    pub fn with_memory_limit(mut self, bytes: u64) -> Self {
        self.max_memory = bytes;
        self
    }

    /// Set memory limit in MB (chainable)
    pub fn with_memory_mb(mut self, mb: u64) -> Self {
        self.max_memory = mb * 1024 * 1024;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_is_restrictive() {
        let policy = SandboxPolicy::default();
        assert!(policy.readonly_paths.is_empty());
        assert!(policy.readwrite_paths.is_empty());
        assert!(policy.allowed_ports.is_empty());
        assert!(!policy.allow_exec);
    }

    #[test]
    fn test_builder_pattern() {
        let policy = SandboxPolicy::builder()
            .readonly_path("/tmp/scan")
            .timeout_secs(60)
            .max_memory_mb(512)
            .build();

        assert_eq!(policy.readonly_paths.len(), 1);
        assert_eq!(policy.timeout, Duration::from_secs(60));
        assert_eq!(policy.max_memory, 512 * 1024 * 1024);
    }

    #[test]
    fn test_chainable_methods() {
        let policy = SandboxPolicy::default()
            .with_readonly_path("/path1")
            .with_readonly_path("/path2")
            .with_timeout_secs(120);

        assert_eq!(policy.readonly_paths.len(), 2);
        assert_eq!(policy.timeout, Duration::from_secs(120));
    }
}
