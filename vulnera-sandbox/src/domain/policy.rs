//! Sandbox policy value objects

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Predefined policy profiles for analysis modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxPolicyProfile {
    /// No network access; filesystem-only analysis.
    ReadOnlyAnalysis,
    /// Dependency resolution profile with outbound HTTP(S) and optional Redis/Dragonfly.
    DependencyResolution { include_cache_port: bool },
}

/// Sandbox policy defining allowed operations for module execution
///
/// # Security Model
///
/// By default, the policy is maximally restrictive:
/// - No filesystem access (except explicitly allowed paths)
/// - No network access
/// - 30 second timeout
/// - 1GB memory limit
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
            max_memory: 1024 * 1024 * 1024, // 1GB
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

    /// Create a policy suitable for running analysis modules on Linux
    ///
    /// This policy includes essential system paths needed for Rust binaries:
    /// - `/usr`, `/lib`, `/lib64` - shared libraries
    /// - `/proc` - process information (needed by some libraries)
    /// - `/etc/ssl`, `/etc/pki` - SSL certificates (for network modules)
    /// - `/tmp` - temporary files (read-write)
    ///
    /// # Example
    /// ```rust,ignore
    /// let policy = SandboxPolicy::for_analysis("/path/to/scan")
    ///     .with_timeout_secs(60);
    /// ```
    pub fn for_analysis(source_path: impl Into<PathBuf>) -> Self {
        let mut policy = Self::default();

        // Essential system paths for Rust binaries
        let system_paths = [
            "/usr",
            "/lib",
            "/lib64",
            "/lib32",
            "/proc",
            "/etc/ssl",
            "/etc/pki",
            "/etc/ca-certificates",
            "/etc/resolv.conf",
            "/etc/hosts",
            "/etc/nsswitch.conf",
            "/etc/passwd", // getpwuid needs this
            "/etc/group",
        ];

        for path in system_paths {
            let p = PathBuf::from(path);
            if p.exists() {
                policy.readonly_paths.push(p);
            }
        }

        // Add source path
        policy.readonly_paths.push(source_path.into());

        // Temp directory for scratch files (read-write)
        policy.readwrite_paths.push(PathBuf::from("/tmp"));

        // Reasonable defaults for analysis
        policy.timeout = Duration::from_secs(120); // 2 minutes
        policy.max_memory = 2 * 1024 * 1024 * 1024; // 2GB

        policy
    }

    /// Create an analysis policy with a predefined profile.
    pub fn for_profile(source_path: impl Into<PathBuf>, profile: SandboxPolicyProfile) -> Self {
        Self::for_analysis(source_path).with_profile(profile)
    }

    /// Apply a predefined profile to this policy.
    pub fn with_profile(mut self, profile: SandboxPolicyProfile) -> Self {
        match profile {
            SandboxPolicyProfile::ReadOnlyAnalysis => {
                self.allowed_ports.clear();
            }
            SandboxPolicyProfile::DependencyResolution { include_cache_port } => {
                self = self.with_http_access();
                if include_cache_port {
                    self = self.with_port(6379);
                }
            }
        }
        self
    }

    /// Add a read-only path (chainable)
    pub fn with_readonly_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.readonly_paths.push(path.into());
        self
    }

    /// Add a read-write path (chainable)
    pub fn with_readwrite_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.readwrite_paths.push(path.into());
        self
    }

    /// Add /tmp for temporary file access (chainable)
    pub fn with_temp_access(mut self) -> Self {
        let tmp = PathBuf::from("/tmp");
        if !self.readwrite_paths.contains(&tmp) {
            self.readwrite_paths.push(tmp);
        }
        self
    }

    /// Add network port access (chainable)
    pub fn with_port(mut self, port: u16) -> Self {
        if !self.allowed_ports.contains(&port) {
            self.allowed_ports.push(port);
        }
        self
    }

    /// Add common HTTPS/HTTP ports (chainable)
    pub fn with_http_access(mut self) -> Self {
        for port in [80, 443, 8080, 8443] {
            if !self.allowed_ports.contains(&port) {
                self.allowed_ports.push(port);
            }
        }
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

    #[test]
    fn test_read_only_profile_blocks_network() {
        let policy = SandboxPolicy::default()
            .with_http_access()
            .with_profile(SandboxPolicyProfile::ReadOnlyAnalysis);

        assert!(policy.allowed_ports.is_empty());
    }

    #[test]
    fn test_dependency_profile_adds_required_ports() {
        let policy = SandboxPolicy::default().with_profile(
            SandboxPolicyProfile::DependencyResolution {
                include_cache_port: true,
            },
        );

        assert!(policy.allowed_ports.contains(&80));
        assert!(policy.allowed_ports.contains(&443));
        assert!(policy.allowed_ports.contains(&6379));
    }
}
