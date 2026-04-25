use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxPolicyProfile {
    ReadOnlyAnalysis,
    DependencyResolution { include_cache_port: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    pub readonly_paths: Vec<PathBuf>,
    pub readwrite_paths: Vec<PathBuf>,
    pub allowed_ports: Vec<u16>,
    pub timeout: Duration,
    pub max_memory: u64,
    pub allow_exec: bool,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            readonly_paths: vec![],
            readwrite_paths: vec![],
            allowed_ports: vec![],
            timeout: Duration::from_secs(30),
            max_memory: 1024 * 1024 * 1024,
            allow_exec: false,
        }
    }
}

impl SandboxPolicy {
    pub fn for_analysis(source_path: impl Into<PathBuf>) -> Self {
        let mut policy = Self::default();

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
            "/etc/passwd",
            "/etc/group",
        ]; //TODO
        for path in system_paths {
            let p = PathBuf::from(path);
            if p.exists() {
                policy.readonly_paths.push(p);
            }
        }
        policy.readonly_paths.push(source_path.into());
        policy.readwrite_paths.push(PathBuf::from("/tmp"));
        policy.timeout = Duration::from_secs(120);
        policy.max_memory = 2 * 1024 * 1024 * 1024;
        policy
    }

    pub fn for_profile(source_path: impl Into<PathBuf>, profile: SandboxPolicyProfile) -> Self {
        Self::for_analysis(source_path).with_profile(profile)
    }

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

    pub fn with_readonly_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.readonly_paths.push(path.into());
        self
    }

    pub fn with_readwrite_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.readwrite_paths.push(path.into());
        self
    }

    pub fn with_temp_access(mut self) -> Self {
        let tmp = PathBuf::from("/tmp");
        if !self.readwrite_paths.contains(&tmp) {
            self.readwrite_paths.push(tmp);
        }
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        if !self.allowed_ports.contains(&port) {
            self.allowed_ports.push(port);
        }
        self
    }

    pub fn with_http_access(mut self) -> Self {
        for port in [80, 443, 8080, 8443] {
            if !self.allowed_ports.contains(&port) {
                self.allowed_ports.push(port);
            }
        }
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_timeout_secs(mut self, secs: u64) -> Self {
        self.timeout = Duration::from_secs(secs);
        self
    }

    pub fn with_memory_limit(mut self, bytes: u64) -> Self {
        self.max_memory = bytes;
        self
    }

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
        let policy =
            SandboxPolicy::default().with_profile(SandboxPolicyProfile::DependencyResolution {
                include_cache_port: true,
            });
        assert!(policy.allowed_ports.contains(&80));
        assert!(policy.allowed_ports.contains(&443));
        assert!(policy.allowed_ports.contains(&6379));
    }
}
