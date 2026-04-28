use async_trait::async_trait;
use nix::sched::{self, CloneFlags};
use nix::sys::resource::{Resource, setrlimit};
use tracing::{debug, info, warn};

use super::seccomp;
use crate::domain::policy::SandboxPolicy;
use crate::domain::traits::{SandboxBackend, SandboxError, SandboxResult};

#[derive(Debug, Default)]
pub struct ProcessSandbox;

impl ProcessSandbox {
    pub fn new() -> Self {
        Self
    }

    fn apply_resource_limits(policy: &SandboxPolicy) -> SandboxResult<()> {
        setrlimit(Resource::RLIMIT_AS, policy.max_memory, policy.max_memory)
            .map_err(|e| SandboxError::CreationFailed(format!("RLIMIT_AS: {e}")))?;
        let cpu_secs = policy.timeout.as_secs();
        setrlimit(Resource::RLIMIT_CPU, cpu_secs, cpu_secs + 5)
            .map_err(|e| SandboxError::CreationFailed(format!("RLIMIT_CPU: {e}")))?;
        setrlimit(Resource::RLIMIT_CORE, 0, 0)
            .map_err(|e| SandboxError::CreationFailed(format!("RLIMIT_CORE: {e}")))?;
        setrlimit(Resource::RLIMIT_NOFILE, 256, 512)
            .map_err(|e| SandboxError::CreationFailed(format!("RLIMIT_NOFILE: {e}")))?;
        setrlimit(Resource::RLIMIT_NPROC, 32, 64)
            .map_err(|e| SandboxError::CreationFailed(format!("RLIMIT_NPROC: {e}")))?;
        debug!("Process resource limits applied");
        Ok(())
    }

    fn apply_namespaces(policy: &SandboxPolicy) -> SandboxResult<()> {
        let mut flags = CloneFlags::empty();
        flags.insert(CloneFlags::CLONE_NEWNET);
        if policy.allowed_ports.is_empty() {
            flags.insert(CloneFlags::CLONE_NEWNS);
            flags.insert(CloneFlags::CLONE_NEWPID);
        }
        if policy.max_memory > 0 {
            flags.insert(CloneFlags::CLONE_NEWIPC);
        }
        match sched::unshare(flags) {
            Ok(()) => {
                debug!("Namespaces created: {:?}", flags);
                if flags.contains(CloneFlags::CLONE_NEWNET) {
                    info!("Network namespace isolated");
                }
            }
            Err(e) => {
                warn!("Namespace creation failed (non-fatal): {e}");
            }
        }
        Ok(())
    }
}

#[async_trait]
impl SandboxBackend for ProcessSandbox {
    fn name(&self) -> &'static str {
        "process"
    }

    fn is_available(&self) -> bool {
        cfg!(unix)
    }

    async fn apply_restrictions(&self, policy: &SandboxPolicy) -> SandboxResult<()> {
        Self::apply_resource_limits(policy)?;

        if let Err(e) = Self::apply_namespaces(policy) {
            warn!("Namespace isolation failed (continuing with rlimits): {e}");
        }

        let seccomp_config = seccomp::create_analysis_config(policy);
        match seccomp::apply_seccomp_filter(&seccomp_config) {
            Ok(()) => info!("Process sandbox: resource limits + namespaces + seccomp applied"),
            Err(e) => warn!("Seccomp filter failed (continuing with rlimits): {e}"),
        }

        Ok(())
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

    #[tokio::test]
    async fn test_process_sandbox_restrictions() {
        let sandbox = ProcessSandbox::new();
        let policy = SandboxPolicy::default()
            .with_memory_mb(4096)
            .with_timeout_secs(30);
        let result = sandbox.apply_restrictions(&policy).await;
        assert!(result.is_ok());
    }
}
