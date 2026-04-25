use async_trait::async_trait;
use landlock::{
    ABI, Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus,
};
use tracing::{debug, info, warn};

use crate::domain::policy::SandboxPolicy;
use crate::domain::traits::{SandboxBackend, SandboxError, SandboxResult};

#[derive(Debug)]
pub struct LandlockSandbox {
    abi: ABI,
}

impl Default for LandlockSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl LandlockSandbox {
    pub fn new() -> Self {
        Self { abi: ABI::V4 }
    }

    pub fn with_abi(abi: ABI) -> Self {
        Self { abi }
    }

    pub fn is_supported() -> bool {
        Ruleset::default()
            .handle_access(AccessFs::from_all(ABI::V1))
            .and_then(|r| r.create())
            .is_ok()
    }

    fn landlock_restrict(&self, policy: &SandboxPolicy) -> SandboxResult<RulesetStatus> {
        let fs_read = AccessFs::ReadFile | AccessFs::ReadDir;
        let fs_write =
            AccessFs::WriteFile | AccessFs::MakeDir | AccessFs::RemoveFile | AccessFs::RemoveDir;

        let mut ruleset = Ruleset::default()
            .handle_access(AccessFs::from_all(self.abi))
            .map_err(|e| SandboxError::CreationFailed(format!("handle_access fs: {e}")))?;

        if self.abi >= ABI::V4 {
            ruleset = ruleset
                .handle_access(AccessNet::from_all(self.abi))
                .map_err(|e| SandboxError::CreationFailed(format!("handle_access net: {e}")))?;
        }

        let mut created = ruleset
            .create()
            .map_err(|e| SandboxError::CreationFailed(format!("create ruleset: {e}")))?;

        for path in &policy.readonly_paths {
            if path.exists() {
                let fd = PathFd::new(path)
                    .map_err(|e| SandboxError::CreationFailed(format!("open {:?}: {e}", path)))?;
                created = created
                    .add_rule(PathBeneath::new(fd, fs_read))
                    .map_err(|e| SandboxError::CreationFailed(format!("add read rule: {e}")))?;
                debug!("Landlock RO: {:?}", path);
            }
        }

        for path in &policy.readwrite_paths {
            if path.exists() {
                let fd = PathFd::new(path)
                    .map_err(|e| SandboxError::CreationFailed(format!("open {:?}: {e}", path)))?;
                created = created
                    .add_rule(PathBeneath::new(fd, fs_read | fs_write))
                    .map_err(|e| SandboxError::CreationFailed(format!("add write rule: {e}")))?;
                debug!("Landlock RW: {:?}", path);
            }
        }

        if self.abi >= ABI::V4 {
            for port in &policy.allowed_ports {
                created = created
                    .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
                    .map_err(|e| SandboxError::CreationFailed(format!("add port {port}: {e}")))?;
                debug!("Landlock port: {}", port);
            }
        }

        let status = created
            .restrict_self()
            .map_err(|e| SandboxError::CreationFailed(format!("restrict_self: {e}")))?;

        match status.ruleset {
            RulesetStatus::FullyEnforced => info!("Landlock fully enforced"),
            RulesetStatus::PartiallyEnforced => warn!("Landlock partially enforced"),
            RulesetStatus::NotEnforced => {
                return Err(SandboxError::NotSupported(
                    "Landlock not enforced by kernel".into(),
                ));
            }
        }

        Ok(status.ruleset)
    }
}

#[async_trait]
impl SandboxBackend for LandlockSandbox {
    fn name(&self) -> &'static str {
        "landlock"
    }

    fn is_available(&self) -> bool {
        Self::is_supported()
    }

    async fn apply_restrictions(&self, policy: &SandboxPolicy) -> SandboxResult<()> {
        self.landlock_restrict(policy)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_landlock_availability() {
        let available = LandlockSandbox::is_supported();
        println!("Landlock available: {available}");
    }

    #[test]
    fn test_sandbox_creation() {
        let sandbox = LandlockSandbox::new();
        assert_eq!(sandbox.name(), "landlock");
    }
}
