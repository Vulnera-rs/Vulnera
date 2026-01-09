//! Landlock-based sandbox implementation for Linux 5.13+
//!
//! Landlock is a Linux Security Module that enables unprivileged processes
//! to restrict their own capabilities, providing kernel-enforced sandboxing
//! with near-zero overhead (<1µs).

use async_trait::async_trait;
use landlock::{
    ABI, Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus,
};
use tracing::{debug, info, warn};

use crate::domain::policy::SandboxPolicy;
use crate::domain::traits::{SandboxBackend, SandboxError, SandboxResult};

/// Apply Landlock restrictions to the current process
///
/// This is the main entry point for sandboxing. Call this function
/// to restrict the current process's capabilities based on the policy.
///
/// # Safety
///
/// After calling this function, the current process will be permanently
/// restricted. This cannot be undone. Only call this in worker processes,
/// never in the main orchestrator.
pub fn apply_landlock_restrictions(policy: &SandboxPolicy) -> SandboxResult<()> {
    let sandbox = LandlockSandbox::new();
    sandbox.apply_landlock_rules(policy)?;
    Ok(())
}

/// Landlock-based sandbox for Linux 5.13+
///
/// This is the fastest sandboxing option, using kernel-level restrictions
/// with virtually no performance overhead.
#[derive(Debug)]
pub struct LandlockSandbox {
    /// ABI version to use (V4 includes network restrictions)
    abi: ABI,
}

impl Default for LandlockSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl LandlockSandbox {
    /// Create a new Landlock sandbox
    pub fn new() -> Self {
        Self { abi: ABI::V4 }
    }

    /// Create with a specific ABI version
    pub fn with_abi(abi: ABI) -> Self {
        Self { abi }
    }

    /// Check if Landlock is available on this system
    pub fn is_supported() -> bool {
        Ruleset::default()
            .handle_access(AccessFs::from_all(ABI::V1))
            .and_then(|r| r.create())
            .is_ok()
    }

    /// Apply Landlock restrictions to the current thread (internal)
    fn apply_landlock_rules(&self, policy: &SandboxPolicy) -> SandboxResult<RulesetStatus> {
        // Define filesystem access flags
        let fs_read = AccessFs::ReadFile | AccessFs::ReadDir;
        let fs_write =
            AccessFs::WriteFile | AccessFs::MakeDir | AccessFs::RemoveFile | AccessFs::RemoveDir;

        // Build the ruleset
        let mut ruleset = Ruleset::default()
            .handle_access(AccessFs::from_all(self.abi))
            .map_err(|e| {
                SandboxError::CreationFailed(format!("Failed to handle fs access: {}", e))
            })?;

        // Add network handling if ABI supports it
        if self.abi >= ABI::V4 {
            ruleset = ruleset
                .handle_access(AccessNet::from_all(self.abi))
                .map_err(|e| {
                    SandboxError::CreationFailed(format!("Failed to handle net access: {}", e))
                })?;
        }

        let mut created = ruleset.create().map_err(|e| {
            SandboxError::CreationFailed(format!("Failed to create ruleset: {}", e))
        })?;

        // Add read-only paths
        for path in &policy.readonly_paths {
            if path.exists() {
                let path_fd = PathFd::new(path).map_err(|e| {
                    SandboxError::CreationFailed(format!("Failed to open path {:?}: {}", path, e))
                })?;

                created = created
                    .add_rule(PathBeneath::new(path_fd, fs_read))
                    .map_err(|e| {
                        SandboxError::CreationFailed(format!("Failed to add read rule: {}", e))
                    })?;

                debug!("Added read-only path: {:?}", path);
            } else {
                warn!("Skipping non-existent path: {:?}", path);
            }
        }

        // Add read-write paths
        for path in &policy.readwrite_paths {
            if path.exists() {
                let path_fd = PathFd::new(path).map_err(|e| {
                    SandboxError::CreationFailed(format!("Failed to open path {:?}: {}", path, e))
                })?;

                created = created
                    .add_rule(PathBeneath::new(path_fd, fs_read | fs_write))
                    .map_err(|e| {
                        SandboxError::CreationFailed(format!("Failed to add write rule: {}", e))
                    })?;

                debug!("Added read-write path: {:?}", path);
            }
        }

        // Add network port rules (ABI V4+)
        if self.abi >= ABI::V4 {
            for port in &policy.allowed_ports {
                created = created
                    .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
                    .map_err(|e| {
                        SandboxError::CreationFailed(format!("Failed to add port rule: {}", e))
                    })?;

                debug!("Added allowed port: {}", port);
            }
        }

        // Apply restrictions
        let status = created
            .restrict_self()
            .map_err(|e| SandboxError::CreationFailed(format!("Failed to restrict self: {}", e)))?;

        match status.ruleset {
            RulesetStatus::FullyEnforced => {
                info!("Landlock sandbox fully enforced");
            }
            RulesetStatus::PartiallyEnforced => {
                warn!("Landlock sandbox partially enforced (some features unavailable)");
            }
            RulesetStatus::NotEnforced => {
                return Err(SandboxError::NotSupported(
                    "Landlock not enforced - kernel may be too old".to_string(),
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
        self.apply_landlock_rules(policy)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_landlock_availability_check() {
        // This will return true on Linux 5.13+ with Landlock enabled
        let available = LandlockSandbox::is_supported();
        println!("Landlock available: {}", available);
    }

    #[test]
    fn test_sandbox_creation() {
        let sandbox = LandlockSandbox::new();
        assert_eq!(sandbox.name(), "landlock");
    }
}
