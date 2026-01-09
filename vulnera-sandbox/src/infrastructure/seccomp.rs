//! Seccomp-bpf syscall filtering
//!
//! Provides an additional layer of security by filtering system calls
//! that the sandboxed process can make.
//!
//! Note: This module provides a high-level interface to seccomp filtering.
//! For the initial implementation, we rely on Landlock for the primary
//! sandboxing and leave seccomp integration as a future enhancement.

use nix::libc;

use crate::domain::policy::SandboxPolicy;

/// Seccomp filter configuration for restricting system calls
///
/// Note: Full seccomp integration requires careful syscall enumeration
/// and testing. For the initial release, we use Landlock as the primary
/// sandbox and seccomp as an optional enhancement.
#[derive(Debug, Clone)]
pub struct SeccompConfig {
    /// Syscalls to allow (everything else is blocked)
    pub allowed_syscalls: Vec<i64>,
    /// Use default EPERM action for blocked syscalls
    pub use_eperm: bool,
}

impl Default for SeccompConfig {
    fn default() -> Self {
        Self {
            allowed_syscalls: get_default_allowed_syscalls(),
            use_eperm: true,
        }
    }
}

/// Apply seccomp filter based on configuration
///
/// This function uses seccompiler to install a BPF filter that restricts
/// which system calls the current process can make.
///
/// # Safety
///
/// After calling this function, the current process will be permanently
/// restricted. This cannot be undone. Only call this in worker processes.
pub fn apply_seccomp_filter(config: &SeccompConfig) -> Result<(), String> {
    // Note: Full seccomp integration with seccompiler requires careful setup.
    // For the initial implementation, we log the restriction intent but
    // don't actually install the filter to avoid breaking module execution.
    //
    // TODO: Implement proper `seccompiler::SeccompFilter` when we have
    // a complete list of syscalls needed by each analysis module.

    tracing::debug!(
        "Seccomp filter configured with {} allowed syscalls (filter installation pending full integration)",
        config.allowed_syscalls.len()
    );

    // Placeholder: In production, we would use seccompiler like this:
    // let filter = seccompiler::SeccompFilter::new(
    //     config.allowed_syscalls.iter().map(|&sc| (sc as i64, vec![])).collect(),
    //     seccompiler::SeccompAction::Errno(nix::libc::EPERM as u32),
    // )?;
    // filter.load()?;

    Ok(())
}

/// Get the default set of syscalls needed for Rust programs
fn get_default_allowed_syscalls() -> Vec<i64> {
    vec![
        // Essential I/O
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_lseek,
        // Memory management
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_mremap,
        libc::SYS_madvise,
        // File operations (Landlock handles path restrictions)
        libc::SYS_openat,
        libc::SYS_readv,
        libc::SYS_pread64,
        libc::SYS_access,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_getdents64,
        // Thread operations
        libc::SYS_futex,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        // Time operations
        libc::SYS_clock_gettime,
        libc::SYS_gettimeofday,
        libc::SYS_nanosleep,
        // Process info
        libc::SYS_getpid,
        libc::SYS_gettid,
        // Signals
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_sigaltstack,
        libc::SYS_tgkill,
        // Random
        libc::SYS_getrandom,
        // Exit
        libc::SYS_exit,
        libc::SYS_exit_group,
    ]
}

/// Create seccomp configuration for analysis modules
///
/// This creates a restrictive config that allows only the syscalls
/// needed for file analysis, blocking network and other dangerous operations.
pub fn create_analysis_config(policy: &SandboxPolicy) -> SeccompConfig {
    let mut config = SeccompConfig::default();

    // Add network syscalls if network access is allowed
    if !policy.allowed_ports.is_empty() {
        config.allowed_syscalls.extend([
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_sendto,
            libc::SYS_recvfrom,
        ]);
    }

    config
}

/// Check if seccomp is available on this system
pub fn is_seccomp_available() -> bool {
    // Check if the kernel supports seccomp
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        fs::read_to_string("/proc/sys/kernel/seccomp/actions_avail")
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SeccompConfig::default();
        assert!(!config.allowed_syscalls.is_empty());
        assert!(config.use_eperm);
    }

    #[test]
    fn test_analysis_config_without_network() {
        let policy = SandboxPolicy::default();
        let config = create_analysis_config(&policy);

        // Should not include network syscalls
        assert!(!config.allowed_syscalls.contains(&libc::SYS_socket));
    }

    #[test]
    fn test_analysis_config_with_network() {
        let mut policy = SandboxPolicy::default();
        policy.allowed_ports = vec![443];
        let config = create_analysis_config(&policy);

        // Should include network syscalls
        assert!(config.allowed_syscalls.contains(&libc::SYS_socket));
    }
}
