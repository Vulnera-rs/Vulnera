//! Seccomp-bpf syscall filtering for vulnera-sandbox
//!
//! Provides syscall filtering using Linux seccomp-bpf.
//! This creates a kernel-enforced allowlist of system calls, blocking
//! everything not explicitly permitted with EPERM.
//!
//! # Security Model
//!
//! - Default-deny: All syscalls blocked unless explicitly allowed
//! - Allowlist approach: Only essential syscalls for analysis are permitted
//! - Permanent: Once applied, restrictions cannot be removed
//! - Dual-layer: Works with Landlock for defense-in-depth

use std::convert::TryInto;

use nix::libc;
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
use tracing::{debug, info};

use crate::domain::policy::SandboxPolicy;

/// Seccomp filter configuration for restricting system calls
#[derive(Debug, Clone)]
pub struct SeccompConfig {
    /// Syscalls to allow (everything else is blocked)
    pub allowed_syscalls: Vec<i64>,
    /// Action for blocked syscalls (default: Errno(EPERM))
    pub deny_action: SeccompAction,
}

impl Default for SeccompConfig {
    fn default() -> Self {
        Self {
            allowed_syscalls: get_default_allowed_syscalls(),
            deny_action: SeccompAction::Errno(libc::EPERM as u32),
        }
    }
}

/// Apply seccomp filter based on configuration
///
/// This function installs a BPF filter that blocks all syscalls except
/// those in the allowlist. Blocked syscalls return EPERM.
///
/// # Safety
///
/// After calling this function, the current process will be permanently
/// restricted. This cannot be undone. Only call this in worker processes,
/// never in the main orchestrator.
///
/// # Errors
///
/// Returns an error if:
/// - The filter cannot be compiled
/// - The filter cannot be installed (kernel too old, no permissions)
pub fn apply_seccomp_filter(config: &SeccompConfig) -> Result<(), String> {
    info!(
        "Applying seccomp filter with {} allowed syscalls",
        config.allowed_syscalls.len()
    );

    // Build the allowlist rules
    // Each allowed syscall maps to an empty Vec<SeccompRule> (no argument filtering)
    // which means the syscall is allowed with any arguments
    let rules: Vec<(i64, Vec<SeccompRule>)> = config
        .allowed_syscalls
        .iter()
        .map(|&syscall| (syscall, vec![]))
        .collect();

    debug!("Building seccomp filter with {} rules", rules.len());

    // Create the filter
    // - rules: syscalls to MATCH (trigger match_action)
    // - mismatch_action: what to do when syscall is NOT in rules (Allow for allowlist)
    // - match_action: what to do when syscall IS in rules (DENY in this reversed approach)
    //
    // IMPORTANT: seccompiler uses a "match-based" model where matched syscalls
    // get the match_action. For an allowlist, we want:
    // - matched syscalls (in our list) -> Allow
    // - unmatched syscalls -> Deny (EPERM)
    let filter = SeccompFilter::new(
        rules.into_iter().collect(),
        config.deny_action.clone(), // Default action for unmatched syscalls -> EPERM
        SeccompAction::Allow,       // Action for matched syscalls -> Allow
        target_arch(),
    )
    .map_err(|e| format!("Failed to create seccomp filter: {}", e))?;

    // Compile to BPF program
    let bpf_prog: BpfProgram = filter
        .try_into()
        .map_err(|e| format!("Failed to compile BPF program: {}", e))?;

    // Install the filter
    seccompiler::apply_filter(&bpf_prog)
        .map_err(|e| format!("Failed to install seccomp filter: {}", e))?;

    info!("Seccomp filter applied successfully");
    Ok(())
}

/// Get the target architecture for BPF compilation
fn target_arch() -> seccompiler::TargetArch {
    #[cfg(target_arch = "x86_64")]
    {
        seccompiler::TargetArch::x86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        seccompiler::TargetArch::aarch64
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        compile_error!("Unsupported architecture for seccomp")
    }
}

/// Get the default set of syscalls needed for Rust analysis programs
///
/// This is a carefully curated allowlist that permits:
/// - Basic I/O operations
/// - Memory management
/// - File operations (paths restricted by Landlock)
/// - Thread operations
/// - Time operations
/// - Signal handling
/// - Process exit
///
/// Notably BLOCKED:
/// - Network syscalls (socket, connect, bind, etc.) unless explicitly enabled
/// - Process execution (execve, fork, etc.)
/// - Kernel module operations
/// - Privilege escalation syscalls
fn get_default_allowed_syscalls() -> Vec<i64> {
    vec![
        // === Essential I/O ===
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_lseek,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_pipe,
        libc::SYS_pipe2,
        libc::SYS_poll,
        libc::SYS_ppoll,
        libc::SYS_select,
        libc::SYS_pselect6,
        libc::SYS_epoll_create,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_wait,
        libc::SYS_epoll_pwait,
        libc::SYS_eventfd,
        libc::SYS_eventfd2,
        // === Memory management ===
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_mincore,
        libc::SYS_msync,
        // === File operations (paths restricted by Landlock) ===
        libc::SYS_openat,
        libc::SYS_newfstatat,
        libc::SYS_access,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_fstatfs,
        libc::SYS_statfs,
        libc::SYS_readlink,
        libc::SYS_readlinkat,
        libc::SYS_getdents,
        libc::SYS_getdents64,
        libc::SYS_fcntl,
        libc::SYS_flock,
        libc::SYS_ioctl, // Needed for terminal operations
        libc::SYS_getcwd,
        // === Thread/process operations (limited) ===
        libc::SYS_futex,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_rseq,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_getppid,
        libc::SYS_getuid,
        libc::SYS_getgid,
        libc::SYS_geteuid,
        libc::SYS_getegid,
        libc::SYS_getgroups,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_prctl, // Needed for thread naming, etc.
        libc::SYS_arch_prctl,
        // === Time operations ===
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
        libc::SYS_gettimeofday,
        libc::SYS_nanosleep,
        // === Signals ===
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_tgkill,
        // === Random ===
        libc::SYS_getrandom,
        // === Exit ===
        libc::SYS_exit,
        libc::SYS_exit_group,
        // === Resource limits (read only) ===
        libc::SYS_getrlimit,
        libc::SYS_prlimit64,
        // === Misc ===
        libc::SYS_uname,
        libc::SYS_sysinfo,
    ]
}

/// Get syscalls needed for network operations
fn get_network_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_shutdown,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
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
        config.allowed_syscalls.extend(get_network_syscalls());
        debug!(
            "Added {} network syscalls for {} allowed ports",
            get_network_syscalls().len(),
            policy.allowed_ports.len()
        );
    }

    config
}

/// Check if seccomp is available on this system
pub fn is_seccomp_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        fs::read_to_string("/proc/sys/kernel/seccomp/actions_avail")
            .map(|s| s.contains("allow") && s.contains("errno"))
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
        // Should have a decent number of syscalls
        assert!(config.allowed_syscalls.len() > 50);
    }

    #[test]
    fn test_analysis_config_without_network() {
        let policy = SandboxPolicy::default();
        let config = create_analysis_config(&policy);

        // Should not include network syscalls
        assert!(!config.allowed_syscalls.contains(&libc::SYS_socket));
        assert!(!config.allowed_syscalls.contains(&libc::SYS_connect));
    }

    #[test]
    fn test_analysis_config_with_network() {
        let mut policy = SandboxPolicy::default();
        policy.allowed_ports = vec![443];
        let config = create_analysis_config(&policy);

        // Should include network syscalls
        assert!(config.allowed_syscalls.contains(&libc::SYS_socket));
        assert!(config.allowed_syscalls.contains(&libc::SYS_connect));
    }

    #[test]
    fn test_seccomp_availability() {
        let available = is_seccomp_available();
        println!("Seccomp available: {}", available);
        // Just check it doesn't panic
    }

    #[test]
    fn test_target_arch() {
        let arch = target_arch();
        #[cfg(target_arch = "x86_64")]
        assert!(matches!(arch, seccompiler::TargetArch::x86_64));
        #[cfg(target_arch = "aarch64")]
        assert!(matches!(arch, seccompiler::TargetArch::aarch64));
    }
}
