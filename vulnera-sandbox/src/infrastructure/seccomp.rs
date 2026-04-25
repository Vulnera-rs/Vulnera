use nix::libc;
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
use std::convert::TryInto;
use tracing::{debug, info};

use crate::domain::policy::SandboxPolicy;

#[derive(Debug, Clone)]
pub struct SeccompConfig {
    pub allowed_syscalls: Vec<i64>,
    pub deny_action: SeccompAction,
}

impl Default for SeccompConfig {
    fn default() -> Self {
        Self {
            allowed_syscalls: default_allowed_syscalls(),
            deny_action: SeccompAction::Errno(libc::EPERM as u32),
        }
    }
}

pub fn apply_seccomp_filter(config: &SeccompConfig) -> Result<(), String> {
    info!(
        "Applying seccomp filter: {} syscalls allowed",
        config.allowed_syscalls.len()
    );

    let rules: Vec<(i64, Vec<SeccompRule>)> = config
        .allowed_syscalls
        .iter()
        .map(|&s| (s, vec![]))
        .collect();

    let filter = SeccompFilter::new(
        rules.into_iter().collect(),
        config.deny_action.clone(),
        SeccompAction::Allow,
        target_arch(),
    )
    .map_err(|e| format!("create seccomp filter: {e}"))?;

    let bpf: BpfProgram = filter.try_into().map_err(|e| format!("compile BPF: {e}"))?;

    seccompiler::apply_filter(&bpf).map_err(|e| format!("install seccomp: {e}"))?;

    info!("Seccomp filter applied");
    Ok(())
}

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
        compile_error!("Unsupported architecture")
    }
}

fn default_allowed_syscalls() -> Vec<i64> {
    vec![
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
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_mincore,
        libc::SYS_msync,
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
        libc::SYS_ioctl,
        libc::SYS_getcwd,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_set_tid_address,
        libc::SYS_wait4,
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
        libc::SYS_prctl,
        libc::SYS_arch_prctl,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
        libc::SYS_gettimeofday,
        libc::SYS_nanosleep,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_tgkill,
        libc::SYS_getrandom,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_getrlimit,
        libc::SYS_prlimit64,
        libc::SYS_uname,
        libc::SYS_sysinfo,
    ]
}

fn network_syscalls() -> Vec<i64> {
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

pub fn create_analysis_config(policy: &SandboxPolicy) -> SeccompConfig {
    let mut config = SeccompConfig::default();
    if !policy.allowed_ports.is_empty() {
        config.allowed_syscalls.extend(network_syscalls());
        debug!(
            "Added {} network syscalls for port access",
            network_syscalls().len()
        );
    }
    config
}

pub fn is_seccomp_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/kernel/seccomp/actions_avail")
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
        assert!(config.allowed_syscalls.len() > 50);
    }

    #[test]
    fn test_analysis_config_without_network() {
        let policy = SandboxPolicy::default();
        let config = create_analysis_config(&policy);
        assert!(!config.allowed_syscalls.contains(&libc::SYS_socket));
        assert!(!config.allowed_syscalls.contains(&libc::SYS_connect));
    }

    #[test]
    fn test_analysis_config_with_network() {
        let policy = SandboxPolicy::default().with_port(443);
        let config = create_analysis_config(&policy);
        assert!(config.allowed_syscalls.contains(&libc::SYS_socket));
        assert!(config.allowed_syscalls.contains(&libc::SYS_connect));
    }
}
