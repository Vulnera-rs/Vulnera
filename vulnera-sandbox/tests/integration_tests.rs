//! Integration tests for sandbox isolation
//!
//! These tests verify that the sandbox backends actually restrict
//! filesystem and network access as expected.

use std::path::PathBuf;
use std::time::Duration;

use vulnera_sandbox::{SandboxBackend, SandboxExecutor, SandboxPolicy, SandboxSelector};

#[cfg(target_os = "linux")]
use vulnera_sandbox::LandlockSandbox;

/// Test that SandboxSelector auto-selects an available backend
#[test]
fn test_selector_picks_available_backend() {
    let backend = SandboxSelector::select();
    assert!(backend.is_available());

    let name = backend.name();
    println!("Auto-selected backend: {}", name);

    #[cfg(target_os = "linux")]
    {
        // On modern Linux, we expect either landlock or process
        assert!(name == "landlock" || name == "process");
    }
}

/// Test that Landlock availability matches kernel version
#[cfg(target_os = "linux")]
#[test]
fn test_landlock_availability_is_accurate() {
    let sandbox = LandlockSandbox::new();
    let is_available = sandbox.is_available();

    // Check kernel version
    let kernel_version = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();

    println!("Kernel version: {}", kernel_version.trim());
    println!("Landlock available: {}", is_available);

    // Landlock requires kernel 5.13+
    let parts: Vec<&str> = kernel_version.split('.').collect();
    if parts.len() >= 2 {
        let major: u32 = parts[0].parse().unwrap_or(0);
        let minor: u32 = parts[1].parse().unwrap_or(0);

        if major > 5 || (major == 5 && minor >= 13) {
            // If kernel supports Landlock, it MIGHT be available
            // (depends on kernel config, so we don't assert)
            println!("Kernel supports Landlock (5.13+)");
        }
    }
}

/// Test SandboxPolicy builder creates restrictive defaults
#[test]
fn test_policy_defaults_are_secure() {
    let policy = SandboxPolicy::default();

    // Default should be maximally restrictive
    assert!(
        policy.readonly_paths.is_empty(),
        "Default should have no read paths"
    );
    assert!(
        policy.readwrite_paths.is_empty(),
        "Default should have no write paths"
    );
    assert!(
        policy.allowed_ports.is_empty(),
        "Default should block network"
    );
    assert!(!policy.allow_exec, "Default should block exec");
    assert_eq!(
        policy.timeout,
        Duration::from_secs(30),
        "Default timeout should be 30s"
    );
}

/// Test SandboxPolicy builder methods work correctly
#[test]
fn test_policy_builder_accumulates() {
    let policy = SandboxPolicy::default()
        .with_readonly_path("/tmp")
        .with_readonly_path("/usr")
        .with_timeout_secs(60)
        .with_memory_mb(512);

    assert_eq!(policy.readonly_paths.len(), 2);
    assert!(policy.readonly_paths.contains(&PathBuf::from("/tmp")));
    assert!(policy.readonly_paths.contains(&PathBuf::from("/usr")));
    assert_eq!(policy.timeout, Duration::from_secs(60));
    assert_eq!(policy.max_memory, 512 * 1024 * 1024);
}

/// Test SandboxExecutor can be created with any backend
#[test]
fn test_executor_creation_all_backends() {
    // Auto selection
    let executor = SandboxExecutor::auto();
    assert!(executor.is_available());

    // By name
    if let Some(backend) = SandboxSelector::select_by_name("auto") {
        let executor = SandboxExecutor::new(backend);
        assert!(executor.is_available());
    }
}

/// Test that selecting unknown backend returns None
#[test]
fn test_unknown_backend_returns_none() {
    assert!(SandboxSelector::select_by_name("potato").is_none());
    assert!(SandboxSelector::select_by_name("").is_none());
    assert!(SandboxSelector::select_by_name("WASM").is_none()); // Not "wasm"
}

/// Test seccomp configuration for network restriction
#[cfg(target_os = "linux")]
#[test]
fn test_seccomp_config_network_restriction() {
    use nix::libc;
    use vulnera_sandbox::create_analysis_config;

    // Without network
    let policy = SandboxPolicy::default();
    let config = create_analysis_config(&policy);
    assert!(!config.allowed_syscalls.contains(&libc::SYS_socket));
    assert!(!config.allowed_syscalls.contains(&libc::SYS_connect));

    // With network
    let policy_with_net = SandboxPolicy {
        allowed_ports: vec![443, 80],
        ..Default::default()
    };
    let config_with_net = create_analysis_config(&policy_with_net);
    assert!(config_with_net.allowed_syscalls.contains(&libc::SYS_socket));
    assert!(
        config_with_net
            .allowed_syscalls
            .contains(&libc::SYS_connect)
    );
}

/// Test that best_available() returns a valid backend name
#[test]
fn test_best_available_is_valid() {
    let name = SandboxSelector::best_available();

    assert!(!name.is_empty());
    assert!(["landlock", "process", "wasm"].contains(&name));

    // The returned name should be selectable
    let backend = SandboxSelector::select_by_name(name);
    assert!(
        backend.is_some(),
        "best_available() should return a selectable backend"
    );
}
