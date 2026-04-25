use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use vulnera_contract::domain::module::ModuleType;
use vulnera_sandbox::infrastructure::noop::NoOpSandbox;
use vulnera_sandbox::{
    SandboxBackendPreference, SandboxConfig, SandboxError, SandboxExecutor, SandboxFailureMode,
    SandboxPolicy, SandboxPolicyProfile, SandboxSelector, SandboxedExecutionError,
    calculate_limits,
};

fn test_config() -> SandboxConfig {
    SandboxConfig {
        enabled: false,
        backend: SandboxBackendPreference::Noop,
        failure_mode: SandboxFailureMode::BestEffort,
        timeout_ms: 60_000,
        max_memory_bytes: 1024 * 1024 * 1024,
        allow_network: true,
        dynamic_limits: true,
        timeout_per_mb_ms: 200,
        memory_per_mb_ratio: 10.0,
        max_memory_cap_bytes: 8 * 1024 * 1024 * 1024,
    }
}

#[test]
fn test_executor_default_creates_auto_backend() {
    let executor = SandboxExecutor::default();
    assert!(executor.is_available());
}

#[test]
fn test_executor_auto_creates_available_backend() {
    let executor = SandboxExecutor::auto();
    assert!(executor.is_available());
}

#[test]
fn test_executor_backend_name_not_empty() {
    let executor = SandboxExecutor::auto();
    assert!(!executor.backend_name().is_empty());
}

#[test]
fn test_executor_new_with_noop() {
    let executor = SandboxExecutor::new(Arc::new(NoOpSandbox::new()));
    assert_eq!(executor.backend_name(), "noop");
}

#[test]
fn test_executor_strict_mode_default_false() {
    let executor = SandboxExecutor::default();
    assert!(!executor.strict_mode());
}

#[test]
fn test_executor_with_options_sets_strict_mode() {
    let backend = SandboxSelector::select_by_name("noop").unwrap();
    let executor = SandboxExecutor::with_options(backend, true);
    assert!(executor.strict_mode());
}

#[test]
fn test_sandbox_policy_default_profile_readonly() {
    let policy = SandboxPolicy::default()
        .with_http_access()
        .with_profile(SandboxPolicyProfile::ReadOnlyAnalysis);
    assert!(policy.allowed_ports.is_empty());
}

#[test]
fn test_sandbox_policy_dependency_profile() {
    let policy =
        SandboxPolicy::default().with_profile(SandboxPolicyProfile::DependencyResolution {
            include_cache_port: true,
        });
    assert!(policy.allowed_ports.contains(&80));
    assert!(policy.allowed_ports.contains(&443));
    assert!(policy.allowed_ports.contains(&6379));
}

#[test]
fn test_sandbox_policy_dependency_no_cache() {
    let policy =
        SandboxPolicy::default().with_profile(SandboxPolicyProfile::DependencyResolution {
            include_cache_port: false,
        });
    assert!(policy.allowed_ports.contains(&80));
    assert!(policy.allowed_ports.contains(&443));
    assert!(!policy.allowed_ports.contains(&6379));
}

#[test]
fn test_limits_calculate_returns_reasonable_values() {
    let config = test_config();
    let limits = calculate_limits(&config, Some(10 * 1024 * 1024), ModuleType::SAST);
    assert!(
        limits.timeout >= Duration::from_secs(30),
        "timeout should be at least 30s, got {:?}",
        limits.timeout
    );
    assert!(
        limits.timeout <= Duration::from_secs(600),
        "timeout should be at most 600s, got {:?}",
        limits.timeout
    );
    assert!(
        limits.max_memory >= 512 * 1024 * 1024,
        "memory should be at least 512MB, got {}",
        limits.max_memory
    );
}

#[test]
fn test_limits_none_source_uses_base() {
    let config = test_config();
    let limits = calculate_limits(&config, None, ModuleType::SecretDetection);
    assert!(
        limits.max_memory >= 512 * 1024 * 1024,
        "memory should be at least 512MB"
    );
    assert!(
        limits.timeout.as_millis() >= config.timeout_ms as u128,
        "timeout should at least match base timeout"
    );
}

#[test]
fn test_limits_capped_at_max() {
    let config = test_config();
    let limits = calculate_limits(&config, Some(10 * 1024 * 1024 * 1024), ModuleType::SAST);
    assert!(
        limits.max_memory <= config.max_memory_cap_bytes,
        "memory {} should not exceed cap {}",
        limits.max_memory,
        config.max_memory_cap_bytes
    );
}

#[test]
fn test_policy_for_analysis_includes_tmp() {
    let policy = SandboxPolicy::for_analysis("/tmp/foo");
    assert!(policy.readwrite_paths.contains(&PathBuf::from("/tmp")));
}

#[test]
fn test_policy_for_analysis_includes_source() {
    let policy = SandboxPolicy::for_analysis("/tmp/foo");
    assert!(policy.readonly_paths.contains(&PathBuf::from("/tmp/foo")));
}

#[test]
fn test_policy_with_temp_access_dedup() {
    let policy = SandboxPolicy::default()
        .with_temp_access()
        .with_temp_access();
    let count = policy
        .readwrite_paths
        .iter()
        .filter(|p| *p == &PathBuf::from("/tmp"))
        .count();
    assert_eq!(count, 1, "expected exactly one /tmp entry, got {count}");
}

#[test]
fn test_sandboxed_execution_error_display_sandbox() {
    let err = SandboxError::NotSupported("no kernel support".into());
    let exec_err = SandboxedExecutionError::Sandbox(err);
    assert_eq!(
        exec_err.to_string(),
        "Sandbox error: Sandbox not supported: no kernel support"
    );
}

#[test]
fn test_sandboxed_execution_error_display_timeout() {
    let dur = Duration::from_secs(30);
    let exec_err = SandboxedExecutionError::Timeout(dur);
    assert_eq!(exec_err.to_string(), "Execution timed out after 30s");
}

#[test]
fn test_sandboxed_execution_error_from_sandbox_error() {
    fn convert_via_question() -> Result<(), SandboxedExecutionError> {
        let result: Result<(), SandboxError> = Err(SandboxError::NotSupported("via ?".into()));
        let _ = result?;
        Ok(())
    }
    let result = convert_via_question();
    assert!(result.is_err());
    let display = result.unwrap_err().to_string();
    assert!(display.contains("Sandbox error"));
    assert!(display.contains("via ?"));
}
