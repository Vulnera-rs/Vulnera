//! Module execution and sandbox configuration tests
//!
//! These tests verify sandbox configuration and execution behavior.

use vulnera_contract::domain::module::ModuleType;
use vulnera_sandbox::{
    SandboxBackendPreference, SandboxConfig, SandboxExecutor, SandboxSelector, calculate_limits,
};

/// Test that sandbox is enabled by default with proper configuration
#[test]
fn test_sandbox_enabled_by_default() {
    let config = SandboxConfig::default();

    assert!(config.enabled, "Sandbox should be enabled by default");
    assert_eq!(
        config.backend,
        SandboxBackendPreference::platform_default(),
        "Backend should default to platform default (Landlock on Linux, WASM otherwise)"
    );
    assert!(
        !config.allow_network,
        "Network should not be allowed by default"
    );
    assert!(
        config.dynamic_limits,
        "Dynamic limits should be enabled by default"
    );
}

/// Test that dynamic limits calculate correctly for different source sizes
#[test]
fn test_dynamic_limits_scale_appropriately() {
    let config = SandboxConfig::default();

    let small = calculate_limits(&config, Some(1024 * 1024), ModuleType::SAST);
    let large = calculate_limits(&config, Some(100 * 1024 * 1024), ModuleType::SAST);

    assert!(
        large.timeout > small.timeout,
        "Large source ({:?}) should get more timeout than small ({:?})",
        large.timeout,
        small.timeout
    );

    assert!(
        large.max_memory > small.max_memory,
        "Large source ({}) should get more memory than small ({})",
        large.max_memory,
        small.max_memory
    );
}

/// Test that SandboxExecutor with noop backend works correctly
#[test]
fn test_noop_executor_available() {
    let backend = SandboxSelector::select_by_name("noop");
    assert!(backend.is_some(), "Noop backend should be selectable");

    let executor = SandboxExecutor::new(backend.unwrap());
    assert!(executor.is_available(), "Noop executor should be available");
    assert_eq!(executor.backend_name(), "noop");
}
