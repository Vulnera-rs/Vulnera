//! Module execution tests
//!
//! These tests verify that each analysis module can execute correctly
//! within the sandbox environment (with noop backend by default).

use std::collections::HashMap;
use vulnera_api::module::ApiSecurityModule;
use vulnera_core::config::{ApiSecurityConfig, SandboxConfig, SastConfig, SecretDetectionConfig};
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig, ModuleType};
use vulnera_sandbox::{SandboxExecutor, SandboxSelector, calculate_limits};
use vulnera_sast::module::SastModule;
use vulnera_secrets::module::SecretDetectionModule;

/// Test that SAST module executes correctly without sandbox restrictions
#[tokio::test]
async fn test_sast_module_executes_without_sandbox() {
    let module = SastModule::with_config(&SastConfig::default());

    let config = ModuleConfig {
        job_id: uuid::Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: ".".to_string(), // Current directory
        config: HashMap::new(),
    };

    // Execute directly without sandbox (noop mode)
    let result = module.execute(&config).await;

    // Should complete without error (may or may not find findings)
    assert!(
        result.is_ok(),
        "SAST module should execute successfully: {:?}",
        result.err()
    );

    let module_result = result.unwrap();
    assert_eq!(module_result.module_type, ModuleType::SAST);
    assert!(module_result.error.is_none());
}

/// Test that SecretDetection module executes correctly
#[tokio::test]
async fn test_secrets_module_executes_without_sandbox() {
    let module = SecretDetectionModule::with_config(&SecretDetectionConfig::default());

    let config = ModuleConfig {
        job_id: uuid::Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: ".".to_string(),
        config: HashMap::new(),
    };

    let result = module.execute(&config).await;

    assert!(
        result.is_ok(),
        "Secrets module should execute successfully: {:?}",
        result.err()
    );

    let module_result = result.unwrap();
    assert_eq!(module_result.module_type, ModuleType::SecretDetection);
    assert!(module_result.error.is_none());
}

/// Test that ApiSecurity module executes correctly
#[tokio::test]
async fn test_api_module_executes_without_sandbox() {
    let module = ApiSecurityModule::with_config(&ApiSecurityConfig::default());

    let config = ModuleConfig {
        job_id: uuid::Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: ".".to_string(),
        config: HashMap::new(),
    };

    let result = module.execute(&config).await;

    // ApiSecurity may or may not find OpenAPI specs, but should not error
    assert!(
        result.is_ok(),
        "API module should execute successfully: {:?}",
        result.err()
    );

    let module_result = result.unwrap();
    assert_eq!(module_result.module_type, ModuleType::ApiSecurity);
    assert!(module_result.error.is_none());
}

/// Test that sandbox is enabled by default with proper configuration
#[test]
fn test_sandbox_enabled_by_default() {
    let config = SandboxConfig::default();

    assert!(config.enabled, "Sandbox should be enabled by default");
    assert_eq!(config.backend, "auto", "Backend should default to auto");
    assert!(
        config.allow_network,
        "Network should be allowed for DependencyAnalyzer"
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

    let small = calculate_limits(&config, Some(1 * 1024 * 1024), ModuleType::SAST);
    let large = calculate_limits(&config, Some(100 * 1024 * 1024), ModuleType::SAST);

    // Larger source should get more time
    assert!(
        large.timeout > small.timeout,
        "Large source ({:?}) should get more timeout than small ({:?})",
        large.timeout,
        small.timeout
    );

    // Larger source should get more memory
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
