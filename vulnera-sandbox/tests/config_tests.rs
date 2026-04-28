use std::sync::Arc;
use vulnera_sandbox::infrastructure::noop::NoOpSandbox;
use vulnera_sandbox::{
    SandboxBackendPreference, SandboxConfig, SandboxExecutor, SandboxFailureMode, SandboxSelector,
};

#[test]
fn test_default_config_enabled() {
    assert!(SandboxConfig::default().enabled);
}

#[cfg(target_os = "linux")]
#[test]
fn test_default_backend_is_platform_aware() {
    assert_eq!(
        SandboxBackendPreference::platform_default(),
        SandboxBackendPreference::Landlock,
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn test_default_backend_is_platform_aware() {
    assert_eq!(
        SandboxBackendPreference::platform_default(),
        SandboxBackendPreference::Wasm,
    );
}

#[test]
fn test_default_backend_as_str_roundtrip() {
    assert_eq!(SandboxBackendPreference::Landlock.as_str(), "landlock");
    assert_eq!(SandboxBackendPreference::Process.as_str(), "process");
    assert_eq!(SandboxBackendPreference::Wasm.as_str(), "wasm");
    assert_eq!(SandboxBackendPreference::Noop.as_str(), "noop");
}

#[test]
fn test_failure_mode_default() {
    assert_eq!(
        SandboxFailureMode::default(),
        SandboxFailureMode::BestEffort
    );
}

#[test]
fn test_sandbox_config_json_roundtrip() {
    let config = SandboxConfig::default();
    let json = serde_json::to_string(&config).expect("serialize default config");
    let deserialized: SandboxConfig =
        serde_json::from_str(&json).expect("deserialize config from JSON");
    assert_eq!(deserialized.enabled, config.enabled);
    assert_eq!(deserialized.backend, config.backend);
    assert_eq!(deserialized.failure_mode, config.failure_mode);
    assert_eq!(deserialized.timeout_ms, config.timeout_ms);
    assert_eq!(deserialized.max_memory_bytes, config.max_memory_bytes);
    assert_eq!(deserialized.allow_network, config.allow_network);
    assert_eq!(deserialized.dynamic_limits, config.dynamic_limits);
    assert_eq!(deserialized.timeout_per_mb_ms, config.timeout_per_mb_ms);
    assert!((deserialized.memory_per_mb_ratio - config.memory_per_mb_ratio).abs() < f64::EPSILON);
    assert_eq!(
        deserialized.max_memory_cap_bytes,
        config.max_memory_cap_bytes
    );
}

#[test]
fn test_sandbox_config_serde_defaults() {
    let json = r#"{"enabled":true}"#;
    let config: SandboxConfig = serde_json::from_str(json).unwrap_or_else(|e| {
        panic!(
            "SandboxConfig partial deserialization failed: {}. \
             Add #[serde(default)] to the struct definition in config.rs",
            e,
        );
    });
    let default = SandboxConfig::default();
    assert_eq!(config.backend, default.backend);
    assert_eq!(config.failure_mode, default.failure_mode);
    assert_eq!(config.timeout_ms, default.timeout_ms);
    assert_eq!(config.max_memory_bytes, default.max_memory_bytes);
    assert!(!config.allow_network);
    assert!(config.dynamic_limits);
    assert_eq!(config.timeout_per_mb_ms, default.timeout_per_mb_ms);
    assert!((config.memory_per_mb_ratio - default.memory_per_mb_ratio).abs() < f64::EPSILON);
    assert_eq!(config.max_memory_cap_bytes, default.max_memory_cap_bytes);
}

#[cfg(target_os = "linux")]
#[test]
fn test_platform_default_matches_auto_select() {
    if vulnera_sandbox::LandlockSandbox::is_supported() {
        assert_eq!(
            SandboxBackendPreference::platform_default().as_str(),
            SandboxSelector::best_available(),
        );
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn test_platform_default_matches_auto_select() {
    assert_eq!(
        SandboxBackendPreference::platform_default().as_str(),
        SandboxSelector::best_available(),
    );
}

#[test]
fn test_config_disabled_creates_noop_executor() {
    let config = SandboxConfig {
        enabled: false,
        ..SandboxConfig::default()
    };
    let executor = create_executor_from_config(&config);
    assert_eq!(executor.backend_name(), "noop");
    assert!(!executor.strict_mode());
    assert!(executor.is_available());
}

/// Mirrors the executor construction logic from
/// `ExecuteAnalysisJobUseCase::new` (vulnera-orchestrator/src/application/use_cases.rs:124-146).
fn create_executor_from_config(config: &SandboxConfig) -> SandboxExecutor {
    if !config.enabled {
        SandboxExecutor::new(Arc::new(NoOpSandbox::new()))
    } else {
        let backend = match SandboxSelector::select_by_name(config.backend.as_str()) {
            Some(backend) => backend,
            None => SandboxSelector::select(),
        };
        SandboxExecutor::with_options(
            backend,
            matches!(config.failure_mode, SandboxFailureMode::FailClosed),
        )
    }
}
