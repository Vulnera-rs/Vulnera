use crate::config::SandboxConfig;
use std::time::Duration;
use vulnera_contract::domain::module::ModuleType;

#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub timeout: Duration,
    pub max_memory: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(120),
            max_memory: 2 * 1024 * 1024 * 1024,
        }
    }
}

pub fn calculate_limits(
    config: &SandboxConfig,
    source_size_bytes: Option<u64>,
    module_type: ModuleType,
) -> ResourceLimits {
    if !config.dynamic_limits {
        return ResourceLimits {
            timeout: Duration::from_millis(config.timeout_ms),
            max_memory: config.max_memory_bytes,
        };
    }

    let size_mb = source_size_bytes.unwrap_or(0) as f64 / (1024.0 * 1024.0);

    let (timeout_factor, memory_factor) = match module_type {
        ModuleType::DependencyAnalyzer => (2.5, 1.5),
        ModuleType::SAST => (2.0, 2.0),
        ModuleType::SecretDetection => (1.0, 1.0),
        ModuleType::ApiSecurity => (1.0, 1.0),
        _ => (1.5, 1.5),
    };

    let dynamic_timeout_ms =
        config.timeout_ms + (size_mb * config.timeout_per_mb_ms as f64 * timeout_factor) as u64;

    let source_bytes = source_size_bytes.unwrap_or(0) as f64;
    let dynamic_memory = config.max_memory_bytes
        + (source_bytes * config.memory_per_mb_ratio * memory_factor) as u64;

    let capped_memory = dynamic_memory.min(config.max_memory_cap_bytes);

    let final_timeout = Duration::from_millis(dynamic_timeout_ms.clamp(30_000, 600_000));
    let final_memory = capped_memory.max(512 * 1024 * 1024);

    ResourceLimits {
        timeout: final_timeout,
        max_memory: final_memory,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SandboxBackendPreference, SandboxFailureMode};

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
    fn test_small_source_limits() {
        let config = test_config();
        let limits = calculate_limits(&config, Some(1024 * 1024), ModuleType::SecretDetection);
        assert!(limits.timeout.as_secs() <= 90);
        assert!(limits.max_memory >= 512 * 1024 * 1024);
    }

    #[test]
    fn test_large_source_gets_more_resources() {
        let config = test_config();
        let small = calculate_limits(&config, Some(1024 * 1024), ModuleType::SAST);
        let large = calculate_limits(&config, Some(100 * 1024 * 1024), ModuleType::SAST);
        assert!(large.timeout > small.timeout);
        assert!(large.max_memory > small.max_memory);
    }

    #[test]
    fn test_deps_analyzer_gets_more_resources() {
        let config = test_config();
        let sast = calculate_limits(&config, Some(10 * 1024 * 1024), ModuleType::SAST);
        let deps = calculate_limits(
            &config,
            Some(10 * 1024 * 1024),
            ModuleType::DependencyAnalyzer,
        );
        assert!(deps.timeout >= sast.timeout);
    }

    #[test]
    fn test_memory_cap_enforced() {
        let config = test_config();
        let limits = calculate_limits(&config, Some(10 * 1024 * 1024 * 1024), ModuleType::SAST);
        assert!(limits.max_memory <= config.max_memory_cap_bytes);
    }

    #[test]
    fn test_dynamic_limits_disabled() {
        let mut config = test_config();
        config.dynamic_limits = false;
        let limits = calculate_limits(&config, Some(100 * 1024 * 1024), ModuleType::SAST);
        assert_eq!(limits.timeout, Duration::from_millis(config.timeout_ms));
        assert_eq!(limits.max_memory, config.max_memory_bytes);
    }

    #[test]
    fn test_none_source_size() {
        let config = test_config();
        let limits = calculate_limits(&config, None, ModuleType::SAST);
        assert!(limits.timeout.as_millis() >= config.timeout_ms as u128);
    }
}
