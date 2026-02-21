//! Dynamic resource limits calculation
//!
//! Calculates appropriate timeout and memory limits based on:
//! - Source code size
//! - Module type (some modules need more resources)
//! - Base configuration values

use std::time::Duration;

use vulnera_core::config::SandboxConfig;
use vulnera_core::domain::module::ModuleType;

/// Calculated resource limits for sandbox execution
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Execution timeout
    pub timeout: Duration,
    /// Maximum memory in bytes
    pub max_memory: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(120),
            max_memory: 2 * 1024 * 1024 * 1024, // 2GB
        }
    }
}

/// Calculate dynamic resource limits based on source characteristics
///
/// This intelligently adjusts limits to prevent timeouts on large repos
/// while still enforcing reasonable caps on small ones.
///
/// # Arguments
/// * `config` - Base sandbox configuration
/// * `source_size_bytes` - Total size of source code to analyze
/// * `module_type` - Type of analysis module (affects resource needs)
///
/// # Returns
/// Calculated `ResourceLimits` with appropriate timeout and memory
pub fn calculate_limits(
    config: &SandboxConfig,
    source_size_bytes: Option<u64>,
    module_type: ModuleType,
) -> ResourceLimits {
    // If dynamic limits are disabled, use base values
    if !config.dynamic_limits {
        return ResourceLimits {
            timeout: Duration::from_millis(config.timeout_ms),
            max_memory: config.max_memory_bytes,
        };
    }

    let size_mb = source_size_bytes.unwrap_or(0) as f64 / (1024.0 * 1024.0);

    // Module-specific multipliers
    // Some modules are inherently more resource-intensive
    let (timeout_factor, memory_factor) = match module_type {
        ModuleType::DependencyAnalyzer => (2.5, 1.5), // Network I/O, external queries
        ModuleType::SAST => (2.0, 2.0),               // Tree-sitter parsing, data flow
        ModuleType::SecretDetection => (1.0, 1.0),    // Pattern matching, efficient
        ModuleType::ApiSecurity => (1.0, 1.0),        // Schema parsing
        _ => (1.5, 1.5),                              // Other modules get moderate resources
    };

    // Calculate timeout: base + (size_mb * per_mb_rate * factor)
    let dynamic_timeout_ms =
        config.timeout_ms + (size_mb * config.timeout_per_mb_ms as f64 * timeout_factor) as u64;

    // Calculate memory: base + (size_bytes * ratio * factor)
    let source_bytes = source_size_bytes.unwrap_or(0) as f64;
    let dynamic_memory = config.max_memory_bytes
        + (source_bytes * config.memory_per_mb_ratio * memory_factor) as u64;

    // Apply cap to prevent runaway allocation
    let capped_memory = dynamic_memory.min(config.max_memory_cap_bytes);

    // Apply reasonable minimum and maximum bounds
    let final_timeout = Duration::from_millis(dynamic_timeout_ms.clamp(30_000, 600_000)); // 30s - 10min
    let final_memory = capped_memory.max(512 * 1024 * 1024); // Minimum 512MB

    ResourceLimits {
        timeout: final_timeout,
        max_memory: final_memory,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vulnera_core::config::{SandboxBackendPreference, SandboxFailureMode};

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

        // Small source should use close to base values
        assert!(limits.timeout.as_secs() <= 90); // Base 60s + small adjustment
        assert!(limits.max_memory >= 512 * 1024 * 1024); // At least minimum
    }

    #[test]
    fn test_large_source_gets_more_resources() {
        let config = test_config();
        let small = calculate_limits(&config, Some(1024 * 1024), ModuleType::SAST);
        let large = calculate_limits(&config, Some(100 * 1024 * 1024), ModuleType::SAST);

        // Large source should get significantly more time and memory
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

        // DependencyAnalyzer needs more time for network I/O
        assert!(deps.timeout >= sast.timeout);
    }

    #[test]
    fn test_memory_cap_enforced() {
        let config = test_config();
        // Massive source should still be capped
        let limits = calculate_limits(&config, Some(10 * 1024 * 1024 * 1024), ModuleType::SAST);

        assert!(limits.max_memory <= config.max_memory_cap_bytes);
    }

    #[test]
    fn test_dynamic_limits_disabled() {
        let mut config = test_config();
        config.dynamic_limits = false;

        let limits = calculate_limits(&config, Some(100 * 1024 * 1024), ModuleType::SAST);

        // Should use exact base values
        assert_eq!(limits.timeout, Duration::from_millis(config.timeout_ms));
        assert_eq!(limits.max_memory, config.max_memory_bytes);
    }

    #[test]
    fn test_none_source_size() {
        let config = test_config();
        let limits = calculate_limits(&config, None, ModuleType::SAST);

        // Should use base values when size is unknown
        assert!(limits.timeout.as_millis() >= config.timeout_ms as u128);
    }
}
