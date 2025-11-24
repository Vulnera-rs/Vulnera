//! Configuration validation module

use crate::config::{
    AnalysisConfig, ApiConfig, ApiSecurityConfig, AuthConfig, CacheConfig, DatabaseConfig,
    GhsaConfig, GitHubConfig, NvdConfig, SecretDetectionConfig, ServerConfig,
};

/// Trait for validating configuration sections
pub trait Validate {
    fn validate(&self) -> Result<(), ValidationError>;
}

/// Configuration validation error
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Server configuration error: {message}")]
    Server { message: String },

    #[error("Cache configuration error: {message}")]
    Cache { message: String },

    #[error("API configuration error: {message}")]
    Api { message: String },

    #[error("Analysis configuration error: {message}")]
    Analysis { message: String },

    #[error("Authentication configuration error: {message}")]
    Auth { message: String },

    #[error("Database configuration error: {message}")]
    Database { message: String },

    #[error("Secret detection configuration error: {message}")]
    SecretDetection { message: String },
}

impl ValidationError {
    pub fn server(message: impl Into<String>) -> Self {
        Self::Server {
            message: message.into(),
        }
    }

    pub fn cache(message: impl Into<String>) -> Self {
        Self::Cache {
            message: message.into(),
        }
    }

    pub fn api(message: impl Into<String>) -> Self {
        Self::Api {
            message: message.into(),
        }
    }

    pub fn analysis(message: impl Into<String>) -> Self {
        Self::Analysis {
            message: message.into(),
        }
    }

    pub fn auth(message: impl Into<String>) -> Self {
        Self::Auth {
            message: message.into(),
        }
    }

    pub fn database(message: impl Into<String>) -> Self {
        Self::Database {
            message: message.into(),
        }
    }

    pub fn secret_detection(message: impl Into<String>) -> Self {
        Self::SecretDetection {
            message: message.into(),
        }
    }
}

impl Validate for ServerConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        // Validate port range (1-65535)
        // Note: u16 cannot exceed 65535, so we only need to check for 0
        if self.port == 0 {
            return Err(ValidationError::server(format!(
                "Port must be in range 1-65535, got {}",
                self.port
            )));
        }

        // Validate host format (basic check - not empty)
        if self.host.is_empty() {
            return Err(ValidationError::server("Host cannot be empty".to_string()));
        }

        // Validate timeout > 0
        if self.request_timeout_seconds == 0 {
            return Err(ValidationError::server(
                "Request timeout must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }
}

impl Validate for CacheConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        // Validate TTL > 0
        if self.ttl_hours == 0 {
            return Err(ValidationError::cache(
                "Cache TTL must be greater than 0 hours".to_string(),
            ));
        }

        Ok(())
    }
}

impl Validate for NvdConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        // Validate URL format
        if !self.base_url.starts_with("http://") && !self.base_url.starts_with("https://") {
            return Err(ValidationError::api(format!(
                "NVD base_url must start with http:// or https://, got: {}",
                self.base_url
            )));
        }

        // Validate timeout > 0
        if self.timeout_seconds == 0 {
            return Err(ValidationError::api(
                "NVD timeout must be greater than 0 seconds".to_string(),
            ));
        }

        // Validate rate limit > 0
        if self.rate_limit_per_30s == 0 {
            return Err(ValidationError::api(
                "NVD rate_limit_per_30s must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }
}

impl Validate for GhsaConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        // Validate URL format
        if !self.graphql_url.starts_with("http://") && !self.graphql_url.starts_with("https://") {
            return Err(ValidationError::api(format!(
                "GHSA graphql_url must start with http:// or https://, got: {}",
                self.graphql_url
            )));
        }

        // Validate timeout > 0
        if self.timeout_seconds == 0 {
            return Err(ValidationError::api(
                "GHSA timeout must be greater than 0 seconds".to_string(),
            ));
        }

        Ok(())
    }
}

impl Validate for GitHubConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        // Validate URL format
        if !self.base_url.starts_with("http://") && !self.base_url.starts_with("https://") {
            return Err(ValidationError::api(format!(
                "GitHub base_url must start with http:// or https://, got: {}",
                self.base_url
            )));
        }

        // Validate timeout > 0
        if self.timeout_seconds == 0 {
            return Err(ValidationError::api(
                "GitHub timeout must be greater than 0 seconds".to_string(),
            ));
        }

        // Validate max_concurrent_file_fetches > 0
        if self.max_concurrent_file_fetches == 0 {
            return Err(ValidationError::api(
                "GitHub max_concurrent_file_fetches must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }
}

impl Validate for ApiConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        self.nvd.validate()?;
        self.ghsa.validate()?;
        self.github.validate()?;
        Ok(())
    }
}

impl Validate for AnalysisConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        // Validate max_concurrent_packages > 0
        if self.max_concurrent_packages == 0 {
            return Err(ValidationError::analysis(
                "max_concurrent_packages must be greater than 0".to_string(),
            ));
        }

        if self.job_queue_capacity == 0 {
            return Err(ValidationError::analysis(
                "job_queue_capacity must be greater than 0".to_string(),
            ));
        }

        if self.max_job_workers == 0 {
            return Err(ValidationError::analysis(
                "max_job_workers must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }
}

impl Validate for AuthConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        // Validate JWT secret length (at least 32 characters in production)
        // In development, we allow shorter secrets for convenience
        if self.jwt_secret.len() < 16 {
            return Err(ValidationError::auth(
                "JWT secret must be at least 16 characters long".to_string(),
            ));
        }

        // Validate token TTL > 0
        if self.token_ttl_hours == 0 {
            return Err(ValidationError::auth(
                "Access token TTL must be greater than 0 hours".to_string(),
            ));
        }

        // Validate refresh token TTL > 0
        if self.refresh_token_ttl_hours == 0 {
            return Err(ValidationError::auth(
                "Refresh token TTL must be greater than 0 hours".to_string(),
            ));
        }

        // Validate API key length (16-128 bytes)
        if self.api_key_length < 16 || self.api_key_length > 128 {
            return Err(ValidationError::auth(
                "API key length must be between 16 and 128 bytes".to_string(),
            ));
        }

        Ok(())
    }
}

impl Validate for DatabaseConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        // Validate database URL is not empty
        if self.url.is_empty() {
            return Err(ValidationError::database(
                "Database URL cannot be empty".to_string(),
            ));
        }

        // Validate URL format (basic check)
        if !self.url.starts_with("postgres://") && !self.url.starts_with("postgresql://") {
            return Err(ValidationError::database(
                "Database URL must start with postgres:// or postgresql://".to_string(),
            ));
        }

        // Validate max_connections > 0
        if self.max_connections == 0 {
            return Err(ValidationError::database(
                "Max connections must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }
}

impl Validate for SecretDetectionConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        // Validate max_scan_depth > 0
        if self.max_scan_depth == 0 {
            return Err(ValidationError::secret_detection(
                "max_scan_depth must be greater than 0".to_string(),
            ));
        }

        // Validate entropy thresholds are reasonable (0.0 to 8.0)
        if self.base64_entropy_threshold < 0.0 || self.base64_entropy_threshold > 8.0 {
            return Err(ValidationError::secret_detection(
                "base64_entropy_threshold must be between 0.0 and 8.0".to_string(),
            ));
        }

        if self.hex_entropy_threshold < 0.0 || self.hex_entropy_threshold > 8.0 {
            return Err(ValidationError::secret_detection(
                "hex_entropy_threshold must be between 0.0 and 8.0".to_string(),
            ));
        }

        // Validate max_file_size_bytes > 0
        if self.max_file_size_bytes == 0 {
            return Err(ValidationError::secret_detection(
                "max_file_size_bytes must be greater than 0".to_string(),
            ));
        }

        // Validate verification_concurrent_limit > 0 if verification is enabled
        if self.enable_verification && self.verification_concurrent_limit == 0 {
            return Err(ValidationError::secret_detection(
                "verification_concurrent_limit must be greater than 0 when verification is enabled"
                    .to_string(),
            ));
        }

        // Validate verification_timeout_seconds > 0 if verification is enabled
        if self.enable_verification && self.verification_timeout_seconds == 0 {
            return Err(ValidationError::secret_detection(
                "verification_timeout_seconds must be greater than 0 when verification is enabled"
                    .to_string(),
            ));
        }

        // Validate max_commits_to_scan > 0 if Some
        if let Some(max_commits) = self.max_commits_to_scan {
            if max_commits == 0 {
                return Err(ValidationError::secret_detection(
                    "max_commits_to_scan must be greater than 0 if specified".to_string(),
                ));
            }
        }

        // Validate file_read_timeout_seconds > 0
        if self.file_read_timeout_seconds == 0 {
            return Err(ValidationError::secret_detection(
                "file_read_timeout_seconds must be greater than 0".to_string(),
            ));
        }

        // Validate scan_timeout_seconds > 0 if Some
        if let Some(scan_timeout) = self.scan_timeout_seconds {
            if scan_timeout == 0 {
                return Err(ValidationError::secret_detection(
                    "scan_timeout_seconds must be greater than 0 if specified".to_string(),
                ));
            }
        }

        Ok(())
    }
}

impl Validate for ApiSecurityConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        // Validate severity override values are valid
        for (vuln_type, severity_str) in &self.severity_overrides {
            let severity_lower = severity_str.to_lowercase();
            if !matches!(
                severity_lower.as_str(),
                "critical" | "high" | "medium" | "low" | "info"
            ) {
                return Err(ValidationError::server(format!(
                    "Invalid severity override for {}: {}. Must be one of: critical, high, medium, low, info",
                    vuln_type, severity_str
                )));
            }
        }

        // Validate analyzer names if specified
        let valid_analyzers = [
            "authentication",
            "authorization",
            "input_validation",
            "data_exposure",
            "design",
            "security_headers",
            "oauth",
        ];
        for analyzer in &self.enabled_analyzers {
            let analyzer_lower = analyzer.to_lowercase();
            let is_valid = valid_analyzers.iter().any(|valid| {
                analyzer_lower == *valid || analyzer_lower == format!("{}_analyzer", valid)
            });
            if !is_valid {
                return Err(ValidationError::server(format!(
                    "Unknown analyzer: {}. Valid analyzers are: {}",
                    analyzer,
                    valid_analyzers.join(", ")
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CacheConfig, ServerConfig};

    #[test]
    fn test_server_config_validation() {
        // Valid config
        let valid = ServerConfig {
            host: "0.0.0.0".to_string(),
            port: 3000,
            workers: None,
            enable_docs: true,
            request_timeout_seconds: 30,
            allowed_origins: vec![],
            security: crate::config::SecurityConfig::default(),
            rate_limit: crate::config::RateLimitConfig::default(),
        };
        assert!(valid.validate().is_ok());

        // Invalid port (0)
        let invalid = ServerConfig {
            port: 0,
            ..valid.clone()
        };
        assert!(invalid.validate().is_err());

        // Port 65535 is valid (max u16 value)
        // Note: u16 cannot exceed 65535, so we can't test "too high" port

        // Invalid timeout (0)
        let invalid = ServerConfig {
            request_timeout_seconds: 0,
            ..valid.clone()
        };
        assert!(invalid.validate().is_err());

        // Invalid host (empty)
        let invalid = ServerConfig {
            host: String::new(),
            ..valid
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_cache_config_validation() {
        let valid = CacheConfig {
            ttl_hours: 24,
            l1_cache_size_mb: 100,
            l1_cache_ttl_seconds: 300,
            enable_cache_compression: true,
            compression_threshold_bytes: 10240,
            dragonfly_enabled: true,
            dragonfly_url: "redis://127.0.0.1:6379".to_string(),
            dragonfly_connection_pool_size: Some(16),
            dragonfly_connection_timeout_seconds: 5,
        };
        assert!(valid.validate().is_ok());

        // Invalid TTL (0)
        let invalid = CacheConfig {
            ttl_hours: 0,
            ..valid.clone()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_nvd_config_validation() {
        // Valid config
        let valid = NvdConfig {
            base_url: "https://services.nvd.nist.gov/rest/json".to_string(),
            api_key: None,
            timeout_seconds: 30,
            rate_limit_per_30s: 5,
            circuit_breaker: crate::config::CircuitBreakerConfigSerializable::default(),
            retry: crate::config::RetryConfigSerializable::default(),
        };
        assert!(valid.validate().is_ok());

        // Invalid URL
        let invalid = NvdConfig {
            base_url: "not-a-url".to_string(),
            ..valid.clone()
        };
        assert!(invalid.validate().is_err());

        // Invalid timeout
        let invalid = NvdConfig {
            timeout_seconds: 0,
            ..valid.clone()
        };
        assert!(invalid.validate().is_err());

        // Invalid rate limit
        let invalid = NvdConfig {
            rate_limit_per_30s: 0,
            ..valid
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_ghsa_config_validation() {
        // Valid config
        let valid = GhsaConfig {
            graphql_url: "https://api.github.com/graphql".to_string(),
            token: None,
            timeout_seconds: 30,
            circuit_breaker: crate::config::CircuitBreakerConfigSerializable::default(),
            retry: crate::config::RetryConfigSerializable::default(),
        };
        assert!(valid.validate().is_ok());

        // Invalid URL
        let invalid = GhsaConfig {
            graphql_url: "not-a-url".to_string(),
            ..valid.clone()
        };
        assert!(invalid.validate().is_err());

        // Invalid timeout
        let invalid = GhsaConfig {
            timeout_seconds: 0,
            ..valid
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_github_config_validation() {
        // Valid config
        let valid = GitHubConfig {
            base_url: "https://api.github.com".to_string(),
            token: None,
            reuse_ghsa_token: true,
            timeout_seconds: 30,
            max_concurrent_file_fetches: 8,
            max_files_scanned: 200,
            max_total_bytes: 2_000_000,
            max_single_file_bytes: 1_000_000,
            backoff_initial_ms: 500,
            backoff_max_retries: 3,
            backoff_jitter: true,
        };
        assert!(valid.validate().is_ok());

        // Invalid URL
        let invalid = GitHubConfig {
            base_url: "not-a-url".to_string(),
            ..valid.clone()
        };
        assert!(invalid.validate().is_err());

        // Invalid timeout
        let invalid = GitHubConfig {
            timeout_seconds: 0,
            ..valid.clone()
        };
        assert!(invalid.validate().is_err());

        // Invalid max_concurrent_file_fetches
        let invalid = GitHubConfig {
            max_concurrent_file_fetches: 0,
            ..valid
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_analysis_config_validation() {
        // Valid config
        let valid = AnalysisConfig {
            max_concurrent_packages: 3,
            max_concurrent_registry_queries: 5,
            max_concurrent_api_calls: 10,
            job_queue_capacity: 32,
            max_job_workers: 4,
        };
        assert!(valid.validate().is_ok());

        // Invalid max_concurrent_packages
        let invalid = AnalysisConfig {
            max_concurrent_packages: 0,
            max_concurrent_registry_queries: 5,
            max_concurrent_api_calls: 10,
            job_queue_capacity: 32,
            max_job_workers: 4,
        };
        assert!(invalid.validate().is_err());
    }
}
