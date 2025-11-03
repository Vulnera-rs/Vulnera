//! Configuration management

pub mod validation;

pub use validation::{Validate, ValidationError};

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Circuit breaker configuration (serializable version)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CircuitBreakerConfigSerializable {
    /// Number of consecutive failures before opening the circuit
    pub failure_threshold: u32,
    /// Duration to wait before transitioning from Open to HalfOpen (in seconds)
    pub recovery_timeout_seconds: u64,
    /// Maximum number of requests allowed in HalfOpen state
    pub half_open_max_requests: u32,
    /// Timeout for individual requests (in seconds)
    pub request_timeout_seconds: u64,
}

impl Default for CircuitBreakerConfigSerializable {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout_seconds: 60,
            half_open_max_requests: 3,
            request_timeout_seconds: 30,
        }
    }
}

/// Retry configuration (serializable version)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RetryConfigSerializable {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial delay between retries (in milliseconds)
    pub initial_delay_ms: u64,
    /// Maximum delay between retries (in milliseconds)
    pub max_delay_ms: u64,
    /// Multiplier for exponential backoff
    pub backoff_multiplier: f64,
}

impl Default for RetryConfigSerializable {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryConfigSerializable {
    /// Convert to the runtime RetryConfig
    pub fn to_retry_config(&self) -> crate::infrastructure::resilience::RetryConfig {
        crate::infrastructure::resilience::RetryConfig {
            max_attempts: self.max_attempts,
            initial_delay: Duration::from_millis(self.initial_delay_ms),
            max_delay: Duration::from_millis(self.max_delay_ms),
            backoff_multiplier: self.backoff_multiplier,
        }
    }
}

impl CircuitBreakerConfigSerializable {
    /// Convert to the runtime CircuitBreakerConfig
    pub fn to_circuit_breaker_config(
        &self,
    ) -> crate::infrastructure::resilience::CircuitBreakerConfig {
        crate::infrastructure::resilience::CircuitBreakerConfig {
            failure_threshold: self.failure_threshold,
            recovery_timeout: Duration::from_secs(self.recovery_timeout_seconds),
            half_open_max_requests: self.half_open_max_requests,
            request_timeout: Duration::from_secs(self.request_timeout_seconds),
        }
    }
}

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub cache: CacheConfig,
    pub apis: ApiConfig,
    pub logging: LoggingConfig,
    pub recommendations: RecommendationsConfig,
    pub analysis: AnalysisConfig,
    pub popular_packages: Option<PopularPackagesConfig>,
}

/// Popular packages configuration for vulnerability listing
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct PopularPackagesConfig {
    pub cache_ttl_hours: Option<u64>,
    pub npm: Option<Vec<PackageConfig>>,
    pub pypi: Option<Vec<PackageConfig>>,
    pub maven: Option<Vec<PackageConfig>>,
    pub cargo: Option<Vec<PackageConfig>>,
    pub go: Option<Vec<PackageConfig>>,
    pub packagist: Option<Vec<PackageConfig>>,
}

/// Individual package configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageConfig {
    pub name: String,
    pub version: String,
}

/// Rate limit strategy
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitStrategy {
    /// Rate limit per IP address
    #[default]
    Ip,
    /// Rate limit per API key
    ApiKey,
    /// Global rate limit for all requests
    Global,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Whether rate limiting is enabled
    pub enabled: bool,
    /// Requests allowed per minute
    pub requests_per_minute: u32,
    /// Requests allowed per hour
    pub requests_per_hour: u32,
    /// Rate limit strategy (IP-based, API key, or global)
    pub strategy: RateLimitStrategy,
    /// Cleanup interval for expired entries in seconds (default: 300 = 5 minutes)
    pub cleanup_interval_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_per_minute: 60,
            requests_per_hour: 1000,
            strategy: RateLimitStrategy::Ip,
            cleanup_interval_seconds: 300,
        }
    }
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: Option<usize>,
    /// Whether to expose interactive API docs (Swagger UI). Should be false in hardened production.
    pub enable_docs: bool,
    /// Global request timeout in seconds applied at the HTTP layer.
    pub request_timeout_seconds: u64,
    /// Allowed CORS origins. Use ["*"] to allow any (development only). Empty vector -> no external origins.
    pub allowed_origins: Vec<String>,

    /// Security configuration
    pub security: SecurityConfig,
    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 3000,
            workers: None,
            enable_docs: true,
            request_timeout_seconds: 30,
            allowed_origins: vec!["*".to_string()],
            security: SecurityConfig::default(),
            rate_limit: RateLimitConfig::default(),
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Whether to enforce HTTPS redirects (redirect HTTP to HTTPS)
    pub enforce_https: bool,
    /// Whether to enable security headers
    pub enable_security_headers: bool,
    /// Whether to sanitize error messages in production
    pub sanitize_errors: bool,
    /// HSTS max age in seconds (31536000 = 1 year)
    pub hsts_max_age: u64,
    /// Whether to include subdomains in HSTS
    pub hsts_include_subdomains: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enforce_https: false,
            enable_security_headers: true,
            sanitize_errors: false,
            hsts_max_age: 31_536_000,
            hsts_include_subdomains: true,
        }
    }
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    pub directory: PathBuf,
    pub ttl_hours: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from(".vulnera_cache"),
            ttl_hours: 24,
        }
    }
}

/// External API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct ApiConfig {
    pub nvd: NvdConfig,
    pub ghsa: GhsaConfig,
    pub github: GitHubConfig,
}

/// NVD API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NvdConfig {
    pub base_url: String,
    pub api_key: Option<String>,
    pub timeout_seconds: u64,
    pub rate_limit_per_30s: u32,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfigSerializable,
    #[serde(default)]
    pub retry: RetryConfigSerializable,
}

impl Default for NvdConfig {
    fn default() -> Self {
        Self {
            base_url: "https://services.nvd.nist.gov/rest/json".to_string(),
            api_key: None,
            timeout_seconds: 30,
            rate_limit_per_30s: 5,
            circuit_breaker: CircuitBreakerConfigSerializable::default(),
            retry: RetryConfigSerializable {
                initial_delay_ms: 2000, // NVD: 2s initial delay (slower service)
                ..RetryConfigSerializable::default()
            },
        }
    }
}

/// GitHub Security Advisories configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GhsaConfig {
    pub graphql_url: String,
    pub token: Option<String>,
    pub timeout_seconds: u64,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfigSerializable,
    #[serde(default)]
    pub retry: RetryConfigSerializable,
}

impl Default for GhsaConfig {
    fn default() -> Self {
        Self {
            graphql_url: "https://api.github.com/graphql".to_string(),
            token: None,
            timeout_seconds: 30,
            circuit_breaker: CircuitBreakerConfigSerializable::default(),
            retry: RetryConfigSerializable::default(),
        }
    }
}

/// GitHub repository analysis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GitHubConfig {
    pub base_url: String,
    pub token: Option<String>,
    pub reuse_ghsa_token: bool,
    pub timeout_seconds: u64,
    pub max_concurrent_file_fetches: usize,
    pub max_files_scanned: usize,
    pub max_total_bytes: u64,
    pub max_single_file_bytes: u64,
    pub backoff_initial_ms: u64,
    pub backoff_max_retries: u32,
    pub backoff_jitter: bool,
}

impl Default for GitHubConfig {
    fn default() -> Self {
        Self {
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
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "json".to_string(),
        }
    }
}

/// Recommendations configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RecommendationsConfig {
    pub max_version_queries_per_request: usize,
}

impl Default for RecommendationsConfig {
    fn default() -> Self {
        Self {
            max_version_queries_per_request: 50,
        }
    }
}

/// Analysis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalysisConfig {
    pub max_concurrent_packages: usize,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_concurrent_packages: 3,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 3000,
                workers: None,
                enable_docs: true,
                request_timeout_seconds: 30,
                allowed_origins: vec!["*".to_string()],
                security: SecurityConfig {
                    enforce_https: false, // Disabled by default for development
                    enable_security_headers: true,
                    sanitize_errors: false, // Show detailed errors in development
                    hsts_max_age: 31536000, // 1 year
                    hsts_include_subdomains: true,
                },
                rate_limit: RateLimitConfig::default(),
            },
            cache: CacheConfig {
                directory: PathBuf::from(".vulnera_cache"),
                ttl_hours: 24,
            },
            apis: ApiConfig {
                nvd: NvdConfig {
                    base_url: "https://services.nvd.nist.gov/rest/json".to_string(),
                    rate_limit_per_30s: 5, // Without API key
                    ..NvdConfig::default()
                },
                ghsa: GhsaConfig {
                    graphql_url: "https://api.github.com/graphql".to_string(),
                    token: None,
                    timeout_seconds: 30,
                    circuit_breaker: CircuitBreakerConfigSerializable::default(),
                    retry: RetryConfigSerializable::default(),
                },
                github: GitHubConfig {
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
                },
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
            },
            recommendations: RecommendationsConfig {
                max_version_queries_per_request: 50,
            },
            analysis: AnalysisConfig {
                max_concurrent_packages: 3,
            },
            popular_packages: None,
        }
    }
}

impl Validate for Config {
    fn validate(&self) -> Result<(), ValidationError> {
        self.server.validate()?;
        self.cache.validate()?;
        self.apis.validate()?;
        self.analysis.validate()?;
        Ok(())
    }
}

impl Config {
    /// Load configuration from files and environment variables
    pub fn load() -> Result<Self, ConfigLoadError> {
        let mut builder = config::Config::builder()
            .add_source(config::File::with_name("config/default").required(false));

        // Add environment-specific config if ENV is set
        if let Ok(env) = std::env::var("ENV") {
            builder = builder
                .add_source(config::File::with_name(&format!("config/{}", env)).required(false));
        }

        // Add local config and environment variables last (highest priority)
        builder = builder
            .add_source(config::File::with_name("config/local").required(false))
            .add_source(config::Environment::with_prefix("VULNERA").separator("__"));

        let config: Config = builder.build()?.try_deserialize()?;

        // Validate the loaded configuration
        config.validate()?;

        Ok(config)
    }
}

/// Error type for configuration loading
#[derive(Debug, thiserror::Error)]
pub enum ConfigLoadError {
    #[error("Configuration file error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("Configuration validation error: {0}")]
    Validation(#[from] ValidationError),
}
