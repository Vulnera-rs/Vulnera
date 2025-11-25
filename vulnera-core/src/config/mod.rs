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
    pub sync: SyncConfig,
    pub sast: SastConfig,
    pub secret_detection: SecretDetectionConfig,
    pub api_security: ApiSecurityConfig,
    pub auth: AuthConfig,
    pub database: DatabaseConfig,
    pub popular_packages: Option<PopularPackagesConfig>,
    pub llm: LlmConfig,
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
    /// Requests allowed per day for unauthenticated users
    pub unauthenticated_requests_per_day: u32,
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
            unauthenticated_requests_per_day: 10,
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
    pub ttl_hours: u64,
    /// L1 cache size in MB (deprecated, kept for backward compatibility)
    pub l1_cache_size_mb: u64,
    /// L1 cache TTL in seconds (deprecated, kept for backward compatibility)
    pub l1_cache_ttl_seconds: u64,
    /// Enable cache compression for entries larger than threshold
    pub enable_cache_compression: bool,
    /// Compression threshold in bytes
    pub compression_threshold_bytes: u64,
    /// Enable Dragonfly DB cache (default cache backend, replaces file-based caching)
    pub dragonfly_enabled: bool,
    /// Dragonfly DB connection URL (e.g., "redis://127.0.0.1:6379")
    pub dragonfly_url: String,
    /// Connection pool size for Dragonfly DB (not used directly, but kept for future use)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dragonfly_connection_pool_size: Option<u32>,
    /// Connection timeout in seconds for Dragonfly DB
    pub dragonfly_connection_timeout_seconds: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            ttl_hours: 24,
            l1_cache_size_mb: 100,
            l1_cache_ttl_seconds: 300, // 5 minutes
            enable_cache_compression: true,
            compression_threshold_bytes: 10240, // 10KB
            dragonfly_enabled: true,            // Dragonfly DB is the default cache backend
            dragonfly_url: "redis://127.0.0.1:6379".to_string(),
            dragonfly_connection_pool_size: None,
            dragonfly_connection_timeout_seconds: 5,
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
    #[serde(default = "default_reuse_ghsa_token")]
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

fn default_reuse_ghsa_token() -> bool {
    true
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
    /// Maximum concurrent registry version queries
    pub max_concurrent_registry_queries: usize,
    /// Maximum concurrent API calls per source
    pub max_concurrent_api_calls: usize,
    /// Maximum number of jobs buffered before back-pressure is applied
    pub job_queue_capacity: usize,
    /// Maximum number of concurrent background workers processing jobs
    pub max_job_workers: usize,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_concurrent_packages: 3,
            max_concurrent_registry_queries: 5,
            max_concurrent_api_calls: 10,
            job_queue_capacity: 32,
            max_job_workers: 4,
        }
    }
}

/// Vulnerability sync configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SyncConfig {
    /// Whether background vulnerability sync is enabled
    pub enabled: bool,
    /// Interval between syncs in hours
    pub interval_hours: u64,
    /// Whether to run an initial sync on startup
    pub on_startup: bool,
    /// Maximum time to wait for sync to complete on shutdown (in seconds)
    pub shutdown_timeout_seconds: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            enabled: false,    // Opt-in by default
            interval_hours: 6, // Sync every 6 hours
            on_startup: true,  // Run initial sync immediately
            shutdown_timeout_seconds: 30,
        }
    }
}

/// SAST (Static Application Security Testing) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SastConfig {
    /// Maximum depth for directory scanning
    pub max_scan_depth: usize,
    /// Patterns to exclude from scanning (directory or file names)
    pub exclude_patterns: Vec<String>,
    /// Optional path to rule configuration file (TOML or JSON)
    pub rule_file_path: Option<PathBuf>,
    /// Whether to enable logging for SAST operations
    pub enable_logging: bool,
}

impl Default for SastConfig {
    fn default() -> Self {
        Self {
            max_scan_depth: 10,
            exclude_patterns: vec![
                "node_modules".to_string(),
                ".git".to_string(),
                "target".to_string(),
                "__pycache__".to_string(),
                ".venv".to_string(),
                "venv".to_string(),
                ".pytest_cache".to_string(),
                "dist".to_string(),
                "build".to_string(),
            ],
            rule_file_path: None,
            enable_logging: true,
        }
    }
}

/// Secret Detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretDetectionConfig {
    /// Maximum depth for directory scanning
    pub max_scan_depth: usize,
    /// Patterns to exclude from scanning (directory or file names)
    pub exclude_patterns: Vec<String>,
    /// Optional path to rule configuration file (TOML or JSON)
    pub rule_file_path: Option<PathBuf>,
    /// Entropy threshold for Base64 strings (default: 4.5)
    pub base64_entropy_threshold: f64,
    /// Entropy threshold for hex strings (default: 3.0)
    pub hex_entropy_threshold: f64,
    /// Whether to enable entropy-based detection
    pub enable_entropy_detection: bool,
    /// Maximum file size to scan in bytes (default: 10MB)
    pub max_file_size_bytes: u64,
    /// Whether to enable secret verification
    pub enable_verification: bool,
    /// Timeout for secret verification in seconds
    pub verification_timeout_seconds: u64,
    /// Maximum concurrent verification requests
    pub verification_concurrent_limit: usize,
    /// Optional path to baseline file for tracking known secrets
    pub baseline_file_path: Option<PathBuf>,
    /// Whether to update baseline after scan
    pub update_baseline: bool,
    /// Whether to scan git history for secrets
    pub scan_git_history: bool,
    /// Maximum number of commits to scan (None = unlimited)
    pub max_commits_to_scan: Option<usize>,
    /// Only scan commits since this date (None = scan all)
    pub since_date: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether to enable logging for secret detection operations
    pub enable_logging: bool,
    /// Timeout for file read operations in seconds (default: 30)
    pub file_read_timeout_seconds: u64,
    /// Overall scan timeout in seconds (None = no timeout)
    pub scan_timeout_seconds: Option<u64>,
}

impl Default for SecretDetectionConfig {
    fn default() -> Self {
        Self {
            max_scan_depth: 10,
            exclude_patterns: vec![
                "node_modules".to_string(),
                ".git".to_string(),
                "target".to_string(),
                "__pycache__".to_string(),
                ".venv".to_string(),
                "venv".to_string(),
                ".pytest_cache".to_string(),
                "dist".to_string(),
                "build".to_string(),
                "*.lock".to_string(),
                "*.min.js".to_string(),
                "*.min.css".to_string(),
            ],
            rule_file_path: None,
            base64_entropy_threshold: 4.5,
            hex_entropy_threshold: 3.0,
            enable_entropy_detection: true,
            max_file_size_bytes: 10 * 1024 * 1024, // 10MB
            enable_verification: false,
            verification_timeout_seconds: 5,
            verification_concurrent_limit: 10,
            baseline_file_path: None,
            update_baseline: false,
            scan_git_history: false,
            max_commits_to_scan: None,
            since_date: None,
            enable_logging: true,
            file_read_timeout_seconds: 30,
            scan_timeout_seconds: None,
        }
    }
}

/// API Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct ApiSecurityConfig {
    /// List of enabled analyzers (empty = all enabled)
    pub enabled_analyzers: Vec<String>,
    /// Severity overrides for specific vulnerability types
    pub severity_overrides: std::collections::HashMap<String, String>,
    /// Paths to exclude from analysis
    pub exclude_paths: Vec<String>,
    /// Whether to use strict mode (more aggressive checks)
    pub strict_mode: bool,
}

/// Cookie SameSite policy
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CookieSameSite {
    /// Cookies sent with same-site requests and cross-site top-level navigations
    #[default]
    Lax,
    /// Cookies only sent with same-site requests
    Strict,
    /// Cookies sent with all requests (requires Secure)
    None,
}

impl CookieSameSite {
    /// Convert to cookie::SameSite string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            CookieSameSite::Lax => "Lax",
            CookieSameSite::Strict => "Strict",
            CookieSameSite::None => "None",
        }
    }
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// JWT secret key for signing tokens (must be at least 32 characters in production)
    pub jwt_secret: String,
    /// Access token TTL in hours
    pub token_ttl_hours: u64,
    /// Refresh token TTL in hours
    pub refresh_token_ttl_hours: u64,
    /// API key length (in bytes, will be hex-encoded)
    pub api_key_length: usize,
    /// API key TTL in days (None means no expiration)
    pub api_key_ttl_days: Option<u64>,

    // Cookie-based authentication settings
    /// Cookie domain (None = current host only, recommended for security)
    pub cookie_domain: Option<String>,
    /// Whether cookies require HTTPS (should be true in production)
    pub cookie_secure: bool,
    /// Cookie SameSite policy (Lax recommended for balance of security and usability)
    pub cookie_same_site: CookieSameSite,
    /// Cookie path for access token
    pub cookie_path: String,
    /// Cookie path for refresh token (more restrictive)
    pub refresh_cookie_path: String,
    /// CSRF token length in bytes (will be base64-encoded)
    pub csrf_token_bytes: usize,
    /// Whether to blacklist tokens on logout
    pub blacklist_tokens_on_logout: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "change-me-in-production-use-strong-random-secret-key".to_string(),
            token_ttl_hours: 24,
            refresh_token_ttl_hours: 720, // 30 days
            api_key_length: 32,
            api_key_ttl_days: Some(365), // 1 year
            // Cookie settings
            cookie_domain: None, // Current host only (most secure default)
            cookie_secure: true, // Require HTTPS in production
            cookie_same_site: CookieSameSite::Lax, // Balance security and usability
            cookie_path: "/api".to_string(), // Scope to API routes
            refresh_cookie_path: "/api/v1/auth".to_string(), // More restrictive for refresh
            csrf_token_bytes: 32, // 256 bits of entropy
            blacklist_tokens_on_logout: true, // Invalidate tokens on logout
        }
    }
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    /// Database connection URL (can also be set via DATABASE_URL env var)
    pub url: String,
    /// Maximum number of connections in the pool
    pub max_connections: u32,
    /// Minimum number of idle connections to maintain
    pub min_idle: Option<u32>,
    /// Connection timeout in seconds
    pub connect_timeout_seconds: u64,
    /// Maximum lifetime of a connection in seconds
    pub max_lifetime_seconds: Option<u64>,
    /// Idle timeout in seconds (connections idle longer than this will be closed)
    pub idle_timeout_seconds: Option<u64>,
    /// Enable connection health checks
    pub enable_health_checks: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgres://postgres:postgres@localhost/vulnera".to_string(),
            max_connections: 10,
            min_idle: Some(2),
            connect_timeout_seconds: 30,
            max_lifetime_seconds: Some(1800), // 30 minutes
            idle_timeout_seconds: Some(600),  // 10 minutes
            enable_health_checks: true,
        }
    }
}

/// LLM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LlmConfig {
    /// Huawei ModelArts API URL
    pub huawei_api_url: String,
    /// Huawei ModelArts API Key
    pub huawei_api_key: Option<String>,
    /// Default model to use (qwen3-32b or deepseek-v3.1)
    pub default_model: String,
    /// Model to use for explanations (overrides default)
    pub explanation_model: Option<String>,
    /// Model to use for code fixes (overrides default)
    pub code_fix_model: Option<String>,
    /// Temperature for generation (0.0 to 1.0)
    pub temperature: f64,
    /// Maximum tokens to generate
    pub max_tokens: u32,
    /// Request timeout in seconds
    pub timeout_seconds: u64,
    /// Whether to enable streaming responses
    pub enable_streaming: bool,
    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: LlmRateLimitConfig,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            huawei_api_url: "https://api-ap-southeast-1.modelarts-maas.com/v1/chat/completions"
                .to_string(),
            huawei_api_key: None,
            default_model: "deepseek-v3.1".to_string(),
            explanation_model: Some("deepseek-v3.1".to_string()),
            code_fix_model: Some("qwen3-32b".to_string()),
            temperature: 0.3,
            max_tokens: 2048,
            timeout_seconds: 60,
            enable_streaming: true,
            rate_limit: LlmRateLimitConfig::default(),
        }
    }
}

/// LLM Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LlmRateLimitConfig {
    /// Whether rate limiting is enabled
    pub enabled: bool,
    /// Requests allowed per minute
    pub requests_per_minute: u32,
    /// Requests allowed per hour
    pub requests_per_hour: u32,
    /// Burst size (max concurrent requests allowed above rate)
    pub burst_size: u32,
    /// Whether to enforce per-user limits
    pub per_user_limit: bool,
}

impl Default for LlmRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: 20,
            requests_per_hour: 200,
            burst_size: 5,
            per_user_limit: true,
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
                ttl_hours: 24,
                l1_cache_size_mb: 100,
                l1_cache_ttl_seconds: 300,
                enable_cache_compression: true,
                compression_threshold_bytes: 10240,
                dragonfly_enabled: true,
                dragonfly_url: "redis://127.0.0.1:6379".to_string(),
                dragonfly_connection_pool_size: None,
                dragonfly_connection_timeout_seconds: 5,
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
                max_concurrent_registry_queries: 5,
                max_concurrent_api_calls: 10,
                job_queue_capacity: 32,
                max_job_workers: 4,
            },
            sync: SyncConfig::default(),
            sast: SastConfig::default(),
            secret_detection: SecretDetectionConfig::default(),
            api_security: ApiSecurityConfig::default(),
            auth: AuthConfig::default(),
            database: DatabaseConfig::default(),
            popular_packages: None,
            llm: LlmConfig::default(),
        }
    }
}

impl Validate for Config {
    fn validate(&self) -> Result<(), ValidationError> {
        self.server.validate()?;
        self.cache.validate()?;
        self.apis.validate()?;
        self.analysis.validate()?;
        validation::Validate::validate(&self.secret_detection)?;
        validation::Validate::validate(&self.api_security)?;
        validation::Validate::validate(&self.auth)?;
        validation::Validate::validate(&self.database)?;
        // LLM config validation is simple for now, but we could add more checks
        if self.llm.timeout_seconds == 0 {
            return Err(ValidationError::api("LLM timeout must be > 0"));
        }
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

        let mut config: Config = builder.build()?.try_deserialize()?;

        // Override database URL from DATABASE_URL env var if present (common convention)
        if let Ok(database_url) = std::env::var("DATABASE_URL") {
            config.database.url = database_url;
        }

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
