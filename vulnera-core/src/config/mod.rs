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
    pub analytics: AnalyticsConfig,
    pub popular_packages: Option<PopularPackagesConfig>,
    pub llm: LlmConfig,
    pub sandbox: SandboxConfig,
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

/// Storage backend for rate limiting
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitStorageBackend {
    /// Use Dragonfly/Redis for distributed rate limiting (recommended for production)
    #[default]
    Dragonfly,
    /// Use in-memory storage (suitable for development/single instance)
    Memory,
}

/// Single tier limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TierLimitConfig {
    /// Requests allowed per minute
    pub requests_per_minute: u32,
    /// Requests allowed per hour
    pub requests_per_hour: u32,
    /// Burst size (max concurrent requests allowed above rate)
    pub burst_size: u32,
}

impl Default for TierLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            requests_per_hour: 1000,
            burst_size: 10,
        }
    }
}

/// All tier limits configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TierLimitsConfig {
    /// API key authentication (CLI/Extensions) - highest limits
    pub api_key: TierLimitConfig,
    /// Cookie-based authentication (web users) - medium limits
    pub authenticated: TierLimitConfig,
    /// Unauthenticated users - lowest limits
    pub anonymous: TierLimitConfig,
    /// Bonus percentage for organization members (applied on top of tier limits)
    pub org_bonus_percent: u8,
}

impl Default for TierLimitsConfig {
    fn default() -> Self {
        Self {
            api_key: TierLimitConfig {
                requests_per_minute: 100,
                requests_per_hour: 2000,
                burst_size: 20,
            },
            authenticated: TierLimitConfig {
                requests_per_minute: 60,
                requests_per_hour: 1000,
                burst_size: 10,
            },
            anonymous: TierLimitConfig {
                requests_per_minute: 20,
                requests_per_hour: 100,
                burst_size: 5,
            },
            org_bonus_percent: 20,
        }
    }
}

/// Request cost weights for different operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RequestCostsConfig {
    /// Cost for GET requests (read operations)
    pub get: u32,
    /// Cost for POST/PUT/DELETE requests (write operations)
    pub post: u32,
    /// Cost for analysis operations (dependency scanning, SAST, etc.)
    pub analysis: u32,
    /// Cost for LLM operations (explanations, code fixes)
    pub llm: u32,
}

impl Default for RequestCostsConfig {
    fn default() -> Self {
        Self {
            get: 1,
            post: 2,
            analysis: 5,
            llm: 10,
        }
    }
}

/// Auth endpoint brute-force protection configuration (sliding window)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthProtectionConfig {
    /// Whether auth brute-force protection is enabled
    pub enabled: bool,
    /// Maximum login attempts per minute per IP
    pub login_attempts_per_minute: u32,
    /// Maximum login attempts per hour per IP
    pub login_attempts_per_hour: u32,
    /// Maximum registration attempts per minute per IP
    pub register_attempts_per_minute: u32,
    /// Maximum registration attempts per hour per IP
    pub register_attempts_per_hour: u32,
    /// Lockout duration in minutes after exceeding limits
    pub lockout_duration_minutes: u32,
}

impl Default for AuthProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            login_attempts_per_minute: 5,
            login_attempts_per_hour: 20,
            register_attempts_per_minute: 3,
            register_attempts_per_hour: 10,
            lockout_duration_minutes: 15,
        }
    }
}

/// Tiered rate limiting configuration
///
/// This unified configuration replaces the old RateLimitConfig and LlmRateLimitConfig
/// with a tier-based system that provides different limits based on authentication type:
/// - API Key (CLI/Extensions): Highest limits, programmatic access
/// - Authenticated (Cookie): Medium limits, web users
/// - Anonymous: Lowest limits, unauthenticated users
///
/// Uses token bucket algorithm for general rate limiting (allows bursts),
/// and sliding window for auth endpoint protection (stricter, no bursts).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TieredRateLimitConfig {
    /// Whether rate limiting is enabled
    pub enabled: bool,
    /// Storage backend for rate limit counters
    pub storage_backend: RateLimitStorageBackend,
    /// Cleanup interval for expired entries in seconds
    pub cleanup_interval_seconds: u64,
    /// Per-tier rate limits
    pub tiers: TierLimitsConfig,
    /// Request cost weights by operation type
    pub costs: RequestCostsConfig,
    /// Auth endpoint brute-force protection
    pub auth_protection: AuthProtectionConfig,
}

impl Default for TieredRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            storage_backend: RateLimitStorageBackend::Dragonfly,
            cleanup_interval_seconds: 300, // 5 minutes
            tiers: TierLimitsConfig::default(),
            costs: RequestCostsConfig::default(),
            auth_protection: AuthProtectionConfig::default(),
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
    /// Per-endpoint timeout for dependency analysis (in seconds). Overrides global timeout.
    /// Set this higher than global timeout since dependency analysis with many packages can be slow.
    pub dependencies_analysis_timeout_seconds: u64,
    /// Per-endpoint timeout for general analysis (in seconds). Overrides global timeout.
    pub general_analysis_timeout_seconds: u64,
    /// Allowed CORS origins. Use ["*"] to allow any (development only). Empty vector -> no external origins.
    pub allowed_origins: Vec<String>,

    /// Security configuration
    pub security: SecurityConfig,
    /// Tiered rate limiting configuration
    #[serde(default)]
    pub rate_limit: TieredRateLimitConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 3000,
            workers: None,
            enable_docs: true,
            request_timeout_seconds: 30,
            dependencies_analysis_timeout_seconds: 120, // 2 minutes for dependency analysis
            general_analysis_timeout_seconds: 60,       // 1 minute for general analysis
            allowed_origins: vec!["*".to_string()],
            security: SecurityConfig::default(),
            rate_limit: TieredRateLimitConfig::default(),
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
            interval_hours: 8, // Sync every 8 hours
            on_startup: true,  // Run initial sync immediately
            shutdown_timeout_seconds: 30,
        }
    }
}

/// Analysis depth for SAST - controls trade-off between speed and thoroughness
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnalysisDepth {
    /// Fast pattern matching only - no data flow analysis
    Quick,
    /// Pattern matching + intra-procedural data flow (default)
    #[default]
    Standard,
    /// Full analysis: patterns + data flow + call graph + inter-procedural
    Deep,
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
    /// Optional path to taint configuration file (TOML or JSON)
    /// Allows defining custom taint sources, sinks, and sanitizers
    pub taint_config_path: Option<PathBuf>,
    /// Whether to enable logging for SAST operations
    pub enable_logging: bool,
    /// Enable data flow / taint analysis (default: true)
    pub enable_data_flow: bool,
    /// Enable call graph construction for inter-procedural analysis (default: true)
    pub enable_call_graph: bool,
    /// Analysis depth: quick, standard, or deep
    pub analysis_depth: AnalysisDepth,
    /// Enable AST caching via Dragonfly (default: true)
    pub enable_ast_cache: Option<bool>,
    /// AST cache TTL in hours (default: 4)
    pub ast_cache_ttl_hours: Option<u64>,
    /// Maximum concurrent file analysis (default: 4)
    pub max_concurrent_files: Option<usize>,
    /// Maximum file size to analyze in bytes (default: 1MB, files larger are skipped)
    pub max_file_size_bytes: Option<u64>,
    /// Per-file analysis timeout in seconds (default: 30)
    pub per_file_timeout_seconds: Option<u64>,
    /// Overall scan timeout in seconds (None = no limit)
    pub scan_timeout_seconds: Option<u64>,
    /// Maximum findings per file (prevents memory explosion, default: 100)
    pub max_findings_per_file: Option<usize>,
    /// Maximum total findings across all files (stops scan early if exceeded, None = no limit)
    pub max_total_findings: Option<usize>,
    /// Enable incremental analysis (skip unchanged files based on content hash)
    pub enable_incremental: Option<bool>,
    /// Path to store incremental analysis state (file hashes)
    pub incremental_state_path: Option<PathBuf>,
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
                "dist".to_string(),
                "build".to_string(),
                "docs".to_string(),
                "doc".to_string(),
                "examples".to_string(),
                "example".to_string(),
                "test".to_string(),
                "tests".to_string(),
                "vendor".to_string(),
                "third_party".to_string(),
                "fixtures".to_string(),
            ],
            rule_file_path: None,
            taint_config_path: None,
            enable_logging: true,
            enable_data_flow: true,
            enable_call_graph: true,
            analysis_depth: AnalysisDepth::Standard,
            enable_ast_cache: Some(true),
            ast_cache_ttl_hours: Some(4),
            max_concurrent_files: Some(4),
            max_file_size_bytes: Some(1_048_576), // 1MB
            per_file_timeout_seconds: Some(30),
            scan_timeout_seconds: None, // No overall limit by default
            max_findings_per_file: Some(100),
            max_total_findings: None,        // No limit by default
            enable_incremental: Some(false), // Disabled by default
            incremental_state_path: None,
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
    /// File extensions to exclude from scanning (e.g., "md", "markdown", "rst", "txt", "html")
    pub exclude_extensions: Vec<String>,
    /// Whether to scan code blocks inside Markdown files (when Markdown files are included).
    pub scan_markdown_codeblocks: bool,
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
            // Default file extensions to skip during secret scanning to reduce false positives in docs and non-target files
            exclude_extensions: vec![
                "md".to_string(),
                "markdown".to_string(),
                "rst".to_string(),
                "html".to_string(),
            ],
            // Whether to scan code blocks inside Markdown files when Markdown files are explicitly included.
            scan_markdown_codeblocks: false,
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

/// LLM configuration with multi-provider support
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LlmConfig {
    /// Active provider: "google_ai", "openai", "azure"
    pub provider: String,

    /// Google AI (Gemini) configuration
    #[serde(default)]
    pub google_ai: GoogleAIConfig,

    /// OpenAI configuration
    #[serde(default)]
    pub openai: OpenAIConfig,

    /// Azure OpenAI configuration
    #[serde(default)]
    pub azure: AzureOpenAIConfig,

    /// Default model to use (provider-specific)
    pub default_model: String,
    /// Model to use for explanations (overrides default)
    pub explanation_model: Option<String>,
    /// Model to use for code fixes (overrides default)
    pub code_fix_model: Option<String>,
    /// Model to use for finding enrichment (overrides default)
    pub enrichment_model: Option<String>,
    /// Temperature for generation (0.0 to 1.0)
    pub temperature: f64,
    /// Maximum tokens to generate
    pub max_tokens: u32,
    /// Request timeout in seconds
    pub timeout_seconds: u64,
    /// Whether to enable streaming responses
    pub enable_streaming: bool,

    /// Resilience configuration
    #[serde(default)]
    pub resilience: LlmResilienceConfig,

    /// Finding enrichment configuration
    #[serde(default)]
    pub enrichment: LlmEnrichmentConfig,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            provider: "google_ai".to_string(),
            google_ai: GoogleAIConfig::default(),
            openai: OpenAIConfig::default(),
            azure: AzureOpenAIConfig::default(),
            default_model: "gemini-flash-latest".to_string(),
            explanation_model: None,
            code_fix_model: None,
            enrichment_model: None,
            temperature: 0.3,
            max_tokens: 2048,
            timeout_seconds: 60,
            enable_streaming: true,
            resilience: LlmResilienceConfig::default(),
            enrichment: LlmEnrichmentConfig::default(),
        }
    }
}

/// Google AI (Gemini) provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GoogleAIConfig {
    /// API Key (can also use GOOGLE_AI_KEY env var)
    pub api_key: Option<String>,
    /// Base URL for the API
    pub base_url: String,
}

impl Default for GoogleAIConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            base_url: "https://generativelanguage.googleapis.com/v1beta".to_string(),
        }
    }
}

/// OpenAI provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OpenAIConfig {
    /// API Key (can also use OPENAI_API_KEY env var)
    pub api_key: Option<String>,
    /// Base URL for the API
    pub base_url: String,
    /// Organization ID (optional)
    pub organization_id: Option<String>,
}

impl Default for OpenAIConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            base_url: "https://api.openai.com/v1".to_string(),
            organization_id: None,
        }
    }
}

/// Azure OpenAI provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AzureOpenAIConfig {
    /// Azure resource endpoint
    pub endpoint: String,
    /// API Key (can also use AZURE_OPENAI_KEY env var)
    pub api_key: Option<String>,
    /// Deployment name
    pub deployment: String,
    /// API version
    pub api_version: String,
}

impl Default for AzureOpenAIConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            api_key: None,
            deployment: String::new(),
            api_version: "2024-02-15-preview".to_string(),
        }
    }
}

/// LLM resilience configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LlmResilienceConfig {
    /// Enable resilience wrapper (circuit breaker + retry)
    pub enabled: bool,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Initial backoff delay in milliseconds
    pub initial_backoff_ms: u64,
    /// Maximum backoff delay in milliseconds
    pub max_backoff_ms: u64,
    /// Number of failures before circuit opens
    pub circuit_breaker_threshold: u32,
    /// Seconds before circuit attempts recovery
    pub circuit_breaker_timeout_secs: u64,
}

impl Default for LlmResilienceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_retries: 3,
            initial_backoff_ms: 500,
            max_backoff_ms: 30_000,
            circuit_breaker_threshold: 5,
            circuit_breaker_timeout_secs: 60,
        }
    }
}

/// LLM Finding Enrichment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LlmEnrichmentConfig {
    /// Maximum number of findings to enrich per request (prioritized by severity)
    pub max_findings_to_enrich: usize,
    /// Maximum concurrent LLM calls for enrichment
    pub max_concurrent_enrichments: usize,
    /// Whether to include code context in enrichment prompts
    pub include_code_context: bool,
    /// Maximum code snippet length to include in context (in chars)
    pub max_code_context_chars: usize,
}

impl Default for LlmEnrichmentConfig {
    fn default() -> Self {
        Self {
            max_findings_to_enrich: 10,
            max_concurrent_enrichments: 3,
            include_code_context: true,
            max_code_context_chars: 2000,
        }
    }
}

/// Analytics configuration for usage tracking and cleanup
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalyticsConfig {
    /// Whether analytics tracking is enabled
    pub enabled: bool,
    /// Whether to enable user-level (personal) analytics tracking
    pub enable_user_level_tracking: bool,
    /// Retention period for analysis events in days (events older than this will be cleaned up)
    pub event_retention_days: u64,
    /// Interval between cleanup runs in hours
    pub cleanup_interval_hours: u64,
    /// Whether to run cleanup on startup
    pub cleanup_on_startup: bool,
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            enable_user_level_tracking: true,
            event_retention_days: 180,  // 6 months
            cleanup_interval_hours: 24, // Daily cleanup
            cleanup_on_startup: false,
        }
    }
}

/// Sandbox configuration for module execution isolation
///
/// enabled with Landlock/seccomp on Linux 5.13+, provides kernel-level isolation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxConfig {
    /// Enable sandboxing for module execution (default: false for compatibility)
    ///
    /// When enabled on Linux, uses Landlock + seccomp for kernel-level isolation.
    /// Enable only after thorough testing with your specific workloads.
    pub enabled: bool,
    /// Sandbox backend preference: "noop", "auto", "landlock", "process"
    pub backend: String,
    /// Base timeout per module in milliseconds (dynamically adjusted based on source size)
    pub timeout_ms: u64,
    /// Base memory limit per module in bytes (dynamically adjusted based on source size)
    pub max_memory_bytes: u64,
    /// Allow network access for modules (required for DependencyAnalyzer)
    pub allow_network: bool,
    /// Enable dynamic limit calculation based on source size and module type
    pub dynamic_limits: bool,
    /// Additional timeout milliseconds per MB of source code
    pub timeout_per_mb_ms: u64,
    /// Memory multiplier per MB of source (e.g., 10.0 = 10x source size added to base)
    pub memory_per_mb_ratio: f64,
    /// Maximum memory cap in bytes (prevents runaway allocations)
    pub max_memory_cap_bytes: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: true,               // Enabled by default - for_analysis() provides safe paths
            backend: "auto".to_string(), // Auto-select best backend (Landlock on Linux)
            timeout_ms: 120_000,         // 2 minutes base timeout
            max_memory_bytes: 2 * 1024 * 1024 * 1024, // 2GB base
            allow_network: true,         // DependencyAnalyzer needs network
            dynamic_limits: true,
            timeout_per_mb_ms: 200,    // +200ms per MB of source
            memory_per_mb_ratio: 10.0, // 10x source size for memory overhead
            max_memory_cap_bytes: 8 * 1024 * 1024 * 1024, // 8GB cap
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
                dependencies_analysis_timeout_seconds: 120,
                general_analysis_timeout_seconds: 60,
                allowed_origins: vec!["*".to_string()],
                security: SecurityConfig {
                    enforce_https: false, // Disabled by default for development
                    enable_security_headers: true,
                    sanitize_errors: false, // Show detailed errors in development
                    hsts_max_age: 31536000, // 1 year
                    hsts_include_subdomains: true,
                },
                rate_limit: TieredRateLimitConfig::default(),
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
            analytics: AnalyticsConfig::default(),
            popular_packages: None,
            llm: LlmConfig::default(),
            sandbox: SandboxConfig::default(),
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
        validation::Validate::validate(&self.server.rate_limit)?;
        // LLM config validation is simple for now, but we could add more checks
        if self.llm.timeout_seconds == 0 {
            return Err(ValidationError::api("LLM timeout must be > 0"));
        }
        // Analytics config validation
        if self.analytics.event_retention_days == 0 {
            return Err(ValidationError::api(
                "Analytics event_retention_days must be > 0",
            ));
        }
        if self.analytics.cleanup_interval_hours == 0 {
            return Err(ValidationError::api(
                "Analytics cleanup_interval_hours must be > 0",
            ));
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
