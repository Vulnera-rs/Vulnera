//! Server configuration

use serde::Deserialize;

/// HTTP server binding and runtime settings
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Host address to bind (e.g., "0.0.0.0")
    pub host: String,
    /// TCP port to listen on
    pub port: u16,
    /// Number of Tokio worker threads
    pub workers: usize,
    /// Enable Swagger UI at /docs
    pub enable_docs: bool,
    /// Global request timeout in seconds
    pub request_timeout_seconds: u64,
    /// Timeout for dependency analysis endpoints
    #[serde(default = "default_deps_timeout")]
    pub dependencies_analysis_timeout_seconds: u64,
    /// Timeout for general analysis endpoints
    #[serde(default = "default_general_timeout")]
    pub general_analysis_timeout_seconds: u64,
    /// CORS allowed origins
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Security settings
    #[serde(default)]
    pub security: SecurityConfig,
}

fn default_deps_timeout() -> u64 {
    600
}
fn default_general_timeout() -> u64 {
    90
}

/// Server security configuration
#[derive(Debug, Default, Clone, Deserialize)]
pub struct SecurityConfig {
    /// Enforce HTTPS redirects
    #[serde(default)]
    pub enforce_https: bool,
    /// Enable security headers (CSP, HSTS, etc.)
    #[serde(default)]
    pub enable_security_headers: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 3000,
            workers: 4,
            enable_docs: true,
            request_timeout_seconds: 30,
            dependencies_analysis_timeout_seconds: 600,
            general_analysis_timeout_seconds: 90,
            allowed_origins: vec![],
            security: SecurityConfig::default(),
        }
    }
}
