//! Shared constants for the CLI application
//!
//! This module contains global constants used across the application to ensure
//! consistency and avoid magic strings.

/// Default server URL for API calls
pub const DEFAULT_SERVER_URL: &str = "https://api.vulnera.studio/";

/// Default timeout for HTTP requests in seconds
pub const DEFAULT_TIMEOUT_SECS: u64 = 600;

/// Default connection timeout in seconds
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 30;

/// User agent string
pub const USER_AGENT: &str = concat!("vulnera-cli/", env!("CARGO_PKG_VERSION"));
