//! LLM-specific error types
//!
//! Provides typed errors for LLM operations, enabling better error handling
//! and recovery strategies.

use std::fmt;

/// LLM operation error
#[derive(Debug)]
pub enum LlmError {
    /// Authentication failed (invalid API key, expired token, etc.)
    Authentication(String),

    /// Rate limited by the provider
    RateLimited {
        /// Seconds to wait before retrying (if provided)
        retry_after: Option<u64>,
        /// Error message
        message: String,
    },

    /// Request was invalid (bad parameters, too many tokens, etc.)
    InvalidRequest(String),

    /// Content was filtered/blocked by safety systems
    ContentFiltered {
        /// Reason for filtering
        reason: String,
    },

    /// Model not found or not available
    ModelNotFound(String),

    /// Context length exceeded
    ContextLengthExceeded {
        /// Tokens in the request
        requested: u32,
        /// Maximum allowed
        maximum: u32,
    },

    /// Network/connection error
    Network(String),

    /// Request timed out
    Timeout {
        /// Timeout duration in seconds
        seconds: u64,
    },

    /// Service temporarily unavailable
    ServiceUnavailable(String),

    /// Provider returned an unexpected response
    InvalidResponse(String),

    /// Streaming error
    StreamError(String),

    /// Configuration error
    Configuration(String),

    /// Provider not supported or not configured
    ProviderNotFound(String),

    /// Circuit breaker is open
    CircuitOpen {
        /// Name of the circuit
        circuit: String,
    },

    /// Generic/unknown error
    Other(String),
}

impl LlmError {
    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            LlmError::RateLimited { .. }
                | LlmError::Network(_)
                | LlmError::Timeout { .. }
                | LlmError::ServiceUnavailable(_)
                | LlmError::StreamError(_)
        )
    }

    /// Check if this is a rate limit error
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, LlmError::RateLimited { .. })
    }

    /// Get retry-after duration if available
    pub fn retry_after(&self) -> Option<std::time::Duration> {
        match self {
            LlmError::RateLimited { retry_after, .. } => {
                retry_after.map(std::time::Duration::from_secs)
            }
            _ => None,
        }
    }

    /// Create a rate limited error
    pub fn rate_limited(message: impl Into<String>) -> Self {
        Self::RateLimited {
            retry_after: None,
            message: message.into(),
        }
    }

    /// Create a rate limited error with retry duration
    pub fn rate_limited_with_retry(message: impl Into<String>, seconds: u64) -> Self {
        Self::RateLimited {
            retry_after: Some(seconds),
            message: message.into(),
        }
    }

    /// Create a timeout error
    pub fn timeout(seconds: u64) -> Self {
        Self::Timeout { seconds }
    }

    /// Create a network error
    pub fn network(message: impl Into<String>) -> Self {
        Self::Network(message.into())
    }

    /// Create an authentication error
    pub fn auth(message: impl Into<String>) -> Self {
        Self::Authentication(message.into())
    }
}

impl fmt::Display for LlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LlmError::Authentication(msg) => write!(f, "Authentication failed: {}", msg),
            LlmError::RateLimited {
                message,
                retry_after,
            } => {
                if let Some(secs) = retry_after {
                    write!(f, "Rate limited: {} (retry after {}s)", message, secs)
                } else {
                    write!(f, "Rate limited: {}", message)
                }
            }
            LlmError::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
            LlmError::ContentFiltered { reason } => write!(f, "Content filtered: {}", reason),
            LlmError::ModelNotFound(model) => write!(f, "Model not found: {}", model),
            LlmError::ContextLengthExceeded { requested, maximum } => {
                write!(
                    f,
                    "Context length exceeded: {} tokens requested, {} maximum",
                    requested, maximum
                )
            }
            LlmError::Network(msg) => write!(f, "Network error: {}", msg),
            LlmError::Timeout { seconds } => write!(f, "Request timed out after {}s", seconds),
            LlmError::ServiceUnavailable(msg) => write!(f, "Service unavailable: {}", msg),
            LlmError::InvalidResponse(msg) => write!(f, "Invalid response: {}", msg),
            LlmError::StreamError(msg) => write!(f, "Stream error: {}", msg),
            LlmError::Configuration(msg) => write!(f, "Configuration error: {}", msg),
            LlmError::ProviderNotFound(name) => write!(f, "Provider not found: {}", name),
            LlmError::CircuitOpen { circuit } => {
                write!(f, "Circuit breaker open for: {}", circuit)
            }
            LlmError::Other(msg) => write!(f, "LLM error: {}", msg),
        }
    }
}

impl std::error::Error for LlmError {}

impl From<reqwest::Error> for LlmError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            LlmError::Timeout { seconds: 0 }
        } else if err.is_connect() {
            LlmError::Network(format!("Connection failed: {}", err))
        } else {
            LlmError::Network(err.to_string())
        }
    }
}

impl From<serde_json::Error> for LlmError {
    fn from(err: serde_json::Error) -> Self {
        LlmError::InvalidResponse(format!("JSON parse error: {}", err))
    }
}

impl From<anyhow::Error> for LlmError {
    fn from(err: anyhow::Error) -> Self {
        LlmError::Other(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = LlmError::Authentication("invalid key".to_string());
        assert_eq!(err.to_string(), "Authentication failed: invalid key");

        let err = LlmError::rate_limited_with_retry("too many requests", 30);
        assert!(err.to_string().contains("30s"));
    }

    #[test]
    fn test_is_retryable() {
        assert!(LlmError::network("connection reset").is_retryable());
        assert!(LlmError::timeout(30).is_retryable());
        assert!(LlmError::rate_limited("quota exceeded").is_retryable());

        assert!(!LlmError::auth("bad key").is_retryable());
        assert!(!LlmError::InvalidRequest("bad params".to_string()).is_retryable());
    }

    #[test]
    fn test_retry_after() {
        let err = LlmError::rate_limited_with_retry("quota", 60);
        assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(60)));

        let err = LlmError::network("failed");
        assert_eq!(err.retry_after(), None);
    }
}
