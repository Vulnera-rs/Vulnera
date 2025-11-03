//! Resilience patterns for external API calls

use crate::application::errors::{ApiError, VulnerabilityError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Circuit breaker states
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    /// Circuit is closed, requests are allowed through
    Closed,
    /// Circuit is open, requests are rejected immediately
    Open,
    /// Circuit is half-open, allowing limited requests to test if service has recovered
    HalfOpen,
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit
    pub failure_threshold: u32,
    /// Duration to wait before transitioning from Open to HalfOpen
    pub recovery_timeout: Duration,
    /// Maximum number of requests allowed in HalfOpen state
    pub half_open_max_requests: u32,
    /// Timeout for individual requests
    pub request_timeout: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout: Duration::from_secs(60),
            half_open_max_requests: 3,
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// Circuit breaker implementation for resilient API calls
///
/// Implements the **Circuit Breaker Pattern** to prevent cascading failures when external
/// services become unavailable. This provides fault tolerance and automatic recovery.
///
/// **State Machine:**
/// ```
///    ┌─────────────┐    Failure Threshold     ┌──────────────┐
///    │   CLOSED    │ ───────────────────────► │     OPEN      │
///    └─────────────┘                          └──────────────┘
///    │         ▲ Recovery Timeout                 │ Success
///    │         │                                  ▼
///    └─────────┼──────────────────────────────────┐
///              │                                  │
///              ▼                                  │
///         ┌──────────────┐   Half-Open Max        │
///         │  HALF_OPEN   │ ───────────────────────┘
///         └──────────────┘     Requests Limit
/// ```
///
/// **Behavior by State:**
/// - **CLOSED**: All requests pass through normally, failures are counted
/// - **OPEN**: All requests fail immediately with `ServiceUnavailable`
/// - **HALF_OPEN**: Limited requests allowed to test service recovery
///
/// **Configuration:**
/// - `failure_threshold`: Number of consecutive failures before opening
/// - `recovery_timeout`: How long to wait before trying half-open state
/// - `half_open_max_requests`: Max test requests in half-open state
/// - `request_timeout`: Per-request timeout
///
/// **Thread Safety:**
/// - Uses `Arc<Mutex<>>` for safe concurrent access to state
/// - Atomic operations prevent race conditions
/// - Lock contention minimized for high-performance scenarios
#[derive(Debug)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<Mutex<CircuitBreakerState>>,
}

#[derive(Debug)]
struct CircuitBreakerState {
    current_state: CircuitState,
    failure_count: u32,
    last_failure_time: Option<Instant>,
    half_open_requests: u32,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given configuration
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(CircuitBreakerState {
                current_state: CircuitState::Closed,
                failure_count: 0,
                last_failure_time: None,
                half_open_requests: 0,
            })),
        }
    }

    /// Create a circuit breaker with default configuration
    pub fn with_default_config() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }

    /// Execute a function with circuit breaker protection
    ///
    /// This is the core method that implements the circuit breaker logic. It follows
    /// this decision tree:
    ///
    /// ```
    /// Can Execute?
    ///    ├─ No → Return ServiceUnavailable error
    ///    └─ Yes → Execute with timeout
    ///        ├─ Success → Reset failure count, return result
    ///        ├─ Timeout → Record failure, check state transition
    ///        └─ Error → Record failure, check state transition
    /// ```
    ///
    /// **Concurrency Model:**
    /// - Uses async/await for non-blocking execution
    /// - Timeout prevents hanging on slow/unresponsive services
    /// - State transitions are atomic and thread-safe
    ///
    /// **Performance Characteristics:**
    /// - Minimal overhead when circuit is closed (just a few atomic operations)
    /// - Fast failure when circuit is open (immediate return, no network call)
    /// - Controlled testing when circuit is half-open
    ///
    /// **Error Handling:**
    /// - Timeouts are treated as failures and count toward the threshold
    /// - All error types are captured and counted
    /// - State transitions happen after each operation
    pub async fn execute<F, Fut, T>(&self, operation: F) -> Result<T, VulnerabilityError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, VulnerabilityError>>,
    {
        // Check if we can execute the request
        if !self.can_execute().await? {
            return Err(VulnerabilityError::Api(ApiError::ServiceUnavailable));
        }

        // Execute with timeout
        let result = tokio::time::timeout(self.config.request_timeout, operation()).await;

        match result {
            Ok(Ok(success)) => {
                self.on_success().await;
                Ok(success)
            }
            Ok(Err(error)) => {
                self.on_failure().await;
                Err(error)
            }
            Err(_) => {
                // Timeout occurred
                self.on_failure().await;
                Err(VulnerabilityError::Timeout {
                    seconds: self.config.request_timeout.as_secs(),
                })
            }
        }
    }

    /// Check if a request can be executed based on circuit breaker state
    async fn can_execute(&self) -> Result<bool, VulnerabilityError> {
        let mut state = self.state.lock().await;

        match state.current_state {
            CircuitState::Closed => Ok(true),
            CircuitState::Open => {
                // Check if we should transition to half-open
                if let Some(last_failure) = state.last_failure_time {
                    if last_failure.elapsed() >= self.config.recovery_timeout {
                        state.current_state = CircuitState::HalfOpen;
                        state.half_open_requests = 0;
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                } else {
                    Ok(false)
                }
            }
            CircuitState::HalfOpen => {
                if state.half_open_requests < self.config.half_open_max_requests {
                    state.half_open_requests += 1;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Handle successful request
    async fn on_success(&self) {
        let mut state = self.state.lock().await;

        match state.current_state {
            CircuitState::Closed => {
                // Reset failure count on success
                state.failure_count = 0;
            }
            CircuitState::HalfOpen => {
                // Transition back to closed state
                state.current_state = CircuitState::Closed;
                state.failure_count = 0;
                state.half_open_requests = 0;
            }
            CircuitState::Open => {
                // This shouldn't happen, but reset if it does
                state.current_state = CircuitState::Closed;
                state.failure_count = 0;
            }
        }
    }

    /// Handle failed request
    async fn on_failure(&self) {
        let mut state = self.state.lock().await;

        state.failure_count += 1;
        state.last_failure_time = Some(Instant::now());

        match state.current_state {
            CircuitState::Closed => {
                if state.failure_count >= self.config.failure_threshold {
                    state.current_state = CircuitState::Open;
                }
            }
            CircuitState::HalfOpen => {
                // Go back to open state on any failure in half-open
                state.current_state = CircuitState::Open;
                state.half_open_requests = 0;
            }
            CircuitState::Open => {
                // Already open, just update failure time
            }
        }
    }

    /// Get current circuit breaker state
    pub async fn get_state(&self) -> CircuitState {
        let state = self.state.lock().await;
        state.current_state.clone()
    }

    /// Get current failure count
    pub async fn get_failure_count(&self) -> u32 {
        let state = self.state.lock().await;
        state.failure_count
    }

    /// Reset the circuit breaker to closed state
    pub async fn reset(&self) {
        let mut state = self.state.lock().await;
        state.current_state = CircuitState::Closed;
        state.failure_count = 0;
        state.last_failure_time = None;
        state.half_open_requests = 0;
    }
}

/// Retry configuration for exponential backoff
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial delay between retries
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Multiplier for exponential backoff
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(1000),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
        }
    }
}

/// Execute a function with exponential backoff retry logic
pub async fn retry_with_backoff<F, Fut, T>(
    config: RetryConfig,
    mut operation: F,
) -> Result<T, VulnerabilityError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, VulnerabilityError>>,
{
    let mut attempts = 0;
    let mut delay = config.initial_delay;

    loop {
        attempts += 1;

        match operation().await {
            Ok(result) => return Ok(result),
            Err(error) => {
                if attempts >= config.max_attempts {
                    return Err(error);
                }

                // Check if error is retryable
                if !is_retryable_error(&error) {
                    return Err(error);
                }

                // Log retry attempt
                tracing::debug!(
                    attempt = attempts,
                    max_attempts = config.max_attempts,
                    delay_ms = delay.as_millis(),
                    error = %error,
                    "Retrying operation with exponential backoff"
                );

                // Wait before retrying
                tokio::time::sleep(delay).await;

                // Calculate next delay with exponential backoff
                delay = std::cmp::min(
                    Duration::from_millis(
                        (delay.as_millis() as f64 * config.backoff_multiplier) as u64,
                    ),
                    config.max_delay,
                );
            }
        }
    }
}

/// Check if an error is retryable
pub fn is_retryable_error(error: &VulnerabilityError) -> bool {
    match error {
        VulnerabilityError::Network(_) => true,
        VulnerabilityError::Timeout { .. } => true,
        VulnerabilityError::Api(ApiError::Http { status, .. }) => {
            // Retry on server errors and rate limiting
            *status >= 500 || *status == 429
        }
        VulnerabilityError::Api(ApiError::ServiceUnavailable) => true,
        _ => false,
    }
}

/// Execute a function with exponential backoff retry logic for RegistryError
pub async fn retry_with_backoff_registry<F, Fut, T>(
    config: RetryConfig,
    mut operation: F,
) -> Result<T, crate::infrastructure::registries::RegistryError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, crate::infrastructure::registries::RegistryError>>,
{
    let mut attempts = 0;
    let mut delay = config.initial_delay;

    loop {
        attempts += 1;

        match operation().await {
            Ok(result) => return Ok(result),
            Err(error) => {
                if attempts >= config.max_attempts {
                    return Err(error);
                }

                // Check if error is retryable
                if !is_retryable_registry_error(&error) {
                    return Err(error);
                }

                // Log retry attempt
                tracing::debug!(
                    attempt = attempts,
                    max_attempts = config.max_attempts,
                    delay_ms = delay.as_millis(),
                    error = %error,
                    "Retrying registry operation"
                );

                // Wait before retrying
                tokio::time::sleep(delay).await;

                // Calculate next delay with exponential backoff
                delay = std::cmp::min(
                    Duration::from_millis(
                        (delay.as_millis() as f64 * config.backoff_multiplier) as u64,
                    ),
                    config.max_delay,
                );
            }
        }
    }
}

/// Check if a RegistryError is retryable
fn is_retryable_registry_error(error: &crate::infrastructure::registries::RegistryError) -> bool {
    match error {
        crate::infrastructure::registries::RegistryError::Http { status, .. } => {
            // Retry on server errors (5xx) and rate limiting (429)
            status.map(|s| s >= 500 || s == 429).unwrap_or(true) // Default to retryable if no status
        }
        crate::infrastructure::registries::RegistryError::RateLimited => true,
        // Don't retry on NotFound, Parse, UnsupportedEcosystem, or Other
        _ => false,
    }
}

/// Health check result
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Degraded,
}

/// Health checker for monitoring API availability
#[derive(Debug)]
pub struct HealthChecker {
    circuit_breaker: CircuitBreaker,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(circuit_breaker: CircuitBreaker) -> Self {
        Self { circuit_breaker }
    }

    /// Check the health of a service
    pub async fn check_health<F, Fut>(&self, health_check: F) -> HealthStatus
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), VulnerabilityError>>,
    {
        let state = self.circuit_breaker.get_state().await;

        match state {
            CircuitState::Closed => {
                // Try to execute health check
                match self.circuit_breaker.execute(health_check).await {
                    Ok(_) => HealthStatus::Healthy,
                    Err(_) => HealthStatus::Degraded,
                }
            }
            CircuitState::HalfOpen => HealthStatus::Degraded,
            CircuitState::Open => HealthStatus::Unhealthy,
        }
    }

    /// Get circuit breaker statistics
    pub async fn get_stats(&self) -> CircuitBreakerStats {
        let state = self.circuit_breaker.get_state().await;
        let failure_count = self.circuit_breaker.get_failure_count().await;

        CircuitBreakerStats {
            state,
            failure_count,
        }
    }
}

/// Circuit breaker statistics
#[derive(Debug, Clone)]
pub struct CircuitBreakerStats {
    pub state: CircuitState,
    pub failure_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn test_circuit_breaker_closed_state() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            recovery_timeout: Duration::from_millis(100),
            half_open_max_requests: 2,
            request_timeout: Duration::from_secs(1),
        };
        let circuit_breaker = CircuitBreaker::new(config);

        // Should start in closed state
        assert_eq!(circuit_breaker.get_state().await, CircuitState::Closed);

        // Successful request should keep it closed
        let result = circuit_breaker
            .execute(|| async { Ok::<(), VulnerabilityError>(()) })
            .await;
        assert!(result.is_ok());
        assert_eq!(circuit_breaker.get_state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_on_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            recovery_timeout: Duration::from_millis(100),
            half_open_max_requests: 2,
            request_timeout: Duration::from_secs(1),
        };
        let circuit_breaker = CircuitBreaker::new(config);

        // First failure
        let result = circuit_breaker
            .execute(|| async {
                Err::<(), VulnerabilityError>(VulnerabilityError::Api(ApiError::ServiceUnavailable))
            })
            .await;
        assert!(result.is_err());
        assert_eq!(circuit_breaker.get_state().await, CircuitState::Closed);

        // Second failure should open the circuit
        let result = circuit_breaker
            .execute(|| async {
                Err::<(), VulnerabilityError>(VulnerabilityError::Api(ApiError::ServiceUnavailable))
            })
            .await;
        assert!(result.is_err());
        assert_eq!(circuit_breaker.get_state().await, CircuitState::Open);
    }

    #[tokio::test]
    async fn test_circuit_breaker_rejects_when_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_secs(10), // Long timeout
            half_open_max_requests: 2,
            request_timeout: Duration::from_secs(1),
        };
        let circuit_breaker = CircuitBreaker::new(config);

        // Cause a failure to open the circuit
        let _ = circuit_breaker
            .execute(|| async {
                Err::<(), VulnerabilityError>(VulnerabilityError::Api(ApiError::ServiceUnavailable))
            })
            .await;

        assert_eq!(circuit_breaker.get_state().await, CircuitState::Open);

        // Next request should be rejected immediately
        let result = circuit_breaker
            .execute(|| async { Ok::<(), VulnerabilityError>(()) })
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            VulnerabilityError::Api(ApiError::ServiceUnavailable) => {}
            _ => panic!("Expected ServiceUnavailable error"),
        }
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_recovery() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_millis(50),
            half_open_max_requests: 2,
            request_timeout: Duration::from_secs(1),
        };
        let circuit_breaker = CircuitBreaker::new(config);

        // Cause a failure to open the circuit
        let _ = circuit_breaker
            .execute(|| async {
                Err::<(), VulnerabilityError>(VulnerabilityError::Api(ApiError::ServiceUnavailable))
            })
            .await;

        assert_eq!(circuit_breaker.get_state().await, CircuitState::Open);

        // Wait for recovery timeout
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Next request should transition to half-open
        let result = circuit_breaker
            .execute(|| async { Ok::<(), VulnerabilityError>(()) })
            .await;
        assert!(result.is_ok());
        assert_eq!(circuit_breaker.get_state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_circuit_breaker_timeout() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_millis(100),
            half_open_max_requests: 2,
            request_timeout: Duration::from_millis(50),
        };
        let circuit_breaker = CircuitBreaker::new(config);

        // Request that takes longer than timeout
        let result = circuit_breaker
            .execute(|| async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok::<(), VulnerabilityError>(())
            })
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            VulnerabilityError::Timeout { seconds } => {
                assert_eq!(seconds, 0); // 50ms rounds down to 0 seconds
            }
            _ => panic!("Expected Timeout error"),
        }
    }

    #[tokio::test]
    async fn test_retry_with_backoff_success() {
        let config = RetryConfig::default();
        let counter = Arc::new(AtomicU32::new(0));

        let result = retry_with_backoff(config, || {
            let counter = counter.clone();
            async move {
                let count = counter.fetch_add(1, Ordering::SeqCst);
                if count < 2 {
                    Err(VulnerabilityError::Api(ApiError::Http {
                        status: 500,
                        message: "Internal Server Error".to_string(),
                    }))
                } else {
                    Ok("success")
                }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_with_backoff_max_attempts() {
        let config = RetryConfig {
            max_attempts: 2,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            backoff_multiplier: 2.0,
        };
        let counter = Arc::new(AtomicU32::new(0));

        let result = retry_with_backoff(config, || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err::<(), VulnerabilityError>(VulnerabilityError::Api(ApiError::Http {
                    status: 500,
                    message: "Internal Server Error".to_string(),
                }))
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_retry_non_retryable_error() {
        let config = RetryConfig::default();
        let counter = Arc::new(AtomicU32::new(0));

        let result = retry_with_backoff(config, || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err::<(), VulnerabilityError>(VulnerabilityError::Api(ApiError::Authentication))
            }
        })
        .await;

        assert!(result.is_err());
        // Should not retry authentication errors
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_health_checker() {
        let circuit_breaker = Default::default();
        let health_checker = HealthChecker::new(circuit_breaker);

        // Healthy service
        let status = health_checker
            .check_health(|| async { Ok::<(), VulnerabilityError>(()) })
            .await;
        assert_eq!(status, HealthStatus::Healthy);

        // Unhealthy service
        let status = health_checker
            .check_health(|| async {
                Err::<(), VulnerabilityError>(VulnerabilityError::Api(ApiError::ServiceUnavailable))
            })
            .await;
        assert_eq!(status, HealthStatus::Degraded);
    }

    #[test]
    fn test_is_retryable_error() {
        // Retryable errors
        assert!(is_retryable_error(&VulnerabilityError::Timeout {
            seconds: 30
        }));
        assert!(is_retryable_error(&VulnerabilityError::Api(
            ApiError::Http {
                status: 500,
                message: "Internal Server Error".to_string()
            }
        )));
        assert!(is_retryable_error(&VulnerabilityError::Api(
            ApiError::Http {
                status: 502,
                message: "Bad Gateway".to_string()
            }
        )));
        assert!(is_retryable_error(&VulnerabilityError::Api(
            ApiError::Http {
                status: 503,
                message: "Service Unavailable".to_string()
            }
        )));
        assert!(is_retryable_error(&VulnerabilityError::Api(
            ApiError::Http {
                status: 429,
                message: "Too Many Requests".to_string()
            }
        )));
        assert!(is_retryable_error(&VulnerabilityError::Api(
            ApiError::ServiceUnavailable
        )));

        // Non-retryable errors
        assert!(!is_retryable_error(&VulnerabilityError::Api(
            ApiError::Http {
                status: 400,
                message: "Bad Request".to_string()
            }
        )));
        assert!(!is_retryable_error(&VulnerabilityError::Api(
            ApiError::Http {
                status: 401,
                message: "Unauthorized".to_string()
            }
        )));
        assert!(!is_retryable_error(&VulnerabilityError::Api(
            ApiError::Http {
                status: 404,
                message: "Not Found".to_string()
            }
        )));
        assert!(!is_retryable_error(&VulnerabilityError::Api(
            ApiError::Authentication
        )));
    }
}
