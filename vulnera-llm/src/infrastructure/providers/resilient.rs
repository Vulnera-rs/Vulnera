//! Resilient LLM provider wrapper
//!
//! Adds circuit breaker and retry logic to any LlmProvider using
//! infrastructure from `vulnera-core`.

use async_trait::async_trait;
use futures::stream::BoxStream;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::domain::{
    CompletionRequest, CompletionResponse, LlmError, LlmProvider, ProviderInfo, StreamChunk,
};

/// Resilience configuration for LLM providers
#[derive(Debug, Clone)]
pub struct ResilienceConfig {
    /// Maximum number of retries for transient errors
    pub max_retries: u32,
    /// Initial backoff delay in milliseconds
    pub initial_backoff_ms: u64,
    /// Maximum backoff delay in milliseconds
    pub max_backoff_ms: u64,
    /// Number of failures before circuit opens
    pub circuit_breaker_threshold: u32,
    /// Time in seconds before circuit attempts to close
    pub circuit_breaker_timeout_secs: u64,
    /// Maximum requests allowed in half-open state
    pub half_open_max_requests: u32,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff_ms: 500,
            max_backoff_ms: 30_000,
            circuit_breaker_threshold: 5,
            circuit_breaker_timeout_secs: 60,
            half_open_max_requests: 2,
        }
    }
}

/// Circuit breaker state
#[derive(Debug, Clone, PartialEq)]
enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Mutable state for circuit breaker
struct CircuitBreakerState {
    state: CircuitState,
    failure_count: u32,
    last_failure_time: Option<std::time::Instant>,
    half_open_requests: u32,
}

/// Wraps any LlmProvider with resilience patterns
///
/// Provides:
/// - **Circuit Breaker**: Fails fast when provider is unavailable
/// - **Retry with Backoff**: Handles transient failures with exponential backoff
///
/// # Example
///
/// ```rust,ignore
/// use vulnera_llm::{GoogleAIProvider, ResilientProvider, ResilienceConfig};
///
/// let inner = GoogleAIProvider::new("api-key", "gemini-2.0-flash");
/// let provider = ResilientProvider::new(inner, ResilienceConfig::default());
///
/// // Now all calls are protected by circuit breaker and retry
/// let response = provider.complete(request).await?;
/// ```
pub struct ResilientProvider<P: LlmProvider> {
    inner: Arc<P>,
    config: ResilienceConfig,
    circuit_state: Arc<Mutex<CircuitBreakerState>>,
}

impl<P: LlmProvider> ResilientProvider<P> {
    /// Create a new resilient provider wrapper
    pub fn new(provider: P, config: ResilienceConfig) -> Self {
        Self {
            inner: Arc::new(provider),
            config,
            circuit_state: Arc::new(Mutex::new(CircuitBreakerState {
                state: CircuitState::Closed,
                failure_count: 0,
                last_failure_time: None,
                half_open_requests: 0,
            })),
        }
    }

    /// Create with default configuration
    pub fn with_defaults(provider: P) -> Self {
        Self::new(provider, ResilienceConfig::default())
    }

    /// Check if circuit allows request
    async fn can_execute(&self) -> Result<(), LlmError> {
        let mut state = self.circuit_state.lock().await;

        match state.state {
            CircuitState::Closed => Ok(()),
            CircuitState::Open => {
                // Check if enough time has passed to try half-open
                if let Some(last_failure) = state.last_failure_time {
                    let elapsed = last_failure.elapsed();
                    if elapsed >= Duration::from_secs(self.config.circuit_breaker_timeout_secs) {
                        debug!("Circuit breaker transitioning to half-open");
                        state.state = CircuitState::HalfOpen;
                        state.half_open_requests = 0;
                        Ok(())
                    } else {
                        Err(LlmError::CircuitOpen {
                            circuit: self.inner.info().id.to_string(),
                        })
                    }
                } else {
                    Err(LlmError::CircuitOpen {
                        circuit: self.inner.info().id.to_string(),
                    })
                }
            }
            CircuitState::HalfOpen => {
                if state.half_open_requests < self.config.half_open_max_requests {
                    state.half_open_requests += 1;
                    Ok(())
                } else {
                    Err(LlmError::CircuitOpen {
                        circuit: self.inner.info().id.to_string(),
                    })
                }
            }
        }
    }

    /// Record a successful request
    async fn on_success(&self) {
        let mut state = self.circuit_state.lock().await;

        match state.state {
            CircuitState::HalfOpen => {
                debug!("Circuit breaker closing after successful request in half-open state");
                state.state = CircuitState::Closed;
                state.failure_count = 0;
                state.half_open_requests = 0;
            }
            CircuitState::Closed => {
                // Reset failure count on success
                if state.failure_count > 0 {
                    state.failure_count = 0;
                }
            }
            _ => {}
        }
    }

    /// Record a failed request
    async fn on_failure(&self) {
        let mut state = self.circuit_state.lock().await;

        state.failure_count += 1;
        state.last_failure_time = Some(std::time::Instant::now());

        match state.state {
            CircuitState::Closed => {
                if state.failure_count >= self.config.circuit_breaker_threshold {
                    warn!(
                        failures = state.failure_count,
                        threshold = self.config.circuit_breaker_threshold,
                        "Circuit breaker opening due to failures"
                    );
                    state.state = CircuitState::Open;
                }
            }
            CircuitState::HalfOpen => {
                debug!("Circuit breaker reopening after failure in half-open state");
                state.state = CircuitState::Open;
                state.half_open_requests = 0;
            }
            _ => {}
        }
    }

    /// Execute with retry logic
    async fn execute_with_retry(
        &self,
        request: CompletionRequest,
    ) -> Result<CompletionResponse, LlmError> {
        let mut last_error = None;
        let mut backoff = self.config.initial_backoff_ms;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                debug!(
                    attempt = attempt,
                    backoff_ms = backoff,
                    "Retrying LLM request"
                );
                sleep(Duration::from_millis(backoff)).await;

                // Exponential backoff with jitter
                backoff = std::cmp::min(
                    (backoff * 2) + rand_jitter(backoff / 4),
                    self.config.max_backoff_ms,
                );
            }

            match self.inner.complete(request.clone()).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if !e.is_retryable() || attempt == self.config.max_retries {
                        return Err(e);
                    }

                    // Honor retry-after if provided
                    if let Some(retry_after) = e.retry_after()
                        && retry_after.as_millis() < self.config.max_backoff_ms as u128
                    {
                        backoff = retry_after.as_millis() as u64;
                    }

                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| LlmError::Other("Max retries exceeded".to_string())))
    }
}

/// Add some randomness to backoff to prevent thundering herd
fn rand_jitter(max: u64) -> u64 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos as u64) % max.max(1)
}

#[async_trait]
impl<P: LlmProvider + 'static> LlmProvider for ResilientProvider<P> {
    fn info(&self) -> ProviderInfo {
        let mut info = self.inner.info();
        // Indicate this is wrapped
        info.name = Box::leak(format!("{} (Resilient)", info.name).into_boxed_str());
        info
    }

    fn default_model(&self) -> &str {
        self.inner.default_model()
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError> {
        // Check circuit breaker
        self.can_execute().await?;

        // Execute with retry
        match self.execute_with_retry(request).await {
            Ok(response) => {
                self.on_success().await;
                Ok(response)
            }
            Err(e) => {
                self.on_failure().await;
                Err(e)
            }
        }
    }

    async fn complete_stream(
        &self,
        request: CompletionRequest,
    ) -> Result<BoxStream<'static, Result<StreamChunk, LlmError>>, LlmError> {
        // Check circuit breaker
        self.can_execute().await?;

        // For streaming, we don't retry individual chunks, just the initial connection
        match self.inner.complete_stream(request).await {
            Ok(stream) => {
                self.on_success().await;
                Ok(stream)
            }
            Err(e) => {
                self.on_failure().await;
                Err(e)
            }
        }
    }

    async fn health_check(&self) -> Result<(), LlmError> {
        self.inner.health_check().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ResilienceConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.circuit_breaker_threshold, 5);
    }

    #[test]
    fn test_rand_jitter() {
        let jitter = rand_jitter(100);
        assert!(jitter < 100);
    }
}
