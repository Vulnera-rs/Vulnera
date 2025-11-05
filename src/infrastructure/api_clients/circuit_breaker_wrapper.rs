//! Circuit breaker and retry wrapper for API clients

use crate::application::errors::VulnerabilityError;
use crate::domain::vulnerability::entities::Package;
use crate::infrastructure::api_clients::traits::{RawVulnerability, VulnerabilityApiClient};
use crate::infrastructure::resilience::{CircuitBreaker, RetryConfig, retry_with_backoff};
use async_trait::async_trait;
use std::sync::Arc;

/// Wrapper that adds circuit breaker protection and retry logic to an API client
///
/// This wrapper implements the **Decorator Pattern** to enhance existing API clients
/// with resilience patterns without modifying their core implementation. It combines
/// two complementary patterns:
///
/// **1. Circuit Breaker Pattern:**
/// - Prevents cascading failures when external services are down
/// - Provides fast failure when circuits are open
/// - Enables automatic recovery testing
///
/// **2. Retry Pattern with Exponential Backoff:**
/// - Handles transient failures (network blips, rate limits)
/// - Increases delay between retries to avoid overwhelming services
/// - Configurable maximum attempts and backoff parameters
///
/// **Combined Resilience Strategy:**
/// ```text
/// Request -> Circuit Breaker (First Line of Defense)
///    +- Circuit Open -> Immediate Failure
///    +- Circuit Closed -> Retry Logic (Second Line of Defense)
///        +- Success -> Return Result
///        +- All Retries Failed -> Record Failure, Update Circuit State
///        +- Timeout -> Record Failure, Update Circuit State
/// ```
///
/// **Configuration:**
/// - Circuit breaker has its own failure threshold and recovery timeout
/// - Retry logic uses exponential backoff with jitter
/// - Both patterns work independently but complement each other
///
/// **Use Cases:**
/// - External API calls (OSV, NVD, GHSA)
/// - Database connections
/// - Network service calls
/// - Any operation that might fail transiently
pub struct CircuitBreakerApiClient {
    inner: Arc<dyn VulnerabilityApiClient>,
    circuit_breaker: Arc<CircuitBreaker>,
    retry_config: RetryConfig,
}

impl CircuitBreakerApiClient {
    /// Create a new circuit breaker-wrapped API client with retry logic
    pub fn new(
        inner: Arc<dyn VulnerabilityApiClient>,
        circuit_breaker: Arc<CircuitBreaker>,
        retry_config: RetryConfig,
    ) -> Self {
        Self {
            inner,
            circuit_breaker,
            retry_config,
        }
    }
}

#[async_trait]
impl VulnerabilityApiClient for CircuitBreakerApiClient {
    async fn query_vulnerabilities(
        &self,
        package: &Package,
    ) -> Result<Vec<RawVulnerability>, VulnerabilityError> {
        let inner = self.inner.clone();
        let package = package.clone();
        let retry_config = self.retry_config.clone();

        self.circuit_breaker
            .execute(move || {
                let inner = inner.clone();
                let package = package.clone();
                let retry_config = retry_config.clone();
                async move {
                    // Apply retry logic with exponential backoff
                    // Retry only happens when circuit is closed (checked by circuit breaker)
                    retry_with_backoff(retry_config, move || {
                        let inner = inner.clone();
                        let package = package.clone();
                        async move { inner.query_vulnerabilities(&package).await }
                    })
                    .await
                }
            })
            .await
    }

    async fn get_vulnerability_details(
        &self,
        id: &str,
    ) -> Result<Option<RawVulnerability>, VulnerabilityError> {
        let inner = self.inner.clone();
        let id = id.to_string();
        let retry_config = self.retry_config.clone();

        self.circuit_breaker
            .execute(move || {
                let inner = inner.clone();
                let id = id.clone();
                let retry_config = retry_config.clone();
                async move {
                    // Apply retry logic with exponential backoff
                    // Retry only happens when circuit is closed (checked by circuit breaker)
                    retry_with_backoff(retry_config, move || {
                        let inner = inner.clone();
                        let id = id.clone();
                        async move { inner.get_vulnerability_details(&id).await }
                    })
                    .await
                }
            })
            .await
    }
}
