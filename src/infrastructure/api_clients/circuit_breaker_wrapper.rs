//! Circuit breaker and retry wrapper for API clients

use crate::application::errors::VulnerabilityError;
use crate::domain::Package;
use crate::infrastructure::api_clients::traits::{RawVulnerability, VulnerabilityApiClient};
use crate::infrastructure::resilience::{CircuitBreaker, RetryConfig, retry_with_backoff};
use async_trait::async_trait;
use std::sync::Arc;

/// Wrapper that adds circuit breaker protection and retry logic to an API client
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
