//! Circuit breaker for API clients

use crate::application::errors::VulnerabilityError;
use crate::domain::Package;
use crate::infrastructure::api_clients::traits::{RawVulnerability, VulnerabilityApiClient};
use crate::infrastructure::resilience::CircuitBreaker;
use async_trait::async_trait;
use std::sync::Arc;

/// Wrapper that adds circuit breaker protection to an API client
pub struct CircuitBreakerApiClient {
    inner: Arc<dyn VulnerabilityApiClient>,
    circuit_breaker: Arc<CircuitBreaker>,
}

impl CircuitBreakerApiClient {
    /// Create a new circuit breaker-wrapped API client
    pub fn new(
        inner: Arc<dyn VulnerabilityApiClient>,
        circuit_breaker: Arc<CircuitBreaker>,
    ) -> Self {
        Self {
            inner,
            circuit_breaker,
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

        self.circuit_breaker
            .execute(move || {
                let inner = inner.clone();
                let package = package.clone();
                async move { inner.query_vulnerabilities(&package).await }
            })
            .await
    }

    async fn get_vulnerability_details(
        &self,
        id: &str,
    ) -> Result<Option<RawVulnerability>, VulnerabilityError> {
        let inner = self.inner.clone();
        let id = id.to_string();

        self.circuit_breaker
            .execute(move || {
                let inner = inner.clone();
                let id = id.clone();
                async move { inner.get_vulnerability_details(&id).await }
            })
            .await
    }
}
