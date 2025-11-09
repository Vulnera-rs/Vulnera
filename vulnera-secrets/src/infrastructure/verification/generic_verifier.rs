//! Generic API key verifier

use crate::domain::entities::SecretType;
use crate::infrastructure::verification::{SecretVerifier, VerificationResult};
use async_trait::async_trait;
use std::time::Duration;
use tracing::debug;

/// Generic API key verifier (configurable endpoints)
pub struct GenericVerifier {
    endpoint: String,
    header_name: String,
}

impl GenericVerifier {
    pub fn new(endpoint: String, header_name: String) -> Self {
        Self {
            endpoint,
            header_name,
        }
    }
}

#[async_trait]
impl SecretVerifier for GenericVerifier {
    fn supports(&self, _secret_type: &SecretType) -> bool {
        // Generic verifier can be configured for any secret type
        true
    }

    async fn verify(
        &self,
        secret: &str,
        _secret_type: &SecretType,
        timeout: Duration,
    ) -> VerificationResult {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let response = client
            .get(&self.endpoint)
            .header(&self.header_name, secret)
            .send()
            .await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    debug!("Generic API key verified successfully");
                    VerificationResult::Verified
                } else if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                    VerificationResult::Invalid
                } else {
                    VerificationResult::Failed
                }
            }
            Err(_) => VerificationResult::Failed,
        }
    }
}
