//! GitLab token verifier

use crate::domain::entities::SecretType;
use crate::infrastructure::verification::{SecretVerifier, VerificationResult};
use async_trait::async_trait;
use std::time::Duration;
use tracing::{debug, warn};

/// GitLab token verifier
pub struct GitLabVerifier;

#[async_trait]
impl SecretVerifier for GitLabVerifier {
    fn supports(&self, secret_type: &SecretType) -> bool {
        secret_type == &SecretType::GitLabToken
    }

    async fn verify(
        &self,
        secret: &str,
        _secret_type: &SecretType,
        timeout: Duration,
    ) -> VerificationResult {
        // Verify GitLab token by calling GitLab API
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let response = client
            .get("https://gitlab.com/api/v4/user")
            .header("PRIVATE-TOKEN", secret)
            .send()
            .await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    debug!("GitLab token verified successfully");
                    VerificationResult::Verified
                } else if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                    debug!("GitLab token is invalid");
                    VerificationResult::Invalid
                } else {
                    warn!(status = %resp.status(), "Unexpected status from GitLab API");
                    VerificationResult::Failed
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to verify GitLab token");
                VerificationResult::Failed
            }
        }
    }
}
