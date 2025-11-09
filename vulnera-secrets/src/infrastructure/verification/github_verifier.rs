//! GitHub token verifier

use crate::domain::entities::SecretType;
use crate::infrastructure::verification::{SecretVerifier, VerificationResult};
use async_trait::async_trait;
use std::time::Duration;
use tracing::{debug, warn};

/// GitHub token verifier
pub struct GitHubVerifier;

#[async_trait]
impl SecretVerifier for GitHubVerifier {
    fn supports(&self, secret_type: &SecretType) -> bool {
        secret_type == &SecretType::GitHubToken
    }

    async fn verify(
        &self,
        secret: &str,
        _secret_type: &SecretType,
        timeout: Duration,
    ) -> VerificationResult {
        // Verify GitHub token by calling GitHub API
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let response = client
            .get("https://api.github.com/user")
            .header("Authorization", format!("Bearer {}", secret))
            .header("User-Agent", "Vulnera-Secret-Detector")
            .send()
            .await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    debug!("GitHub token verified successfully");
                    VerificationResult::Verified
                } else if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                    debug!("GitHub token is invalid");
                    VerificationResult::Invalid
                } else {
                    warn!(status = %resp.status(), "Unexpected status from GitHub API");
                    VerificationResult::Failed
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to verify GitHub token");
                VerificationResult::Failed
            }
        }
    }
}
