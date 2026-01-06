//! GitLab token verifier

use crate::domain::entities::SecretType;
use crate::infrastructure::verification::{SecretVerifier, VerificationResult};
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, warn};

/// GitLab token verifier
pub struct GitLabVerifier {
    base_url: String,
}

impl GitLabVerifier {
    pub fn new() -> Self {
        Self {
            base_url: "https://gitlab.com/api/v4".to_string(),
        }
    }

    pub fn with_base_url(base_url: String) -> Self {
        Self { base_url }
    }
}

impl Default for GitLabVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretVerifier for GitLabVerifier {
    fn supports(&self, secret_type: &SecretType) -> bool {
        secret_type == &SecretType::GitLabToken
    }

    async fn verify(
        &self,
        secret: &str,
        _secret_type: &SecretType,
        _context: Option<&HashMap<SecretType, String>>,
        timeout: Duration,
    ) -> VerificationResult {
        // Verify GitLab token by calling GitLab API
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let url = format!("{}/user", self.base_url.trim_end_matches('/'));

        let response = client
            .get(&url)
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
