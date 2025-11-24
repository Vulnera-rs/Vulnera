//! Secret verifier trait

use crate::domain::entities::SecretType;
use async_trait::async_trait;
use std::time::Duration;

// Import verifiers
use super::aws_verifier::AwsVerifier;
use super::github_verifier::GitHubVerifier;
use super::gitlab_verifier::GitLabVerifier;

/// Result of secret verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// Secret is verified (valid and active)
    Verified,
    /// Secret is invalid or inactive
    Invalid,
    /// Verification failed (network error, timeout, etc.)
    Failed,
    /// Verification not supported for this secret type
    NotSupported,
}

/// Trait for verifying secrets against live APIs
#[async_trait]
pub trait SecretVerifier: Send + Sync {
    /// Check if this verifier supports the given secret type
    fn supports(&self, secret_type: &SecretType) -> bool;

    /// Verify a secret against the live API
    ///
    /// # Arguments
    /// * `secret` - The secret to verify
    /// * `secret_type` - Type of secret
    /// * `timeout` - Maximum time to wait for verification
    ///
    /// # Returns
    /// Verification result indicating if the secret is valid
    async fn verify(
        &self,
        secret: &str,
        secret_type: &SecretType,
        timeout: Duration,
    ) -> VerificationResult;
}

/// Verification service that routes to appropriate verifiers
pub struct VerificationService {
    verifiers: Vec<Box<dyn SecretVerifier>>,
    timeout: Duration,
}

impl VerificationService {
    pub fn new(timeout: Duration) -> Self {
        let mut verifiers: Vec<Box<dyn SecretVerifier>> = Vec::new();
        verifiers.push(Box::new(AwsVerifier {}));
        verifiers.push(Box::new(GitHubVerifier::new()));
        verifiers.push(Box::new(GitLabVerifier::new()));

        Self { verifiers, timeout }
    }

    /// Verify a secret using the appropriate verifier
    pub async fn verify_secret(
        &self,
        secret: &str,
        secret_type: &SecretType,
    ) -> VerificationResult {
        for verifier in &self.verifiers {
            if verifier.supports(secret_type) {
                return verifier.verify(secret, secret_type, self.timeout).await;
            }
        }

        VerificationResult::NotSupported
    }
}
