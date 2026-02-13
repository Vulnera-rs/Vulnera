//! Secret verifier trait

use crate::domain::entities::SecretType;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

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
    /// * `context` - Optional context (e.g., other secrets found in the same file)
    /// * `timeout` - Maximum time to wait for verification
    ///
    /// # Returns
    /// Verification result indicating if the secret is valid
    async fn verify(
        &self,
        secret: &str,
        secret_type: &SecretType,
        context: Option<&HashMap<SecretType, String>>,
        timeout: Duration,
    ) -> VerificationResult;
}

/// Registry for verifier providers
#[derive(Default)]
pub struct VerifierRegistry {
    verifiers: Vec<Arc<dyn SecretVerifier>>,
}

impl VerifierRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, verifier: Arc<dyn SecretVerifier>) {
        self.verifiers.push(verifier);
    }

    pub fn resolve(&self, secret_type: &SecretType) -> Option<Arc<dyn SecretVerifier>> {
        self.verifiers
            .iter()
            .find(|verifier| verifier.supports(secret_type))
            .cloned()
    }
}

/// Verification service that routes to appropriate verifiers
pub struct VerificationService {
    registry: VerifierRegistry,
    timeout: Duration,
    cache: RwLock<HashMap<String, VerificationResult>>,
}

impl VerificationService {
    const MAX_CACHE_ENTRIES: usize = 10_000;

    pub fn new(timeout: Duration) -> Self {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AwsVerifier {}));
        registry.register(Arc::new(GitHubVerifier::new()));
        registry.register(Arc::new(GitLabVerifier::new()));

        Self::with_registry(timeout, registry)
    }

    pub fn with_registry(timeout: Duration, registry: VerifierRegistry) -> Self {
        Self {
            registry,
            timeout,
            cache: RwLock::new(HashMap::new()),
        }
    }

    pub fn with_verifiers(timeout: Duration, verifiers: Vec<Arc<dyn SecretVerifier>>) -> Self {
        let mut registry = VerifierRegistry::new();
        for verifier in verifiers {
            registry.register(verifier);
        }
        Self::with_registry(timeout, registry)
    }

    fn cache_key(secret: &str, secret_type: &SecretType) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let secret_hash = format!("{:x}", hasher.finalize());
        format!("{:?}:{}", secret_type, secret_hash)
    }

    /// Verify a secret using the appropriate verifier
    pub async fn verify_secret(
        &self,
        secret: &str,
        secret_type: &SecretType,
        context: Option<&HashMap<SecretType, String>>,
    ) -> VerificationResult {
        let cache_key = Self::cache_key(secret, secret_type);

        if let Some(cached) = self.cache.read().await.get(&cache_key).cloned() {
            return cached;
        }

        let result = if let Some(verifier) = self.registry.resolve(secret_type) {
            verifier
                .verify(secret, secret_type, context, self.timeout)
                .await
        } else {
            VerificationResult::NotSupported
        };

        {
            let mut cache = self.cache.write().await;
            if cache.len() >= Self::MAX_CACHE_ENTRIES {
                cache.clear();
            }
            cache.insert(cache_key, result.clone());
        }

        result
    }
}
