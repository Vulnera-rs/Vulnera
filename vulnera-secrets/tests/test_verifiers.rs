use async_trait::async_trait;
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use vulnera_secrets::domain::entities::SecretType;
use vulnera_secrets::infrastructure::verification::{
    GitHubVerifier, GitLabVerifier, SecretVerifier, VerificationResult, VerificationService,
};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_github_verifier_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("Authorization", "Bearer valid_token"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let verifier = GitHubVerifier::with_base_url(mock_server.uri());
    let result = verifier
        .verify(
            "valid_token",
            &SecretType::GitHubToken,
            None,
            Duration::from_secs(1),
        )
        .await;

    assert_eq!(result, VerificationResult::Verified);
}

#[tokio::test]
async fn test_github_verifier_invalid() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock_server)
        .await;

    let verifier = GitHubVerifier::with_base_url(mock_server.uri());
    let result = verifier
        .verify(
            "invalid_token",
            &SecretType::GitHubToken,
            None,
            Duration::from_secs(1),
        )
        .await;

    assert_eq!(result, VerificationResult::Invalid);
}

#[tokio::test]
async fn test_gitlab_verifier_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("PRIVATE-TOKEN", "valid_token"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let verifier = GitLabVerifier::with_base_url(mock_server.uri());
    let result = verifier
        .verify(
            "valid_token",
            &SecretType::GitLabToken,
            None,
            Duration::from_secs(1),
        )
        .await;

    assert_eq!(result, VerificationResult::Verified);
}

struct CountingVerifier {
    calls: Arc<Mutex<usize>>,
}

#[async_trait]
impl SecretVerifier for CountingVerifier {
    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(secret_type, SecretType::ApiKey)
    }

    async fn verify(
        &self,
        _secret: &str,
        _secret_type: &SecretType,
        _context: Option<&HashMap<SecretType, String>>,
        _timeout: Duration,
    ) -> VerificationResult {
        let mut calls = self.calls.lock().await;
        *calls += 1;
        VerificationResult::Verified
    }
}

#[tokio::test]
async fn test_verification_service_caches_results() {
    let calls = Arc::new(Mutex::new(0usize));
    let verifier = Arc::new(CountingVerifier {
        calls: calls.clone(),
    });

    let service = VerificationService::with_verifiers(Duration::from_secs(1), vec![verifier]);

    let first = service
        .verify_secret("same-secret", &SecretType::ApiKey, None)
        .await;
    let second = service
        .verify_secret("same-secret", &SecretType::ApiKey, None)
        .await;

    assert_eq!(first, VerificationResult::Verified);
    assert_eq!(second, VerificationResult::Verified);
    assert_eq!(*calls.lock().await, 1);
}
