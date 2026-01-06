use std::time::Duration;
use vulnera_secrets::domain::entities::SecretType;
use vulnera_secrets::infrastructure::verification::{
    GitHubVerifier, GitLabVerifier, SecretVerifier, VerificationResult,
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
