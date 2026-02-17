//! Integration tests for GoogleAIProvider using wiremock

use futures::StreamExt;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use vulnera_llm::domain::{CompletionRequest, ContentBlock, LlmProvider, Message};
use vulnera_llm::infrastructure::providers::GoogleAIProvider;

fn create_provider(mock_server: &MockServer) -> GoogleAIProvider {
    GoogleAIProvider::new("test-api-key", "test-model")
        .with_base_url(mock_server.uri())
        .with_timeout(10)
}

fn create_test_request() -> CompletionRequest {
    CompletionRequest::new()
        .with_model("test-model")
        .with_message(Message::user("Hello, world!"))
        .with_max_tokens(100)
        .with_temperature(0.7)
}

#[tokio::test]
async fn test_google_ai_provider_complete_success() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "candidates": [{
            "content": {
                "parts": [
                    { "text": "Hello! How can I help you?" }
                ]
            },
            "finishReason": "STOP"
        }],
        "usageMetadata": {
            "promptTokenCount": 10,
            "candidatesTokenCount": 8,
            "totalTokenCount": 18
        }
    });

    Mock::given(method("POST"))
        .and(path("/models/test-model:generateContent"))
        .and(query_param("key", "test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .mount(&mock_server)
        .await;

    let provider = create_provider(&mock_server);
    let result = provider.complete(create_test_request()).await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.model, "test-model");
    assert_eq!(response.text(), "Hello! How can I help you?");
    assert!(!response.is_truncated());
}

#[tokio::test]
async fn test_google_ai_provider_api_error_rate_limited() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/models/test-model:generateContent"))
        .and(query_param("key", "test-api-key"))
        .respond_with(
            ResponseTemplate::new(429).set_body_json(&serde_json::json!({
                "error": {
                    "message": "Rate limit exceeded",
                    "code": "rate_limit_exceeded"
                }
            })),
        )
        .mount(&mock_server)
        .await;

    let provider = create_provider(&mock_server);
    let result = provider.complete(create_test_request()).await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("Rate limited"));
}

#[tokio::test]
async fn test_google_ai_provider_server_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/models/test-model:generateContent"))
        .and(query_param("key", "test-api-key"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(&serde_json::json!({
                "error": "Internal server error"
            })),
        )
        .mount(&mock_server)
        .await;

    let provider = create_provider(&mock_server);
    let result = provider.complete(create_test_request()).await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Service unavailable")
    );
}

#[tokio::test]
async fn test_google_ai_provider_malformed_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/models/test-model:generateContent"))
        .and(query_param("key", "test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not valid json"))
        .mount(&mock_server)
        .await;

    let provider = create_provider(&mock_server);
    let result = provider.complete(create_test_request()).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_google_ai_provider_stream_success() {
    let mock_server = MockServer::start().await;

    let stream_body = [
        serde_json::json!({
            "candidates": [{
                "content": { "parts": [{ "text": "Hello" }] },
                "finishReason": null
            }],
            "usageMetadata": {
                "promptTokenCount": 10,
                "candidatesTokenCount": 3,
                "totalTokenCount": 13
            }
        })
        .to_string(),
        serde_json::json!({
            "candidates": [{
                "content": { "parts": [{ "text": " world" }] },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 10,
                "candidatesTokenCount": 5,
                "totalTokenCount": 15
            }
        })
        .to_string(),
    ]
    .join("\n");

    Mock::given(method("POST"))
        .and(path("/models/test-model:streamGenerateContent"))
        .and(query_param("key", "test-api-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(stream_body)
                .insert_header("Content-Type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    let provider = create_provider(&mock_server);
    let mut request = create_test_request();
    request = request.with_stream(true);

    let result = provider.complete_stream(request).await;
    assert!(result.is_ok());

    let mut stream = result.unwrap();
    let mut chunks = Vec::new();

    while let Some(item) = stream.next().await {
        let chunk = item.expect("stream chunk should be Ok");
        if let Some(delta) = chunk.delta {
            if let ContentBlock::Text { text } = delta {
                chunks.push(text);
            }
        }
    }

    assert_eq!(chunks.join(""), "Hello world");
}
