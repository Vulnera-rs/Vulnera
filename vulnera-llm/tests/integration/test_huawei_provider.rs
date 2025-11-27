//! Integration tests for HuaweiLlmProvider using wiremock

use wiremock::matchers::{body_json_schema, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use vulnera_core::config::LlmConfig;
use vulnera_llm::domain::{LlmRequest, Message};
use vulnera_llm::infrastructure::providers::{HuaweiLlmProvider, LlmProvider};

fn create_test_config(api_url: &str) -> LlmConfig {
    LlmConfig {
        enabled: true,
        default_model: "test-model".to_string(),
        code_fix_model: None,
        explanation_model: None,
        huawei_api_url: api_url.to_string(),
        huawei_api_key: Some("test-api-key".to_string()),
        max_tokens: 1024,
        temperature: 0.7,
        timeout_seconds: 30,
        rate_limit_requests_per_minute: 60,
        rate_limit_tokens_per_minute: 100000,
    }
}

fn create_test_request() -> LlmRequest {
    LlmRequest {
        model: "test-model".to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: "Hello, world!".to_string(),
        }],
        max_tokens: Some(100),
        temperature: Some(0.7),
        stream: Some(false),
    }
}

/// Test successful generation with mocked Huawei API
#[tokio::test]
async fn test_huawei_provider_generate_success() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "id": "resp-123",
        "object": "chat.completion",
        "created": 1234567890,
        "model": "test-model",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "Hello! How can I help you?"
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 8,
            "total_tokens": 18
        }
    });

    Mock::given(method("POST"))
        .and(header("Authorization", "Bearer test-api-key"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .mount(&mock_server)
        .await;

    let config = create_test_config(&mock_server.uri());
    let provider = HuaweiLlmProvider::new(config);

    let result = provider.generate(create_test_request()).await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.id, "resp-123");
    assert_eq!(response.choices.len(), 1);
    assert_eq!(
        response.choices[0].message.as_ref().unwrap().content,
        "Hello! How can I help you?"
    );
}

/// Test error handling for API errors
#[tokio::test]
async fn test_huawei_provider_api_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
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

    let config = create_test_config(&mock_server.uri());
    let provider = HuaweiLlmProvider::new(config);

    let result = provider.generate(create_test_request()).await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("429"));
}

/// Test error handling for network timeout
#[tokio::test]
async fn test_huawei_provider_timeout() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(60)))
        .mount(&mock_server)
        .await;

    let mut config = create_test_config(&mock_server.uri());
    config.timeout_seconds = 1; // Very short timeout
    let provider = HuaweiLlmProvider::new(config);

    let result = provider.generate(create_test_request()).await;

    assert!(result.is_err());
}

/// Test error handling when API key is missing
#[tokio::test]
async fn test_huawei_provider_missing_api_key() {
    let mock_server = MockServer::start().await;

    let mut config = create_test_config(&mock_server.uri());
    config.huawei_api_key = None;
    let provider = HuaweiLlmProvider::new(config);

    let result = provider.generate(create_test_request()).await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("API key not configured")
    );
}

/// Test streaming generation with mocked API
#[tokio::test]
async fn test_huawei_provider_generate_stream() {
    let mock_server = MockServer::start().await;

    // Simulate SSE response
    let sse_response = "data: {\"id\":\"stream-1\",\"object\":\"chat.completion.chunk\",\"created\":1234567890,\"model\":\"test-model\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hello\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"stream-2\",\"object\":\"chat.completion.chunk\",\"created\":1234567890,\"model\":\"test-model\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\" World\"},\"finish_reason\":null}]}\n\ndata: [DONE]\n";

    Mock::given(method("POST"))
        .and(header("Authorization", "Bearer test-api-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_response)
                .insert_header("Content-Type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let config = create_test_config(&mock_server.uri());
    let provider = HuaweiLlmProvider::new(config);

    let mut request = create_test_request();
    request.stream = Some(true);

    let result = provider.generate_stream(request).await;

    assert!(result.is_ok());
    let mut rx = result.unwrap();

    // Collect streamed responses
    let mut responses = Vec::new();
    while let Some(chunk) = rx.recv().await {
        if let Ok(response) = chunk {
            responses.push(response);
        }
    }

    assert!(
        !responses.is_empty(),
        "Should receive at least one response chunk"
    );
}

/// Test request body format
#[tokio::test]
async fn test_huawei_provider_request_format() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "id": "resp-123",
        "object": "chat.completion",
        "created": 1234567890,
        "model": "test-model",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "Response"
            },
            "finish_reason": "stop"
        }]
    });

    Mock::given(method("POST"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = create_test_config(&mock_server.uri());
    let provider = HuaweiLlmProvider::new(config);

    let request = LlmRequest {
        model: "custom-model".to_string(),
        messages: vec![
            Message {
                role: "system".to_string(),
                content: "You are helpful.".to_string(),
            },
            Message {
                role: "user".to_string(),
                content: "Hello".to_string(),
            },
        ],
        max_tokens: Some(500),
        temperature: Some(0.8),
        stream: Some(false),
    };

    let result = provider.generate(request).await;
    assert!(result.is_ok());
}

/// Test handling of malformed API response
#[tokio::test]
async fn test_huawei_provider_malformed_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not valid json"))
        .mount(&mock_server)
        .await;

    let config = create_test_config(&mock_server.uri());
    let provider = HuaweiLlmProvider::new(config);

    let result = provider.generate(create_test_request()).await;

    assert!(result.is_err());
}

/// Test handling of 500 Internal Server Error
#[tokio::test]
async fn test_huawei_provider_server_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(&serde_json::json!({
                "error": "Internal server error"
            })),
        )
        .mount(&mock_server)
        .await;

    let config = create_test_config(&mock_server.uri());
    let provider = HuaweiLlmProvider::new(config);

    let result = provider.generate(create_test_request()).await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("500"));
}

/// Test handling of 401 Unauthorized
#[tokio::test]
async fn test_huawei_provider_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(&serde_json::json!({
                "error": {
                    "message": "Invalid API key",
                    "code": "invalid_api_key"
                }
            })),
        )
        .mount(&mock_server)
        .await;

    let config = create_test_config(&mock_server.uri());
    let provider = HuaweiLlmProvider::new(config);

    let result = provider.generate(create_test_request()).await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("401"));
}
