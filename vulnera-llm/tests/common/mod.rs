//! Common test utilities and mock implementations

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::mpsc;
use vulnera_llm::domain::{Choice, LlmRequest, LlmResponse, Message, Usage};
use vulnera_llm::infrastructure::providers::LlmProvider;

/// Mock LLM provider for testing
pub struct MockLlmProvider {
    /// Response to return from generate()
    pub response: Option<LlmResponse>,
    /// Error message to return (if any)
    pub error: Option<String>,
    /// Captured requests for verification
    pub captured_requests: Arc<tokio::sync::Mutex<Vec<LlmRequest>>>,
}

impl MockLlmProvider {
    pub fn new() -> Self {
        Self {
            response: None,
            error: None,
            captured_requests: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    pub fn with_response(mut self, response: LlmResponse) -> Self {
        self.response = Some(response);
        self
    }

    pub fn with_error(mut self, error: &str) -> Self {
        self.error = Some(error.to_string());
        self
    }

    pub fn with_json_response(content: &str) -> Self {
        Self::new().with_response(create_llm_response(content))
    }
}

#[async_trait]
impl LlmProvider for MockLlmProvider {
    async fn generate(&self, request: LlmRequest) -> Result<LlmResponse, anyhow::Error> {
        // Capture the request
        self.captured_requests.lock().await.push(request);

        if let Some(error) = &self.error {
            return Err(anyhow::anyhow!("{}", error));
        }

        self.response
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No response configured"))
    }

    async fn generate_stream(
        &self,
        request: LlmRequest,
    ) -> Result<mpsc::Receiver<Result<LlmResponse, anyhow::Error>>, anyhow::Error> {
        // Capture the request
        self.captured_requests.lock().await.push(request);

        if let Some(error) = &self.error {
            return Err(anyhow::anyhow!("{}", error));
        }

        let (tx, rx) = mpsc::channel(10);

        // Send the response as a single chunk if available
        if let Some(response) = &self.response {
            let response_clone = response.clone();
            tokio::spawn(async move {
                let _ = tx.send(Ok(response_clone)).await;
            });
        }

        Ok(rx)
    }
}

/// Create a standard LLM response with given content
pub fn create_llm_response(content: &str) -> LlmResponse {
    LlmResponse {
        id: "test-response-id".to_string(),
        object: "chat.completion".to_string(),
        created: 1234567890,
        model: "test-model".to_string(),
        choices: vec![Choice {
            index: 0,
            message: Some(Message {
                role: "assistant".to_string(),
                content: content.to_string(),
            }),
            delta: None,
            finish_reason: Some("stop".to_string()),
        }],
        usage: Some(Usage {
            prompt_tokens: 100,
            completion_tokens: 50,
            total_tokens: 150,
        }),
    }
}

/// Create a streaming LLM response with delta content
pub fn create_streaming_response(content: &str) -> LlmResponse {
    LlmResponse {
        id: "test-stream-id".to_string(),
        object: "chat.completion.chunk".to_string(),
        created: 1234567890,
        model: "test-model".to_string(),
        choices: vec![Choice {
            index: 0,
            message: None,
            delta: Some(Message {
                role: "assistant".to_string(),
                content: content.to_string(),
            }),
            finish_reason: None,
        }],
        usage: None,
    }
}

/// Create default test LlmConfig
pub fn create_test_config() -> vulnera_core::config::LlmConfig {
    vulnera_core::config::LlmConfig {
        enabled: true,
        default_model: "test-model".to_string(),
        code_fix_model: Some("code-fix-model".to_string()),
        explanation_model: Some("explanation-model".to_string()),
        huawei_api_url: "https://test.api.example.com".to_string(),
        huawei_api_key: Some("test-api-key".to_string()),
        max_tokens: 1024,
        temperature: 0.7,
        timeout_seconds: 30,
        rate_limit_requests_per_minute: 60,
        rate_limit_tokens_per_minute: 100000,
    }
}
