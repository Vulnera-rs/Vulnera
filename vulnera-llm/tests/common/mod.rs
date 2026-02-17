//! Common test utilities and mock implementations

use async_trait::async_trait;
use futures::stream::{self, BoxStream};
use std::sync::Arc;
use tokio::sync::Mutex;
use vulnera_llm::domain::{
    CompletionRequest, CompletionResponse, ContentBlock, LlmError, LlmProvider,
    ProviderCapabilities, ProviderInfo, StopReason, StreamChunk, Usage,
};

/// Mock LLM provider for testing
pub struct MockLlmProvider {
    /// Response to return from complete()
    pub response: Option<CompletionResponse>,
    /// Streamed chunks to return from complete_stream()
    pub stream_chunks: Option<Vec<StreamChunk>>,
    /// Error to return (if any)
    pub error: Option<LlmError>,
    /// Captured requests for verification
    pub captured_requests: Arc<Mutex<Vec<CompletionRequest>>>,
}

impl MockLlmProvider {
    pub fn new() -> Self {
        Self {
            response: None,
            stream_chunks: None,
            error: None,
            captured_requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn with_response(mut self, response: CompletionResponse) -> Self {
        self.response = Some(response);
        self
    }

    pub fn with_stream_chunks(mut self, chunks: Vec<StreamChunk>) -> Self {
        self.stream_chunks = Some(chunks);
        self
    }

    pub fn with_error(mut self, error: LlmError) -> Self {
        self.error = Some(error);
        self
    }

    pub fn with_json_response(content: &str) -> Self {
        Self::new().with_response(create_completion_response(content))
    }
}

#[async_trait]
impl LlmProvider for MockLlmProvider {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: "mock",
            name: "Mock Provider",
            version: "test",
            capabilities: ProviderCapabilities::text_only(8192, 2048),
        }
    }

    fn default_model(&self) -> &str {
        "test-model"
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError> {
        self.captured_requests.lock().await.push(request);

        if let Some(error) = &self.error {
            return Err(error.clone());
        }

        self.response
            .clone()
            .ok_or_else(|| LlmError::Other("No response configured".to_string()))
    }

    async fn complete_stream(
        &self,
        request: CompletionRequest,
    ) -> Result<BoxStream<'static, Result<StreamChunk, LlmError>>, LlmError> {
        self.captured_requests.lock().await.push(request);

        if let Some(error) = &self.error {
            return Err(error.clone());
        }

        let chunks = if let Some(chunks) = &self.stream_chunks {
            chunks.clone()
        } else if let Some(response) = &self.response {
            create_stream_chunks(&response.text())
        } else {
            vec![StreamChunk {
                index: 0,
                delta: None,
                is_final: true,
                stop_reason: Some(StopReason::EndTurn),
                usage: Some(Usage::default()),
            }]
        };

        let stream = stream::iter(chunks.into_iter().map(Ok));
        Ok(Box::pin(stream))
    }
}

/// Create a standard LLM response with given content
pub fn create_completion_response(content: &str) -> CompletionResponse {
    CompletionResponse {
        id: "test-response-id".to_string(),
        model: "test-model".to_string(),
        content: vec![ContentBlock::text(content)],
        stop_reason: StopReason::EndTurn,
        usage: Usage {
            prompt_tokens: 100,
            completion_tokens: 50,
            total_tokens: 150,
            cached_tokens: None,
        },
        created: Some(1234567890),
    }
}

/// Create streaming chunks from content
pub fn create_stream_chunks(content: &str) -> Vec<StreamChunk> {
    if content.is_empty() {
        return vec![StreamChunk {
            index: 0,
            delta: None,
            is_final: true,
            stop_reason: Some(StopReason::EndTurn),
            usage: Some(Usage::default()),
        }];
    }

    vec![StreamChunk {
        index: 0,
        delta: Some(ContentBlock::text(content)),
        is_final: true,
        stop_reason: Some(StopReason::EndTurn),
        usage: Some(Usage::default()),
    }]
}

/// Create default test LlmConfig
pub fn create_test_config() -> vulnera_core::config::LlmConfig {
    use vulnera_core::config::{AzureOpenAIConfig, GoogleAIConfig, LlmConfig, OpenAIConfig};

    LlmConfig {
        provider: "google_ai".to_string(),
        google_ai: GoogleAIConfig {
            api_key: Some("test-api-key".to_string()),
            base_url: "https://test.api.example.com".to_string(),
        },
        openai: OpenAIConfig {
            api_key: Some("test-openai-key".to_string()),
            base_url: "https://api.openai.com/v1".to_string(),
            organization_id: None,
        },
        azure: AzureOpenAIConfig {
            endpoint: String::new(),
            api_key: None,
            deployment: String::new(),
            api_version: "2024-02-15-preview".to_string(),
        },
        default_model: "test-model".to_string(),
        explanation_model: Some("explanation-model".to_string()),
        code_fix_model: Some("code-fix-model".to_string()),
        enrichment_model: None,
        temperature: 0.7,
        max_tokens: 10240,
        timeout_seconds: 30,
        enable_streaming: false,
        resilience: Default::default(),
        enrichment: Default::default(),
    }
}
