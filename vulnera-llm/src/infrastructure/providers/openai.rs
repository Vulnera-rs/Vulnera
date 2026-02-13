//! OpenAI-compatible provider implementation
//!
//! Works with OpenAI, Azure OpenAI, and any OpenAI-compatible API.

use async_trait::async_trait;
use futures::stream::{self, BoxStream};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error};

use crate::domain::{
    CompletionRequest, CompletionResponse, ContentBlock, LlmError, LlmProvider,
    ProviderCapabilities, ProviderInfo, Role, StopReason, StreamChunk, Usage,
};

/// OpenAI-compatible provider
///
/// Works with:
/// - OpenAI API
/// - Azure OpenAI Service
/// - Local LLMs with OpenAI-compatible APIs (Ollama, vLLM, etc.)
pub struct OpenAIProvider {
    client: Client,
    api_key: String,
    base_url: String,
    model: String,
    organization_id: Option<String>,
    /// For Azure: deployment name (overrides model in URL)
    azure_deployment: Option<String>,
    /// For Azure: API version
    azure_api_version: Option<String>,
}

impl OpenAIProvider {
    /// Create a new OpenAI provider
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .unwrap_or_else(|e| {
                error!(error = %e, "Failed to build HTTP client with custom timeout, using default client");
                Client::new()
            });

        Self {
            client,
            api_key: api_key.into(),
            base_url: "https://api.openai.com/v1".to_string(),
            model: model.into(),
            organization_id: None,
            azure_deployment: None,
            azure_api_version: None,
        }
    }

    /// Create for Azure OpenAI
    pub fn azure(
        endpoint: impl Into<String>,
        api_key: impl Into<String>,
        deployment: impl Into<String>,
        api_version: impl Into<String>,
    ) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .unwrap_or_else(|e| {
                error!(error = %e, "Failed to build Azure HTTP client with custom timeout, using default client");
                Client::new()
            });

        let deployment_str = deployment.into();

        Self {
            client,
            api_key: api_key.into(),
            base_url: endpoint.into(),
            model: deployment_str.clone(),
            organization_id: None,
            azure_deployment: Some(deployment_str),
            azure_api_version: Some(api_version.into()),
        }
    }

    /// Set custom base URL
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Set organization ID
    pub fn with_organization(mut self, org_id: impl Into<String>) -> Self {
        self.organization_id = Some(org_id.into());
        self
    }

    /// Get the chat completions URL
    fn chat_url(&self) -> String {
        if let Some(ref deployment) = self.azure_deployment {
            let api_version = self
                .azure_api_version
                .as_deref()
                .unwrap_or("2024-02-15-preview");
            format!(
                "{}/openai/deployments/{}/chat/completions?api-version={}",
                self.base_url, deployment, api_version
            )
        } else {
            format!("{}/chat/completions", self.base_url)
        }
    }

    /// Convert to OpenAI request format
    fn to_openai_request(&self, request: &CompletionRequest) -> OpenAIRequest {
        let messages: Vec<OpenAIMessage> = request
            .messages
            .iter()
            .map(|msg| {
                let role = match msg.role {
                    Role::System => "system",
                    Role::User => "user",
                    Role::Assistant => "assistant",
                    Role::Tool => "tool",
                };

                OpenAIMessage {
                    role: role.to_string(),
                    content: Some(msg.text()),
                    name: msg.name.clone(),
                }
            })
            .collect();

        OpenAIRequest {
            model: request.model.clone().unwrap_or_else(|| self.model.clone()),
            messages,
            max_tokens: request.max_tokens,
            temperature: request.temperature,
            top_p: request.top_p,
            frequency_penalty: request.frequency_penalty,
            presence_penalty: request.presence_penalty,
            stop: if request.stop.is_empty() {
                None
            } else {
                Some(request.stop.clone())
            },
            stream: request.stream,
        }
    }

    /// Convert from OpenAI response format
    fn parse_openai_response(&self, response: OpenAIResponse) -> CompletionResponse {
        let choice = response.choices.into_iter().next();

        let content = choice
            .as_ref()
            .and_then(|c| c.message.as_ref())
            .map(|m| {
                vec![ContentBlock::Text {
                    text: m.content.clone().unwrap_or_default(),
                }]
            })
            .unwrap_or_default();

        let stop_reason = choice
            .as_ref()
            .and_then(|c| c.finish_reason.as_deref())
            .map(|r| match r {
                "stop" => StopReason::EndTurn,
                "length" => StopReason::MaxTokens,
                "tool_calls" | "function_call" => StopReason::ToolUse,
                "content_filter" => StopReason::ContentFilter,
                _ => StopReason::Other,
            })
            .unwrap_or(StopReason::Other);

        let usage = response
            .usage
            .map(|u| Usage {
                prompt_tokens: u.prompt_tokens,
                completion_tokens: u.completion_tokens,
                total_tokens: u.total_tokens,
                cached_tokens: None,
            })
            .unwrap_or_default();

        CompletionResponse {
            id: response.id,
            model: response.model,
            content,
            stop_reason,
            usage,
            created: Some(response.created),
        }
    }
}

#[async_trait]
impl LlmProvider for OpenAIProvider {
    fn info(&self) -> ProviderInfo {
        let is_azure = self.azure_deployment.is_some();
        ProviderInfo {
            id: if is_azure { "azure" } else { "openai" },
            name: if is_azure { "Azure OpenAI" } else { "OpenAI" },
            version: "v1",
            capabilities: ProviderCapabilities {
                streaming: true,
                function_calling: true,
                vision: true,
                json_mode: true,
                max_context_tokens: 128_000, // GPT-4 Turbo
                max_output_tokens: 4096,
            },
        }
    }

    fn default_model(&self) -> &str {
        &self.model
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError> {
        let url = self.chat_url();
        let openai_request = self.to_openai_request(&request);

        debug!(model = %openai_request.model, "Sending request to OpenAI-compatible API");

        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/json");

        // Add auth header based on provider type
        if self.azure_deployment.is_some() {
            req = req.header("api-key", &self.api_key);
        } else {
            req = req.header("Authorization", format!("Bearer {}", self.api_key));
            if let Some(ref org) = self.organization_id {
                req = req.header("OpenAI-Organization", org);
            }
        }

        let response = req.json(&openai_request).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();

            if status.as_u16() == 429 {
                // Try to parse retry-after
                return Err(LlmError::rate_limited(text));
            } else if status.as_u16() == 401 || status.as_u16() == 403 {
                return Err(LlmError::auth(text));
            } else if status.as_u16() >= 500 {
                return Err(LlmError::ServiceUnavailable(text));
            }

            error!(status = %status, "OpenAI API error: {}", text);
            return Err(LlmError::InvalidResponse(format!(
                "API error {}: {}",
                status, text
            )));
        }

        let openai_response: OpenAIResponse = response.json().await?;
        Ok(self.parse_openai_response(openai_response))
    }

    async fn complete_stream(
        &self,
        request: CompletionRequest,
    ) -> Result<BoxStream<'static, Result<StreamChunk, LlmError>>, LlmError> {
        let url = self.chat_url();
        let mut openai_request = self.to_openai_request(&request);
        openai_request.stream = Some(true);

        debug!(
            model = %openai_request.model,
            "Starting streaming request to OpenAI-compatible API"
        );

        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/json");

        if self.azure_deployment.is_some() {
            req = req.header("api-key", &self.api_key);
        } else {
            req = req.header("Authorization", format!("Bearer {}", self.api_key));
            if let Some(ref org) = self.organization_id {
                req = req.header("OpenAI-Organization", org);
            }
        }

        let response = req.json(&openai_request).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(LlmError::InvalidResponse(format!(
                "API error {}: {}",
                status, text
            )));
        }

        let byte_stream = response.bytes_stream();
        let index = 0u32;

        let stream = stream::unfold(
            (byte_stream, String::new(), index),
            move |(mut byte_stream, mut buffer, mut idx)| async move {
                use futures::TryStreamExt;

                loop {
                    // Try to find complete SSE events
                    if let Some(line_end) = buffer.find('\n') {
                        let line = buffer[..line_end].trim().to_string();
                        buffer = buffer[line_end + 1..].to_string();

                        if line.is_empty() {
                            continue;
                        }

                        if let Some(data) = line.strip_prefix("data: ") {
                            if data == "[DONE]" {
                                // Final chunk
                                return Some((
                                    Ok(StreamChunk {
                                        index: idx,
                                        delta: None,
                                        is_final: true,
                                        stop_reason: Some(StopReason::EndTurn),
                                        usage: None,
                                    }),
                                    (byte_stream, buffer, idx + 1),
                                ));
                            }

                            if let Ok(chunk) = serde_json::from_str::<OpenAIStreamChunk>(data)
                                && let Some(choice) = chunk.choices.into_iter().next()
                            {
                                let text = choice.delta.content.clone();
                                let is_final = choice.finish_reason.is_some();
                                let stop_reason =
                                    choice.finish_reason.as_deref().map(|r| match r {
                                        "stop" => StopReason::EndTurn,
                                        "length" => StopReason::MaxTokens,
                                        _ => StopReason::Other,
                                    });

                                let chunk_result = StreamChunk {
                                    index: idx,
                                    delta: text.map(|t| ContentBlock::Text { text: t }),
                                    is_final,
                                    stop_reason,
                                    usage: None,
                                };

                                idx += 1;
                                return Some((Ok(chunk_result), (byte_stream, buffer, idx)));
                            }
                        }
                    }

                    // Need more data
                    match byte_stream.try_next().await {
                        Ok(Some(bytes)) => {
                            buffer.push_str(&String::from_utf8_lossy(&bytes));
                        }
                        Ok(None) => return None,
                        Err(e) => {
                            return Some((
                                Err(LlmError::StreamError(e.to_string())),
                                (byte_stream, buffer, idx),
                            ));
                        }
                    }
                }
            },
        );

        Ok(Box::pin(stream))
    }
}

// === OpenAI API Types ===

#[derive(Debug, Serialize)]
struct OpenAIRequest {
    model: String,
    messages: Vec<OpenAIMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    frequency_penalty: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    presence_penalty: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenAIMessage {
    role: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAIResponse {
    id: String,
    model: String,
    created: u64,
    choices: Vec<OpenAIChoice>,
    usage: Option<OpenAIUsage>,
}

#[derive(Debug, Deserialize)]
struct OpenAIChoice {
    message: Option<OpenAIMessage>,
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAIUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
    total_tokens: u32,
}

#[derive(Debug, Deserialize)]
struct OpenAIStreamChunk {
    choices: Vec<OpenAIStreamChoice>,
}

#[derive(Debug, Deserialize)]
struct OpenAIStreamChoice {
    delta: OpenAIDelta,
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAIDelta {
    content: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_info_openai() {
        let provider = OpenAIProvider::new("test-key", "gpt-4");
        let info = provider.info();

        assert_eq!(info.id, "openai");
        assert!(info.capabilities.streaming);
    }

    #[test]
    fn test_provider_info_azure() {
        let provider = OpenAIProvider::azure(
            "https://my-resource.openai.azure.com",
            "test-key",
            "gpt-4-deployment",
            "2024-02-15-preview",
        );
        let info = provider.info();

        assert_eq!(info.id, "azure");
    }

    #[test]
    fn test_chat_url_openai() {
        let provider = OpenAIProvider::new("test-key", "gpt-4");
        assert_eq!(
            provider.chat_url(),
            "https://api.openai.com/v1/chat/completions"
        );
    }

    #[test]
    fn test_chat_url_azure() {
        let provider = OpenAIProvider::azure(
            "https://my-resource.openai.azure.com",
            "test-key",
            "gpt-4-deployment",
            "2024-02-15-preview",
        );
        assert!(
            provider
                .chat_url()
                .contains("openai/deployments/gpt-4-deployment")
        );
    }
}
