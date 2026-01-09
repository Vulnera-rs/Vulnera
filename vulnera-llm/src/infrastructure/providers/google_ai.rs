//! Google AI Studio (Gemini) provider implementation
//!
//! Supports the Gemini API with proper format translation.

use async_trait::async_trait;
use futures::stream::{self, BoxStream};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error};

use crate::domain::{
    CompletionRequest, CompletionResponse, ContentBlock, LlmError, LlmProvider,
    ProviderCapabilities, ProviderInfo, StopReason, StreamChunk, Usage,
};

/// Google AI Studio (Gemini) provider
pub struct GoogleAIProvider {
    client: Client,
    api_key: String,
    model: String,
    base_url: String,
}

impl GoogleAIProvider {
    /// Create a new Google AI provider
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            api_key: api_key.into(),
            model: model.into(),
            base_url: "https://generativelanguage.googleapis.com/v1beta".to_string(),
        }
    }

    /// Create with custom base URL (for testing or proxies)
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Build the API URL for a model endpoint
    fn build_url(&self, model: &str, endpoint: &str) -> String {
        format!(
            "{}/models/{}:{}?key={}",
            self.base_url, model, endpoint, self.api_key
        )
    }

    /// Convert our request format to Gemini's format
    fn to_gemini_request(&self, request: &CompletionRequest) -> GeminiRequest {
        let contents: Vec<GeminiContent> = request
            .messages
            .iter()
            .map(|msg| {
                let role = match msg.role {
                    crate::domain::Role::System => "user", // Gemini handles system differently
                    crate::domain::Role::User => "user",
                    crate::domain::Role::Assistant => "model",
                    crate::domain::Role::Tool => "user",
                };

                let parts: Vec<GeminiPart> = msg
                    .content
                    .iter()
                    .map(|block| match block {
                        ContentBlock::Text { text } => GeminiPart::Text { text: text.clone() },
                        ContentBlock::Image { url, .. } => GeminiPart::InlineData {
                            inline_data: GeminiInlineData {
                                mime_type: "image/jpeg".to_string(), // TODO: detect from URL
                                data: url.clone(),
                            },
                        },
                        _ => GeminiPart::Text {
                            text: "".to_string(),
                        },
                    })
                    .collect();

                GeminiContent {
                    role: role.to_string(),
                    parts,
                }
            })
            .collect();

        // Extract system instruction from messages
        let system_instruction = request
            .messages
            .iter()
            .find(|m| matches!(m.role, crate::domain::Role::System))
            .map(|m| GeminiContent {
                role: "user".to_string(),
                parts: vec![GeminiPart::Text { text: m.text() }],
            });

        GeminiRequest {
            contents,
            system_instruction,
            generation_config: Some(GeminiGenerationConfig {
                temperature: request.temperature,
                top_p: request.top_p,
                top_k: request.top_k,
                max_output_tokens: request.max_tokens,
                stop_sequences: if request.stop.is_empty() {
                    None
                } else {
                    Some(request.stop.clone())
                },
            }),
        }
    }

    /// Convert Gemini response to our format
    fn from_gemini_response(
        &self,
        response: GeminiResponse,
        model: &str,
    ) -> Result<CompletionResponse, LlmError> {
        let candidate =
            response.candidates.into_iter().next().ok_or_else(|| {
                LlmError::InvalidResponse("No candidates in response".to_string())
            })?;

        let content: Vec<ContentBlock> = candidate
            .content
            .parts
            .into_iter()
            .filter_map(|part| match part {
                GeminiPart::Text { text } => Some(ContentBlock::Text { text }),
                _ => None,
            })
            .collect();

        let stop_reason = match candidate.finish_reason.as_deref() {
            Some("STOP") => StopReason::EndTurn,
            Some("MAX_TOKENS") => StopReason::MaxTokens,
            Some("SAFETY") => StopReason::ContentFilter,
            _ => StopReason::Other,
        };

        let usage = response
            .usage_metadata
            .map(|u| Usage {
                prompt_tokens: u.prompt_token_count,
                completion_tokens: u.candidates_token_count,
                total_tokens: u.total_token_count,
                cached_tokens: u.cached_content_token_count,
            })
            .unwrap_or_default();

        Ok(CompletionResponse {
            id: format!("gemini-{}", uuid::Uuid::new_v4()),
            model: model.to_string(),
            content,
            stop_reason,
            usage,
            created: Some(chrono::Utc::now().timestamp() as u64),
        })
    }
}

#[async_trait]
impl LlmProvider for GoogleAIProvider {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: "google_ai",
            name: "Google AI Studio",
            version: "v1beta",
            capabilities: ProviderCapabilities {
                streaming: true,
                function_calling: true,
                vision: true,
                json_mode: true,
                max_context_tokens: 1_000_000, // Gemini 1.5 supports up to 1M
                max_output_tokens: 8192,
            },
        }
    }

    fn default_model(&self) -> &str {
        &self.model
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError> {
        let model = request.model.as_deref().unwrap_or(&self.model);
        let url = self.build_url(model, "generateContent");
        let gemini_request = self.to_gemini_request(&request);

        debug!(model = model, "Sending request to Google AI");

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&gemini_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();

            // Parse specific error types
            if status.as_u16() == 429 {
                return Err(LlmError::rate_limited(text));
            } else if status.as_u16() == 401 || status.as_u16() == 403 {
                return Err(LlmError::auth(text));
            } else if status.as_u16() >= 500 {
                return Err(LlmError::ServiceUnavailable(text));
            }

            error!(status = %status, "Google AI API error: {}", text);
            return Err(LlmError::InvalidResponse(format!(
                "API error {}: {}",
                status, text
            )));
        }

        let gemini_response: GeminiResponse = response.json().await?;
        self.from_gemini_response(gemini_response, model)
    }

    async fn complete_stream(
        &self,
        request: CompletionRequest,
    ) -> Result<BoxStream<'static, Result<StreamChunk, LlmError>>, LlmError> {
        let model = request.model.clone().unwrap_or_else(|| self.model.clone());
        let url = self.build_url(&model, "streamGenerateContent");
        let gemini_request = self.to_gemini_request(&request);

        debug!(model = %model, "Starting streaming request to Google AI");

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&gemini_request)
            .send()
            .await?;

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
        let buffer = String::new();

        let stream = stream::unfold(
            (byte_stream, buffer, index),
            move |(mut byte_stream, mut buffer, mut idx)| async move {
                use futures::TryStreamExt;

                loop {
                    // Try to parse complete JSON objects from buffer
                    if let Some(end) = buffer.find('\n') {
                        let line = buffer[..end].trim().to_string();
                        buffer = buffer[end + 1..].to_string();

                        if line.is_empty() {
                            continue;
                        }

                        // Parse the JSON chunk
                        if let Ok(chunk) = serde_json::from_str::<GeminiStreamChunk>(&line) {
                            if let Some(candidate) = chunk.candidates.into_iter().next() {
                                let text = candidate
                                    .content
                                    .parts
                                    .into_iter()
                                    .filter_map(|p| match p {
                                        GeminiPart::Text { text } => Some(text),
                                        _ => None,
                                    })
                                    .collect::<String>();

                                let is_final = candidate.finish_reason.is_some();
                                let stop_reason =
                                    candidate.finish_reason.as_deref().map(|r| match r {
                                        "STOP" => StopReason::EndTurn,
                                        "MAX_TOKENS" => StopReason::MaxTokens,
                                        _ => StopReason::Other,
                                    });

                                let chunk_result = StreamChunk {
                                    index: idx,
                                    delta: if text.is_empty() {
                                        None
                                    } else {
                                        Some(ContentBlock::Text { text })
                                    },
                                    is_final,
                                    stop_reason,
                                    usage: chunk.usage_metadata.map(|u| Usage {
                                        prompt_tokens: u.prompt_token_count,
                                        completion_tokens: u.candidates_token_count,
                                        total_tokens: u.total_token_count,
                                        cached_tokens: u.cached_content_token_count,
                                    }),
                                };

                                idx += 1;

                                if is_final {
                                    return Some((Ok(chunk_result), (byte_stream, buffer, idx)));
                                }

                                return Some((Ok(chunk_result), (byte_stream, buffer, idx)));
                            }
                        }
                    }

                    // Need more data
                    match byte_stream.try_next().await {
                        Ok(Some(bytes)) => {
                            buffer.push_str(&String::from_utf8_lossy(&bytes));
                        }
                        Ok(None) => return None, // Stream ended
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

// === Gemini API Types ===

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GeminiRequest {
    contents: Vec<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_instruction: Option<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation_config: Option<GeminiGenerationConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GeminiContent {
    role: String,
    parts: Vec<GeminiPart>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum GeminiPart {
    Text { text: String },
    InlineData { inline_data: GeminiInlineData },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiInlineData {
    mime_type: String,
    data: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GeminiGenerationConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_k: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_output_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop_sequences: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiResponse {
    candidates: Vec<GeminiCandidate>,
    usage_metadata: Option<GeminiUsageMetadata>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiCandidate {
    content: GeminiContent,
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiUsageMetadata {
    prompt_token_count: u32,
    candidates_token_count: u32,
    total_token_count: u32,
    #[serde(default)]
    cached_content_token_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiStreamChunk {
    candidates: Vec<GeminiCandidate>,
    usage_metadata: Option<GeminiUsageMetadata>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_info() {
        let provider = GoogleAIProvider::new("test-key", "gemini-2.0-flash");
        let info = provider.info();

        assert_eq!(info.id, "google_ai");
        assert!(info.capabilities.streaming);
        assert!(info.capabilities.vision);
    }

    #[test]
    fn test_build_url() {
        let provider = GoogleAIProvider::new("test-key", "gemini-2.0-flash");
        let url = provider.build_url("gemini-2.0-flash", "generateContent");

        assert!(url.contains("gemini-2.0-flash"));
        assert!(url.contains("generateContent"));
        assert!(url.contains("key=test-key"));
    }
}
