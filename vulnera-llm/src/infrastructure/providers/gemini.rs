use async_trait::async_trait;
use futures::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error};

use super::LlmProvider;
use crate::domain::{Choice, LlmRequest, LlmResponse, Message, Usage};
use vulnera_core::config::LlmConfig;

// ============================================================================
// Gemini API Internal Structs
// ============================================================================

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GeminiRequest {
    contents: Vec<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation_config: Option<GeminiGenerationConfig>,
}

#[derive(Serialize)]
struct GeminiContent {
    parts: Vec<GeminiPart>,
    role: String,
}

#[derive(Serialize)]
struct GeminiPart {
    text: String,
}

#[derive(Serialize)]
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiResponse {
    candidates: Option<Vec<GeminiCandidate>>,
    usage_metadata: Option<GeminiUsage>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiCandidate {
    content: Option<GeminiContentResponse>,
    finish_reason: Option<String>,
    index: Option<u32>,
}

#[derive(Deserialize)]
struct GeminiContentResponse {
    parts: Vec<GeminiPartResponse>,
    #[serde(default)]
    #[allow(dead_code)]
    role: String,
}

#[derive(Deserialize)]
struct GeminiPartResponse {
    text: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiUsage {
    prompt_token_count: Option<u32>,
    candidates_token_count: Option<u32>,
    total_token_count: Option<u32>,
}

// ============================================================================
// Implementation
// ============================================================================

/// Google Gemini LLM Provider
pub struct GeminiLlmProvider {
    client: Client,
    config: LlmConfig,
}

impl GeminiLlmProvider {
    pub fn new(config: LlmConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .expect("Failed to build HTTP client");

        Self { client, config }
    }

    fn get_api_key(&self) -> Result<&str, anyhow::Error> {
        self.config
            .gemini_api_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Gemini API key not configured"))
    }

    /// Convert generic LlmRequest to GeminiRequest
    fn build_request(&self, request: &LlmRequest) -> GeminiRequest {
        let contents: Vec<GeminiContent> = request
            .messages
            .iter()
            .map(|msg| {
                // Map roles: "user" | "system" -> "user", "assistant" -> "model"
                // Gemini technically expects "user" or "model". "system" prompts are often passed as "user" here
                // or via separate systemInstruction field (v1beta). For simplicity, mapping system to user.
                let role = match msg.role.as_deref().unwrap_or("user") {
                    "assistant" => "model".to_string(),
                    "model" => "model".to_string(),
                    _ => "user".to_string(),
                };

                let text = msg.content_str().to_string();

                GeminiContent {
                    parts: vec![GeminiPart { text }],
                    role,
                }
            })
            .collect();

        let generation_config = GeminiGenerationConfig {
            temperature: request.temperature,
            top_p: request.top_p,
            top_k: request.top_k,
            max_output_tokens: request.max_tokens,
            stop_sequences: None,
        };

        GeminiRequest {
            contents,
            generation_config: Some(generation_config),
        }
    }

    /// Convert GeminiResponse to standard LlmResponse
    fn convert_response(&self, gemini_resp: GeminiResponse, model_name: &str) -> LlmResponse {
        let created = chrono::Utc::now().timestamp() as u64;
        let id = format!("gemini-{}", uuid::Uuid::new_v4());

        let choices = gemini_resp
            .candidates
            .unwrap_or_default()
            .into_iter()
            .map(|c| {
                let text = c
                    .content
                    .map(|content| {
                        content
                            .parts
                            .into_iter()
                            .filter_map(|p| p.text)
                            .collect::<Vec<_>>()
                            .join("")
                    })
                    .unwrap_or_default();

                Choice {
                    index: c.index.unwrap_or(0),
                    message: Some(Message::new("assistant", text)),
                    delta: None,
                    finish_reason: c.finish_reason,
                }
            })
            .collect();

        let usage = gemini_resp.usage_metadata.map(|u| Usage {
            prompt_tokens: u.prompt_token_count.unwrap_or(0),
            completion_tokens: u.candidates_token_count.unwrap_or(0),
            total_tokens: u.total_token_count.unwrap_or(0),
        });

        LlmResponse {
            id,
            object: "chat.completion".to_string(),
            created,
            model: model_name.to_string(),
            choices,
            usage,
        }
    }
}

#[async_trait]
impl LlmProvider for GeminiLlmProvider {
    async fn generate(&self, request: LlmRequest) -> Result<LlmResponse, anyhow::Error> {
        let api_key = self.get_api_key()?;
        let url = &self.config.gemini_api_url;
        let model_name = request.model.clone();

        let gemini_request = self.build_request(&request);

        debug!("Sending Gemini request to {}", url);

        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("x-goog-api-key", api_key)
            .json(&gemini_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            error!("LLM API error: {} - {}", status, text);
            return Err(anyhow::anyhow!("LLM API error: {} - {}", status, text));
        }

        let gemini_response: GeminiResponse = response.json().await?;
        Ok(self.convert_response(gemini_response, &model_name))
    }

    // Only non-streaming implemented fully for now as streaming requires SSE parsing of Gemini format
    async fn generate_stream(
        &self,
        request: LlmRequest,
    ) -> Result<mpsc::Receiver<Result<LlmResponse, anyhow::Error>>, anyhow::Error> {
        let api_key = self.get_api_key()?;
        // Streaming endpoint might be different: usually :streamGenerateContent
        // Assuming user configured base URL like ".../models/gemini-pro:generateContent"
        // we might need to replace ":generateContent" with ":streamGenerateContent?alt=sse"

        let url = self
            .config
            .gemini_api_url
            .replace(":generateContent", ":streamGenerateContent?alt=sse");
        let model_name = request.model.clone();

        let gemini_request = self.build_request(&request);

        debug!("Sending streaming Gemini request to {}", url);

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("x-goog-api-key", api_key)
            .json(&gemini_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            error!("LLM API error: {} - {}", status, text);
            return Err(anyhow::anyhow!("LLM API error: {} - {}", status, text));
        }

        let (tx, rx) = mpsc::channel(100);

        tokio::spawn(async move {
            let mut stream = response.bytes_stream();
            let mut buffer = String::new();

            while let Some(item) = stream.next().await {
                match item {
                    Ok(bytes) => {
                        let chunk = String::from_utf8_lossy(&bytes);
                        buffer.push_str(&chunk);

                        while let Some(pos) = buffer.find('\n') {
                            let line = buffer[..pos].trim().to_string();
                            buffer = buffer[pos + 1..].to_string();

                            if line.is_empty() {
                                continue;
                            }

                            // Gemini SSE format usually starts with "data: " containing JSON
                            if let Some(data) = line.strip_prefix("data: ") {
                                if data == "[DONE]" {
                                    break;
                                } // Not standard Gemini but keeping for safety

                                match serde_json::from_str::<GeminiResponse>(data) {
                                    Ok(gemini_resp) => {
                                        // Convert partial Gemini response to LlmResponse delta
                                        // Just wrapping logic similar to convert_response but for streaming
                                        // For now, simpler conversion:

                                        let text = gemini_resp
                                            .candidates
                                            .as_ref()
                                            .and_then(|c| c.first())
                                            .and_then(|c| c.content.as_ref())
                                            .map(|cnt| {
                                                cnt.parts
                                                    .iter()
                                                    .filter_map(|p| p.text.clone())
                                                    .collect::<String>()
                                            })
                                            .unwrap_or_default();

                                        let choice = Choice {
                                            index: 0,
                                            message: None,
                                            delta: Some(Message::new("assistant", text)),
                                            finish_reason: gemini_resp
                                                .candidates
                                                .as_ref()
                                                .and_then(|c| c.first())
                                                .and_then(|c| c.finish_reason.clone()),
                                        };

                                        let llm_resp = LlmResponse {
                                            id: "stream-id".to_string(),
                                            object: "chat.completion.chunk".to_string(),
                                            created: chrono::Utc::now().timestamp() as u64,
                                            model: model_name.clone(),
                                            choices: vec![choice],
                                            usage: None,
                                        };

                                        if tx.send(Ok(llm_resp)).await.is_err() {
                                            return;
                                        }
                                    }
                                    Err(_e) => {
                                        // Sometimes it might not be JSON (e.g. keep-alive), so just warn
                                        // warn!("Failed to parse SSE data: {} - Error: {}", data, e);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(anyhow::anyhow!("Stream error: {}", e))).await;
                        return;
                    }
                }
            }
        });

        Ok(rx)
    }
}
