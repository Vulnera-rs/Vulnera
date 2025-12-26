use async_trait::async_trait;
use futures::StreamExt;
use reqwest::Client;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use super::LlmProvider;
use crate::domain::{LlmRequest, LlmResponse};
use vulnera_core::config::LlmConfig;

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
}

#[async_trait]
impl LlmProvider for GeminiLlmProvider {
    async fn generate(&self, request: LlmRequest) -> Result<LlmResponse, anyhow::Error> {
        let api_key = self.get_api_key()?;
        let url = &self.config.gemini_api_url;

        // Ensure stream is false for non-streaming generation
        let mut request = request;
        request.stream = Some(false);

        debug!("Sending LLM request to {}", url);

        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("x-goog-api-key", api_key)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            error!("LLM API error: {} - {}", status, text);
            return Err(anyhow::anyhow!("LLM API error: {} - {}", status, text));
        }

        let llm_response: LlmResponse = response.json().await?;
        Ok(llm_response)
    }

    async fn generate_stream(
        &self,
        mut request: LlmRequest,
    ) -> Result<mpsc::Receiver<Result<LlmResponse, anyhow::Error>>, anyhow::Error> {
        let api_key = self.get_api_key()?;
        let url = &self.config.gemini_api_url;

        // Ensure stream is true for streaming generation
        request.stream = Some(true);

        debug!("Sending streaming LLM request to {}", url);

        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("x-goog-api-key", api_key)
            .json(&request)
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

                            if let Some(data) = line.strip_prefix("data: ") {
                                if data == "[DONE]" {
                                    break;
                                }

                                match serde_json::from_str::<LlmResponse>(data) {
                                    Ok(response) => {
                                        if tx.send(Ok(response)).await.is_err() {
                                            return; // Receiver dropped
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to parse SSE data: {} - Error: {}", data, e);
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
