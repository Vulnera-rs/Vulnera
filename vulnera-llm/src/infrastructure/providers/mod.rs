use crate::domain::{LlmRequest, LlmResponse};
use async_trait::async_trait;
use tokio::sync::mpsc;

pub mod gemini;

pub use gemini::GeminiLlmProvider;

#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn generate(&self, request: LlmRequest) -> Result<LlmResponse, anyhow::Error>;
    async fn generate_stream(
        &self,
        request: LlmRequest,
    ) -> Result<mpsc::Receiver<Result<LlmResponse, anyhow::Error>>, anyhow::Error>;
}
