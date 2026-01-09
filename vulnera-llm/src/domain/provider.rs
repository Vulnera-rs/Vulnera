//! LLM Provider trait and related types
//!
//! Defines the core abstraction for LLM providers, enabling support for
//! multiple backends (Google AI, Azure, OpenAI, etc.)

use async_trait::async_trait;
use futures::stream::BoxStream;

use crate::domain::error::LlmError;
use crate::domain::messages::{CompletionRequest, CompletionResponse, StreamChunk};

/// Provider capability flags
#[derive(Debug, Clone, Default)]
pub struct ProviderCapabilities {
    /// Supports streaming responses
    pub streaming: bool,
    /// Supports function/tool calling
    pub function_calling: bool,
    /// Supports vision/image input
    pub vision: bool,
    /// Supports JSON mode output
    pub json_mode: bool,
    /// Maximum context window size (tokens)
    pub max_context_tokens: u32,
    /// Maximum output tokens
    pub max_output_tokens: u32,
}

impl ProviderCapabilities {
    /// Create capabilities for a basic text model
    pub fn text_only(max_context: u32, max_output: u32) -> Self {
        Self {
            streaming: true,
            function_calling: false,
            vision: false,
            json_mode: false,
            max_context_tokens: max_context,
            max_output_tokens: max_output,
        }
    }

    /// Create capabilities for a full-featured model
    pub fn full_featured(max_context: u32, max_output: u32) -> Self {
        Self {
            streaming: true,
            function_calling: true,
            vision: true,
            json_mode: true,
            max_context_tokens: max_context,
            max_output_tokens: max_output,
        }
    }
}

/// Metadata about a provider
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    /// Provider identifier (e.g., "google_ai", "azure", "openai")
    pub id: &'static str,
    /// Human-readable name
    pub name: &'static str,
    /// Provider version
    pub version: &'static str,
    /// Provider capabilities
    pub capabilities: ProviderCapabilities,
}

/// Core trait for LLM providers
///
/// All LLM backends must implement this trait. The trait is object-safe
/// and can be used with dynamic dispatch via `Arc<dyn LlmProvider>`.
///
/// # Example
///
/// ```rust,ignore
/// use vulnera_llm::{LlmProvider, CompletionRequest, Message};
///
/// async fn ask_llm(provider: &dyn LlmProvider) -> Result<String, LlmError> {
///     let request = CompletionRequest::new()
///         .with_user("What is the capital of France?");
///     
///     let response = provider.complete(request).await?;
///     Ok(response.text())
/// }
/// ```
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Get provider metadata
    fn info(&self) -> ProviderInfo;

    /// Generate a completion (non-streaming)
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError>;

    /// Generate a streaming completion
    ///
    /// Returns a stream of chunks that can be processed incrementally.
    async fn complete_stream(
        &self,
        request: CompletionRequest,
    ) -> Result<BoxStream<'static, Result<StreamChunk, LlmError>>, LlmError>;

    /// Check if the provider is healthy and can accept requests
    async fn health_check(&self) -> Result<(), LlmError> {
        // Default implementation: try a minimal completion
        let request = CompletionRequest::new()
            .with_user("ping")
            .with_max_tokens(1);

        self.complete(request).await.map(|_| ())
    }

    /// Get the default model for this provider
    fn default_model(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities_text_only() {
        let caps = ProviderCapabilities::text_only(8192, 4096);
        assert!(caps.streaming);
        assert!(!caps.function_calling);
        assert!(!caps.vision);
        assert_eq!(caps.max_context_tokens, 8192);
    }

    #[test]
    fn test_capabilities_full_featured() {
        let caps = ProviderCapabilities::full_featured(128000, 8192);
        assert!(caps.streaming);
        assert!(caps.function_calling);
        assert!(caps.vision);
        assert!(caps.json_mode);
    }
}
