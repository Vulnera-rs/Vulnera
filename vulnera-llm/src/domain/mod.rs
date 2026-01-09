//! Domain layer for LLM operations
//!
//! Contains core entities, traits, and types for LLM integration:
//!
//! - [`messages`] - Unified message types (CompletionRequest, CompletionResponse)
//! - [`provider`] - LlmProvider trait for backend implementations
//! - [`error`] - Typed LLM errors

pub mod error;
pub mod messages;
pub mod provider;

// Re-exports for convenience
pub use error::LlmError;
pub use messages::{
    CompletionRequest, CompletionResponse, ContentBlock, Message, Role, StopReason, StreamChunk,
    Usage,
};
pub use provider::{LlmProvider, ProviderCapabilities, ProviderInfo};

use serde::{Deserialize, Serialize};

/// Code fix suggestion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeFix {
    pub finding_id: String,
    pub original_code: String,
    pub suggested_code: String,
    pub explanation: String,
    pub diff: String,
}

/// Vulnerability explanation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Explanation {
    pub finding_id: String,
    pub text: String,
}
