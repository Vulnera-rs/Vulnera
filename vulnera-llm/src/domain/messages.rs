//! Unified message types for LLM providers
//!
//! This module defines provider-agnostic message types that can be translated
//! to any LLM API format (OpenAI, Gemini, Anthropic, Azure, etc.)

use serde::{Deserialize, Serialize};

/// Role in a conversation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// System prompt that sets the behavior
    System,
    /// User message (the human)
    User,
    /// Assistant response (the model)
    Assistant,
    /// Tool/function call result
    Tool,
}

impl Role {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Tool => "tool",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Content block types for multimodal messages
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    /// Plain text content
    Text { text: String },

    /// Image content (URL or base64)
    Image {
        /// Image URL or base64 data URI
        url: String,
        /// Detail level for vision models (low, high, auto)
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },

    /// Tool/function use request
    ToolUse {
        /// Unique ID for this tool use
        id: String,
        /// Tool name
        name: String,
        /// Tool input as JSON
        input: serde_json::Value,
    },

    /// Tool/function result
    ToolResult {
        /// ID of the tool use this is responding to
        tool_use_id: String,
        /// Result content
        content: String,
        /// Whether the tool execution failed
        #[serde(skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
    },
}

impl ContentBlock {
    /// Create a text content block
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text { text: text.into() }
    }

    /// Create an image content block from URL
    pub fn image(url: impl Into<String>) -> Self {
        Self::Image {
            url: url.into(),
            detail: None,
        }
    }

    /// Extract text content if this is a text block
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text { text } => Some(text),
            _ => None,
        }
    }
}

/// A message in the conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// The role of the message author
    pub role: Role,

    /// Content blocks (usually just one text block)
    pub content: Vec<ContentBlock>,

    /// Optional name for the participant
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Message {
    /// Create a new message with text content
    pub fn new(role: Role, text: impl Into<String>) -> Self {
        Self {
            role,
            content: vec![ContentBlock::text(text)],
            name: None,
        }
    }

    /// Create a system message
    pub fn system(text: impl Into<String>) -> Self {
        Self::new(Role::System, text)
    }

    /// Create a user message
    pub fn user(text: impl Into<String>) -> Self {
        Self::new(Role::User, text)
    }

    /// Create an assistant message
    pub fn assistant(text: impl Into<String>) -> Self {
        Self::new(Role::Assistant, text)
    }

    /// Get the text content (concatenated if multiple blocks)
    pub fn text(&self) -> String {
        self.content
            .iter()
            .filter_map(|block| block.as_text())
            .collect::<Vec<_>>()
            .join("")
    }

    /// Add a content block
    pub fn with_content(mut self, block: ContentBlock) -> Self {
        self.content.push(block);
        self
    }

    /// Set the participant name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// Completion request to send to an LLM provider
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CompletionRequest {
    /// The conversation messages
    pub messages: Vec<Message>,

    /// Model to use (provider-specific)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    /// Maximum tokens to generate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,

    /// Temperature (0.0 to 2.0, lower = more deterministic)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,

    /// Top-p nucleus sampling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,

    /// Top-k sampling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,

    /// Frequency penalty (-2.0 to 2.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<f64>,

    /// Presence penalty (-2.0 to 2.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_penalty: Option<f64>,

    /// Stop sequences
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stop: Vec<String>,

    /// Whether to stream the response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
}

impl CompletionRequest {
    /// Create a new completion request
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a message
    pub fn with_message(mut self, message: Message) -> Self {
        self.messages.push(message);
        self
    }

    /// Add a system message
    pub fn with_system(self, text: impl Into<String>) -> Self {
        self.with_message(Message::system(text))
    }

    /// Add a user message
    pub fn with_user(self, text: impl Into<String>) -> Self {
        self.with_message(Message::user(text))
    }

    /// Set the model
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// Set max tokens
    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    /// Set temperature
    pub fn with_temperature(mut self, temperature: f64) -> Self {
        self.temperature = Some(temperature);
        self
    }

    /// Enable streaming
    pub fn with_stream(mut self, stream: bool) -> Self {
        self.stream = Some(stream);
        self
    }
}

/// Reason why generation stopped
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// Natural end of response
    EndTurn,
    /// Hit a stop sequence
    StopSequence,
    /// Hit max tokens limit
    MaxTokens,
    /// Tool use requested
    ToolUse,
    /// Content was filtered
    ContentFilter,
    /// Unknown/other reason
    Other,
}

/// Token usage statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Usage {
    /// Tokens in the prompt
    pub prompt_tokens: u32,
    /// Tokens in the completion
    pub completion_tokens: u32,
    /// Total tokens used
    pub total_tokens: u32,
    /// Cached tokens (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_tokens: Option<u32>,
}

/// Completion response from an LLM provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionResponse {
    /// Unique response ID
    pub id: String,

    /// Model that generated the response
    pub model: String,

    /// Generated content blocks
    pub content: Vec<ContentBlock>,

    /// Why generation stopped
    pub stop_reason: StopReason,

    /// Token usage statistics
    #[serde(default)]
    pub usage: Usage,

    /// Response timestamp (Unix epoch seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<u64>,
}

impl CompletionResponse {
    /// Get the text content of the response
    pub fn text(&self) -> String {
        self.content
            .iter()
            .filter_map(|block| block.as_text())
            .collect::<Vec<_>>()
            .join("")
    }

    /// Check if the response was truncated due to max tokens
    pub fn is_truncated(&self) -> bool {
        self.stop_reason == StopReason::MaxTokens
    }

    /// Check if a tool use was requested
    pub fn has_tool_use(&self) -> bool {
        self.content
            .iter()
            .any(|block| matches!(block, ContentBlock::ToolUse { .. }))
    }
}

/// Streaming chunk for incremental responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChunk {
    /// Chunk index
    pub index: u32,

    /// Delta content (new tokens)
    pub delta: Option<ContentBlock>,

    /// Whether this is the final chunk
    pub is_final: bool,

    /// Stop reason (only on final chunk)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<StopReason>,

    /// Usage (only on final chunk)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_creation() {
        let msg = Message::user("Hello, world!");
        assert_eq!(msg.role, Role::User);
        assert_eq!(msg.text(), "Hello, world!");
    }

    #[test]
    fn test_request_builder() {
        let request = CompletionRequest::new()
            .with_system("You are a helpful assistant.")
            .with_user("What is 2+2?")
            .with_model("gpt-4")
            .with_temperature(0.7)
            .with_max_tokens(100);

        assert_eq!(request.messages.len(), 2);
        assert_eq!(request.model.as_deref(), Some("gpt-4"));
        assert_eq!(request.temperature, Some(0.7));
        assert_eq!(request.max_tokens, Some(100));
    }

    #[test]
    fn test_response_text_extraction() {
        let response = CompletionResponse {
            id: "resp_123".to_string(),
            model: "test-model".to_string(),
            content: vec![ContentBlock::text("Hello"), ContentBlock::text(" world")],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
            created: None,
        };

        assert_eq!(response.text(), "Hello world");
        assert!(!response.is_truncated());
    }

    #[test]
    fn test_role_display() {
        assert_eq!(Role::System.to_string(), "system");
        assert_eq!(Role::User.to_string(), "user");
        assert_eq!(Role::Assistant.to_string(), "assistant");
    }
}
