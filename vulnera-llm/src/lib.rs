//! Vulnera LLM - AI-Powered Vulnerability Intelligence
//!
//! This crate provides Large Language Model integration for enhanced vulnerability analysis,
//! including explanation generation, code fix suggestions, and natural language queries.
//!
//! # Features
//!
//! - **Vulnerability Explanation** — Generate human-readable explanations of security issues
//! - **Code Fix Suggestions** — AI-powered remediation code generation
//! - **Findings Enrichment** — Enhance vulnerability findings with contextual information
//! - **Natural Language Queries** — Ask questions about vulnerabilities in plain English
//!
//! # Architecture
//!
//! The crate follows Domain-Driven Design with:
//!
//! - `domain/` — Core entities and traits for LLM operations
//! - `application/` — Use cases orchestrating LLM workflows
//! - `infrastructure/` — Provider implementations and registry
//!
//! # Providers
//!
//! Supported LLM providers:
//!
//! - **Google AI Studio** — Via [`GoogleAIProvider`]
//! - **OpenAI** — Via [`OpenAIProvider`]
//! - **Azure OpenAI** — Via [`OpenAIProvider::azure`]
//!
//! All providers can be wrapped with [`ResilientProvider`] for circuit breaker and retry logic.
//!
//! # Usage
//!
//! ```rust,ignore
//! use vulnera_llm::{GoogleAIProvider, ResilientProvider, CompletionRequest, LlmProvider};
//!
//! // Create provider with resilience
//! let inner = GoogleAIProvider::new("api-key", "gemini-2.0-flash");
//! let provider = ResilientProvider::with_defaults(inner);
//!
//! // Make a completion request
//! let request = CompletionRequest::new()
//!     .with_system("You are a security expert.")
//!     .with_user("Explain SQL injection vulnerabilities.");
//!
//! let response = provider.complete(request).await?;
//! println!("{}", response.text());
//! ```
//!
//! # Provider Registry
//!
//! Use [`ProviderRegistry`] to manage multiple providers:
//!
//! ```rust,ignore
//! use vulnera_llm::{ProviderRegistry, ProviderConfig};
//!
//! let mut registry = ProviderRegistry::new();
//! registry.register_from_config("main", ProviderConfig::google_ai("key", "gemini-2.0-flash"))?;
//!
//! let provider = registry.default().unwrap();
//! ```

pub mod application;
pub mod domain;
pub mod infrastructure;

// Domain re-exports
pub use domain::{
    CodeFix, CompletionRequest, CompletionResponse, ContentBlock, Explanation, LlmError,
    LlmProvider, Message, ProviderCapabilities, ProviderInfo, Role, StopReason, StreamChunk, Usage,
};

// Application re-exports
pub use application::use_cases::{
    EnrichFindingsRequest, EnrichFindingsResponse, EnrichFindingsUseCase,
    ExplainVulnerabilityUseCase, GenerateCodeFixUseCase, NaturalLanguageQueryUseCase,
};

// Infrastructure re-exports
pub use infrastructure::prompts;
pub use infrastructure::providers::{
    GoogleAIProvider, OpenAIProvider, ResilienceConfig, ResilientProvider,
};
pub use infrastructure::registry::{ProviderConfig, ProviderRegistry, ProviderType};
