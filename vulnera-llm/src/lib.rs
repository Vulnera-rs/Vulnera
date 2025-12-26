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
//! - `infrastructure/` — Provider implementations (Gemini, etc.)
//!
//! # Usage
//!
//! ```rust,ignore
//! use vulnera_llm::{EnrichFindingsUseCase, LlmProvider, GeminiLlmProvider};
//!
//! // Create provider
//! let provider = GeminiLlmProvider::new(config);
//!
//! // Create use case
//! let use_case = EnrichFindingsUseCase::new(provider);
//!
//! // Enrich findings
//! let enriched = use_case.execute(findings).await?;
//! ```
//!
//! # Providers
//!
//! Currently supported LLM providers:
//!
//! - **Google Gemini** — Via `GeminiLlmProvider`
//!
//! Additional providers can be added by implementing the [`LlmProvider`] trait.

pub mod application;
pub mod domain;
pub mod infrastructure;

pub use application::use_cases::{
    EnrichFindingsRequest, EnrichFindingsResponse, EnrichFindingsUseCase,
    ExplainVulnerabilityUseCase, GenerateCodeFixUseCase, NaturalLanguageQueryUseCase,
};
pub use domain::*;
pub use infrastructure::prompts;
pub use infrastructure::providers::{GeminiLlmProvider, LlmProvider};
