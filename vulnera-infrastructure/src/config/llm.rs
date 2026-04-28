use serde::Deserialize;

/// LLM integration configuration
#[derive(Debug, Clone, Deserialize)]
pub struct LlmConfig {
    /// Provider: "google_ai" or "openai"
    pub provider: String,
    /// Google AI API key (Gemini)
    pub google_ai_api_key: Option<String>,
    /// OpenAI API key
    pub openai_api_key: Option<String>,
    /// Model override for code fix generation
    pub code_fix_model: Option<String>,
    /// Model override for vulnerability explanation
    pub explain_model: Option<String>,
    /// Model override for natural language queries
    pub query_model: Option<String>,
    /// Model override for findings enrichment
    pub enrich_model: Option<String>,
    /// Enable circuit breaker for resilience
    pub circuit_breaker_enabled: bool,
    /// Circuit breaker failure threshold
    pub circuit_breaker_threshold: u32,
    /// Circuit breaker recovery timeout in seconds
    pub circuit_breaker_timeout_seconds: u64,
    /// Max retries for failed requests
    pub max_retries: u32,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            provider: "google_ai".into(),
            google_ai_api_key: None,
            openai_api_key: None,
            code_fix_model: None,
            explain_model: None,
            query_model: None,
            enrich_model: None,
            circuit_breaker_enabled: true,
            circuit_breaker_threshold: 5,
            circuit_breaker_timeout_seconds: 30,
            max_retries: 3,
        }
    }
}
