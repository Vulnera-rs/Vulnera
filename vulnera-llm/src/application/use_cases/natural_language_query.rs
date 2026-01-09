//! Use case for natural language queries about findings

use crate::domain::{CompletionRequest, LlmError, LlmProvider};
use crate::infrastructure::prompts::PromptBuilder;
use std::sync::Arc;
use vulnera_core::config::LlmConfig;

pub struct NaturalLanguageQueryUseCase {
    provider: Arc<dyn LlmProvider>,
    config: LlmConfig,
}

impl NaturalLanguageQueryUseCase {
    pub fn new(provider: Arc<dyn LlmProvider>, config: LlmConfig) -> Self {
        Self { provider, config }
    }

    pub async fn execute(&self, query: &str, findings_json: &str) -> Result<String, LlmError> {
        let user_prompt = PromptBuilder::build_nl_query_prompt(query, findings_json);

        let request = CompletionRequest::new()
            .with_model(&self.config.default_model)
            .with_user(user_prompt)
            .with_max_tokens(self.config.max_tokens)
            .with_temperature(self.config.temperature);

        let response = self.provider.complete(request).await?;
        Ok(response.text())
    }
}
