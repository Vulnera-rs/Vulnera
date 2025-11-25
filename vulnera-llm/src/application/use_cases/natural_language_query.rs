use crate::domain::{LlmRequest, Message};
use crate::infrastructure::prompts::PromptBuilder;
use crate::infrastructure::providers::LlmProvider;
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

    pub async fn execute(&self, query: &str, findings_json: &str) -> Result<String, anyhow::Error> {
        let model = &self.config.default_model;
        let user_prompt = PromptBuilder::build_nl_query_prompt(query, findings_json);

        let request = LlmRequest {
            model: model.to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: user_prompt,
            }],
            max_tokens: Some(self.config.max_tokens),
            temperature: Some(self.config.temperature),
            stream: Some(false),
        };

        let response = self.provider.generate(request).await?;

        response
            .choices
            .first()
            .and_then(|c| c.message.as_ref())
            .map(|m| m.content.clone())
            .ok_or_else(|| anyhow::anyhow!("No content in LLM response"))
    }
}
