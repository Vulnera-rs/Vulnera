use crate::domain::{CodeFix, LlmRequest, Message};
use crate::infrastructure::prompts::CODE_FIX_SYSTEM_PROMPT;
use crate::infrastructure::providers::LlmProvider;
use std::sync::Arc;
use vulnera_core::config::LlmConfig;

pub struct GenerateCodeFixUseCase {
    provider: Arc<dyn LlmProvider>,
    config: LlmConfig,
}

impl GenerateCodeFixUseCase {
    pub fn new(provider: Arc<dyn LlmProvider>, config: LlmConfig) -> Self {
        Self { provider, config }
    }

    pub async fn execute(
        &self,
        finding_id: &str,
        code_context: &str,
        vulnerability_description: &str,
    ) -> Result<CodeFix, anyhow::Error> {
        let model = self
            .config
            .code_fix_model
            .as_deref()
            .unwrap_or(&self.config.default_model);

        let user_prompt = format!(
            "Finding ID: {}\nDescription: {}\n\nVulnerable Code:\n```\n{}\n```",
            finding_id, vulnerability_description, code_context
        );

        // Use lower temperature for code generation (more deterministic)
        let code_temperature = 0.3;

        let request = LlmRequest {
            model: model.to_string(),
            messages: vec![
                Message::new("system", CODE_FIX_SYSTEM_PROMPT),
                Message::new("user", user_prompt),
            ],
            max_tokens: Some(self.config.max_tokens),
            temperature: Some(code_temperature),
            top_p: Some(0.9),
            top_k: Some(40),
            frequency_penalty: Some(0.0),
            presence_penalty: Some(0.0),
            stream: Some(false), // Non-streaming for JSON parsing simplicity in MVP
        };

        let response = self.provider.generate(request).await?;

        let content = response
            .choices
            .first()
            .and_then(|c| c.message.as_ref())
            .map(|m| m.full_response())
            .ok_or_else(|| anyhow::anyhow!("No content in LLM response"))?;

        // Parse JSON from content (handling potential markdown code blocks)
        let json_str = if let Some(start) = content.find("```json") {
            if let Some(_end) = content[start..].find("```") {
                // This logic is flawed if there are multiple blocks, but simple for now
                // Actually, let's just try to find the first { and last }
                let start_brace = content.find('{').unwrap_or(0);
                let end_brace = content.rfind('}').unwrap_or(content.len());
                &content[start_brace..=end_brace]
            } else {
                &content
            }
        } else if let Some(start) = content.find('{') {
            let end = content.rfind('}').unwrap_or(content.len());
            &content[start..=end]
        } else {
            &content
        };

        #[derive(serde::Deserialize)]
        struct LlmOutput {
            explanation: String,
            fixed_code: String,
            diff: String,
        }

        let output: LlmOutput = serde_json::from_str(json_str)?;

        Ok(CodeFix {
            finding_id: finding_id.to_string(),
            original_code: code_context.to_string(),
            suggested_code: output.fixed_code,
            explanation: output.explanation,
            diff: output.diff,
        })
    }
}
