//! Use case for generating code fixes for vulnerabilities

use crate::domain::{CodeFix, CompletionRequest, LlmError, LlmProvider};
use crate::infrastructure::prompts::CODE_FIX_SYSTEM_PROMPT;
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
    ) -> Result<CodeFix, LlmError> {
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
        let request = CompletionRequest::new()
            .with_system(CODE_FIX_SYSTEM_PROMPT)
            .with_user(user_prompt)
            .with_model(model)
            .with_max_tokens(self.config.max_tokens)
            .with_temperature(0.3); // Lower temp for code

        let response = self.provider.complete(request).await?;
        let content = response.text();

        // Parse JSON from content (handling potential markdown code blocks)
        let json_str = if let Some(start) = content.find("```json") {
            if let Some(_end) = content[start..].find("```") {
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

        let output: LlmOutput = serde_json::from_str(json_str).map_err(|e| {
            LlmError::InvalidResponse(format!("Failed to parse code fix response: {}", e))
        })?;

        Ok(CodeFix {
            finding_id: finding_id.to_string(),
            original_code: code_context.to_string(),
            suggested_code: output.fixed_code,
            explanation: output.explanation,
            diff: output.diff,
        })
    }
}
