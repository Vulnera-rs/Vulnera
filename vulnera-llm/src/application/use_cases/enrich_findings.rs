//! Use case for enriching security findings with LLM-generated insights

use crate::domain::{LlmRequest, Message};
use crate::infrastructure::prompts::PromptBuilder;
use crate::infrastructure::providers::LlmProvider;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use vulnera_core::config::LlmConfig;
use vulnera_core::domain::module::{Finding, FindingEnrichment, FindingSeverity};

/// Request for enriching findings
#[derive(Debug, Clone)]
pub struct EnrichFindingsRequest {
    /// The findings to enrich
    pub findings: Vec<Finding>,
    /// Optional code context per finding (keyed by finding ID)
    pub code_contexts: std::collections::HashMap<String, String>,
}

/// Response from enrichment
#[derive(Debug, Clone)]
pub struct EnrichFindingsResponse {
    /// Enriched findings (same order as input, with enrichment populated)
    pub findings: Vec<Finding>,
    /// Number of findings successfully enriched
    pub enriched_count: usize,
    /// Number of findings that failed enrichment
    pub failed_count: usize,
}

/// Use case for enriching vulnerability findings with LLM-generated explanations and remediation
pub struct EnrichFindingsUseCase {
    provider: Arc<dyn LlmProvider>,
    config: LlmConfig,
}

impl EnrichFindingsUseCase {
    pub fn new(provider: Arc<dyn LlmProvider>, config: LlmConfig) -> Self {
        Self { provider, config }
    }

    /// Execute the enrichment use case
    ///
    /// Prioritizes findings by severity (Critical > High > Medium > Low > Info)
    /// and enriches up to `max_findings_to_enrich` from config.
    pub async fn execute(&self, request: EnrichFindingsRequest) -> Result<EnrichFindingsResponse> {
        let max_to_enrich = self.config.enrichment.max_findings_to_enrich;
        let max_concurrent = self.config.enrichment.max_concurrent_enrichments;

        info!(
            total_findings = request.findings.len(),
            max_to_enrich = max_to_enrich,
            "Starting finding enrichment"
        );

        // Sort and prioritize findings by severity
        let mut prioritized: Vec<(usize, &Finding)> = request.findings.iter().enumerate().collect();
        prioritized.sort_by(|a, b| {
            Self::severity_priority(&b.1.severity).cmp(&Self::severity_priority(&a.1.severity))
        });

        // Take top N findings to enrich
        let to_enrich: Vec<(usize, &Finding)> =
            prioritized.into_iter().take(max_to_enrich).collect();

        debug!(count = to_enrich.len(), "Selected findings for enrichment");

        // Prepare findings for enrichment
        let findings_to_process: Vec<(usize, Finding, Option<String>)> = to_enrich
            .into_iter()
            .map(|(idx, finding)| {
                let code_context = request.code_contexts.get(&finding.id).cloned();
                (idx, finding.clone(), code_context)
            })
            .collect();

        // Process findings with concurrency limit
        let enrichment_results: Vec<(usize, Result<FindingEnrichment>)> = stream::iter(
            findings_to_process
                .into_iter()
                .map(|(idx, finding, code_context)| {
                    let provider = self.provider.clone();
                    let config = self.config.clone();

                    async move {
                        let result =
                            Self::enrich_single_finding(&provider, &config, &finding, code_context)
                                .await;
                        (idx, result)
                    }
                }),
        )
        .buffer_unordered(max_concurrent)
        .collect()
        .await;

        // Apply enrichment results to findings
        let mut findings = request.findings;
        let mut enriched_count = 0;
        let mut failed_count = 0;

        for (idx, result) in enrichment_results {
            match result {
                Ok(enrichment) => {
                    if enrichment.enrichment_successful {
                        enriched_count += 1;
                    } else {
                        failed_count += 1;
                    }
                    findings[idx].enrichment = Some(enrichment);
                }
                Err(e) => {
                    warn!(
                        finding_id = %findings[idx].id,
                        error = %e,
                        "Failed to enrich finding"
                    );
                    failed_count += 1;
                    findings[idx].enrichment = Some(FindingEnrichment {
                        enrichment_successful: false,
                        error: Some(e.to_string()),
                        enriched_at: Some(chrono::Utc::now()),
                        ..Default::default()
                    });
                }
            }
        }

        info!(
            enriched_count = enriched_count,
            failed_count = failed_count,
            "Finding enrichment complete"
        );

        Ok(EnrichFindingsResponse {
            findings,
            enriched_count,
            failed_count,
        })
    }

    /// Enrich a single finding
    async fn enrich_single_finding(
        provider: &Arc<dyn LlmProvider>,
        config: &LlmConfig,
        finding: &Finding,
        code_context: Option<String>,
    ) -> Result<FindingEnrichment> {
        let model = config
            .enrichment_model
            .as_deref()
            .unwrap_or(&config.default_model);

        let prompt = PromptBuilder::build_enrichment_prompt(finding, code_context.as_deref());

        let request = LlmRequest {
            model: model.to_string(),
            messages: vec![Message::new("user", prompt)],
            max_tokens: Some(config.max_tokens),
            temperature: Some(config.temperature),
            top_p: Some(0.95),
            top_k: None,
            frequency_penalty: None,
            presence_penalty: None,
            stream: Some(false),
        };

        debug!(finding_id = %finding.id, "Requesting LLM enrichment");

        let response = provider.generate(request).await?;

        // Parse the response - use content_str() to handle Option<String>
        let content = response
            .choices
            .first()
            .and_then(|c| c.message.as_ref())
            .map(|m| m.content_str())
            .unwrap_or("");

        Self::parse_enrichment_response(content)
    }

    /// Parse LLM response into FindingEnrichment
    fn parse_enrichment_response(content: &str) -> Result<FindingEnrichment> {
        // Try to parse as JSON first
        if let Ok(parsed) = serde_json::from_str::<EnrichmentJsonResponse>(content) {
            return Ok(FindingEnrichment {
                explanation: Some(parsed.explanation),
                remediation_suggestion: Some(parsed.remediation),
                risk_summary: Some(parsed.risk_summary),
                enrichment_successful: true,
                error: None,
                enriched_at: Some(chrono::Utc::now()),
            });
        }

        // Try to extract JSON from markdown code block
        if let Some(json_content) = Self::extract_json_from_markdown(content) {
            if let Ok(parsed) = serde_json::from_str::<EnrichmentJsonResponse>(&json_content) {
                return Ok(FindingEnrichment {
                    explanation: Some(parsed.explanation),
                    remediation_suggestion: Some(parsed.remediation),
                    risk_summary: Some(parsed.risk_summary),
                    enrichment_successful: true,
                    error: None,
                    enriched_at: Some(chrono::Utc::now()),
                });
            }
        }

        // Fallback: treat entire response as explanation
        if !content.trim().is_empty() {
            Ok(FindingEnrichment {
                explanation: Some(content.to_string()),
                remediation_suggestion: None,
                risk_summary: None,
                enrichment_successful: true,
                error: None,
                enriched_at: Some(chrono::Utc::now()),
            })
        } else {
            error!("Empty response from LLM");
            Ok(FindingEnrichment {
                enrichment_successful: false,
                error: Some("Empty response from LLM".to_string()),
                enriched_at: Some(chrono::Utc::now()),
                ..Default::default()
            })
        }
    }

    /// Extract JSON from markdown code block
    fn extract_json_from_markdown(content: &str) -> Option<String> {
        let json_start = content.find("```json").or_else(|| content.find("```"))?;
        let content_after_start = &content[json_start..];
        let actual_start = content_after_start.find('\n')? + 1;
        let json_end = content_after_start[actual_start..].find("```")?;
        Some(content_after_start[actual_start..actual_start + json_end].to_string())
    }

    /// Get priority value for severity (higher = more critical)
    fn severity_priority(severity: &FindingSeverity) -> u8 {
        match severity {
            FindingSeverity::Critical => 5,
            FindingSeverity::High => 4,
            FindingSeverity::Medium => 3,
            FindingSeverity::Low => 2,
            FindingSeverity::Info => 1,
        }
    }
}

/// Expected JSON structure from LLM enrichment response
#[derive(Debug, serde::Deserialize)]
struct EnrichmentJsonResponse {
    explanation: String,
    remediation: String,
    risk_summary: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_priority() {
        assert!(
            EnrichFindingsUseCase::severity_priority(&FindingSeverity::Critical)
                > EnrichFindingsUseCase::severity_priority(&FindingSeverity::High)
        );
        assert!(
            EnrichFindingsUseCase::severity_priority(&FindingSeverity::High)
                > EnrichFindingsUseCase::severity_priority(&FindingSeverity::Medium)
        );
    }

    #[test]
    fn test_parse_enrichment_response_json() {
        let json = r#"{"explanation":"Test explanation","remediation":"Fix it","risk_summary":"High risk"}"#;
        let result = EnrichFindingsUseCase::parse_enrichment_response(json).unwrap();
        assert!(result.enrichment_successful);
        assert_eq!(result.explanation.unwrap(), "Test explanation");
        assert_eq!(result.remediation_suggestion.unwrap(), "Fix it");
    }

    #[test]
    fn test_parse_enrichment_response_markdown() {
        let content = r#"Here is the analysis:
```json
{"explanation":"Test","remediation":"Fix","risk_summary":"Medium"}
```
"#;
        let result = EnrichFindingsUseCase::parse_enrichment_response(content).unwrap();
        assert!(result.enrichment_successful);
        assert_eq!(result.explanation.unwrap(), "Test");
    }

    #[test]
    fn test_parse_enrichment_response_fallback() {
        let content = "This is just plain text explanation";
        let result = EnrichFindingsUseCase::parse_enrichment_response(content).unwrap();
        assert!(result.enrichment_successful);
        assert_eq!(result.explanation.unwrap(), content);
        assert!(result.remediation_suggestion.is_none());
    }
}
