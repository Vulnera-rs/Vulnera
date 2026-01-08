//! Semantic validation logic for reducing false positives in secret detection

use crate::domain::entities::SecretFinding;
use crate::domain::value_objects::{Confidence, SemanticContext, ValidationResult};
use async_trait::async_trait;

/// Trait for pluggable semantic validation logic
#[async_trait]
pub trait SemanticValidator: Send + Sync {
    /// Validates a finding against its semantic context.
    /// May modify the finding (e.g., updating confidence) and returns a ValidationResult.
    async fn validate(
        &self,
        finding: &mut SecretFinding,
        context: &SemanticContext,
    ) -> ValidationResult;
}

/// Heuristic-based validator that uses structural information and naming conventions
#[derive(Clone)]
pub struct HeuristicValidator;

#[async_trait]
impl SemanticValidator for HeuristicValidator {
    async fn validate(
        &self,
        finding: &mut SecretFinding,
        context: &SemanticContext,
    ) -> ValidationResult {
        // 1. Structural False Positives: Discard matches in comments
        // Common tree-sitter node types for comments across languages
        let is_comment = context.node_type == "comment"
            || context.node_type == "line_comment"
            || context.node_type == "block_comment";

        if is_comment {
            return ValidationResult::FalsePositive;
        }

        // 2. Structural Heuristics: Check if the value (RHS) is just a repeat of the variable name (LHS)
        if let (Some(lhs), Some(rhs)) = (&context.lhs_variable, &context.rhs_value) {
            let lhs_lower = lhs.to_lowercase();
            let rhs_clean = rhs.trim_matches(|c| c == '"' || c == '\'' || c == '`');
            let rhs_lower = rhs_clean.to_lowercase();

            // Identity and Field Name check: if var_name relates closely to "var_name",
            // it's likely a field mapping or constant name rather than a secret value.
            let is_identity = lhs_lower == rhs_lower
                || lhs_lower.replace('_', "") == rhs_lower.replace('_', "")
                || lhs_lower.replace('-', "") == rhs_lower.replace('-', "");

            // Check for common field name suffixes (e.g., PASSWORD_FIELD = "password")
            let is_field_constant = lhs_lower.ends_with("_field")
                || lhs_lower.ends_with("_name")
                || lhs_lower.ends_with("_key")
                || lhs_lower.ends_with("_header")
                || lhs_lower.ends_with("_column");

            if (is_identity || is_field_constant) && rhs_lower.len() < 24 {
                // If it's a short string matching the variable's intent, it's a false positive
                if lhs_lower.contains(&rhs_lower) || rhs_lower.contains(&lhs_lower) {
                    return ValidationResult::FalsePositive;
                }
            }
        }

        // 3. Safe/Non-Secret RHS Value Detection - discard known non-secret values
        if let Some(ref rhs) = context.rhs_value {
            let rhs_clean = rhs.trim_matches(|c| c == '"' || c == '\'' || c == '`');
            let rhs_lower = rhs_clean.to_lowercase();

            // Non-secret literals (JavaScript/Python/Rust keywords)
            let safe_literals = ["undefined", "null", "none", "nil", "true", "false", ""];
            if safe_literals.contains(&rhs_lower.as_str()) {
                return ValidationResult::FalsePositive;
            }

            // Very short values are likely field names, not secrets
            if rhs_clean.len() <= 12 && !rhs_clean.chars().any(|c| c.is_ascii_digit()) {
                // Check if value looks like a simple word (field name)
                if rhs_clean
                    .chars()
                    .all(|c| c.is_ascii_alphabetic() || c == '_' || c == '-')
                {
                    return ValidationResult::FalsePositive;
                }
            }
        }

        // 4. Placeholder and Environment Detection: Check the value (RHS)
        if let Some(ref rhs) = context.rhs_value {
            let rhs_lower = rhs.to_lowercase();

            // Known placeholders
            let placeholders = [
                "your_api_key",
                "your-api-key",
                "placeholder",
                "********",
                "example_value",
                "insert_here",
                "<your_",
                "${token}",
                "example-token",
                "fake-password",
            ];
            if placeholders.iter().any(|&p| rhs_lower.contains(p)) {
                return ValidationResult::FalsePositive;
            }

            // Environmental or Config access patterns (not hardcoded secrets)
            let access_patterns = [
                "process.env",
                "os.environ",
                "os.getenv",
                "config.",
                "config[",
                "settings.",
                "settings[",
                "app.config",
                "require(",
            ];
            if access_patterns.iter().any(|&p| rhs_lower.contains(p)) {
                return ValidationResult::FalsePositive;
            }
        }

        // 4. Assignment Analysis: Check the variable name (LHS) for intent
        let mut assignment_result = ValidationResult::Potential;
        if let Some(ref var_name) = context.lhs_variable {
            let var_name_lower = var_name.to_lowercase();

            // Check for high-intent trigger words first
            let trigger_words = [
                "key",
                "token",
                "secret",
                "auth",
                "pwd",
                "password",
                "access",
                "credential",
                "api",
                "private",
            ];
            if trigger_words.iter().any(|&t| var_name_lower.contains(t)) {
                finding.confidence = Confidence::High;
                assignment_result = ValidationResult::Confirmed;
            }

            // Exclusion markers override trigger words (e.g. "dummy_password")
            let exclusion_markers = [
                "example",
                "dummy",
                "placeholder",
                "mock",
                "template",
                "sample",
                "test",
                "fake",
            ];
            if exclusion_markers
                .iter()
                .any(|&m| var_name_lower.contains(m))
            {
                finding.confidence = Confidence::Low;
                return ValidationResult::Potential;
            }

            if assignment_result == ValidationResult::Confirmed {
                return ValidationResult::Confirmed;
            }
        }

        // 5. File Context: Downgrade findings in known test/mock environments
        if context.is_test_context {
            finding.confidence = Confidence::Low;
            return ValidationResult::Potential;
        }

        assignment_result
    }
}
