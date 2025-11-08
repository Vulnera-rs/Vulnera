//! Regex-based secret detector

use crate::domain::value_objects::SecretRule;
use regex::Regex;
use std::collections::HashMap;
use tracing::debug;

/// Regex detector for known secret patterns
#[derive(Clone)]
pub struct RegexDetector {
    compiled_rules: HashMap<String, CompiledRule>,
}

/// Compiled regex rule with metadata
#[derive(Clone)]
struct CompiledRule {
    regex: Regex,
    rule: SecretRule,
}

impl RegexDetector {
    pub fn new(rules: Vec<SecretRule>) -> Self {
        let mut compiled_rules = HashMap::new();

        for rule in rules {
            if let crate::domain::value_objects::RulePattern::Regex(ref pattern) = rule.pattern {
                if let Ok(regex) = Regex::new(pattern) {
                    compiled_rules.insert(
                        rule.id.clone(),
                        CompiledRule {
                            regex,
                            rule: rule.clone(),
                        },
                    );
                } else {
                    tracing::warn!(rule_id = %rule.id, "Failed to compile regex pattern");
                }
            }
        }

        Self { compiled_rules }
    }

    /// Detect secrets using regex patterns
    pub fn detect(&self, content: &str, line_number: u32) -> Vec<RegexMatch> {
        let mut matches = Vec::new();

        for (rule_id, compiled_rule) in &self.compiled_rules {
            // Check keywords first (if any) for performance
            if !compiled_rule.rule.keywords.is_empty() {
                let has_keyword = compiled_rule
                    .rule
                    .keywords
                    .iter()
                    .any(|keyword| content.to_lowercase().contains(&keyword.to_lowercase()));
                if !has_keyword {
                    continue;
                }
            }

            // Apply regex
            for cap in compiled_rule.regex.captures_iter(content) {
                if let Some(matched) = cap.get(0) {
                    let matched_text = matched.as_str().to_string();
                    let start_pos = matched.start();
                    let end_pos = matched.end();

                    debug!(
                        rule_id = %rule_id,
                        line = line_number,
                        "Found regex match"
                    );

                    matches.push(RegexMatch {
                        rule_id: rule_id.clone(),
                        rule: compiled_rule.rule.clone(),
                        matched_text,
                        start_pos,
                        end_pos,
                        captures: cap
                            .iter()
                            .skip(1)
                            .filter_map(|m| m.map(|m| m.as_str().to_string()))
                            .collect(),
                    });
                }
            }
        }

        matches
    }

    /// Detect secrets in a line
    pub fn detect_line(&self, line: &str, line_number: u32) -> Vec<RegexMatch> {
        self.detect(line, line_number)
    }
}

/// Result of regex detection
#[derive(Debug, Clone)]
pub struct RegexMatch {
    pub rule_id: String,
    pub rule: SecretRule,
    pub matched_text: String,
    pub start_pos: usize,
    pub end_pos: usize,
    pub captures: Vec<String>,
}
