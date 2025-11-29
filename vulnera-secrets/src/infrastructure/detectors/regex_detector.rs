//! Regex-based secret detector

use crate::domain::value_objects::SecretRule;
use once_cell::sync::OnceCell;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

/// Regex detector for known secret patterns
#[derive(Clone)]
pub struct RegexDetector {
    compiled_rules: HashMap<String, CompiledRule>,
}

/// Compiled regex rule with metadata
#[derive(Clone)]
struct CompiledRule {
    // original regex pattern string - kept for lazy compilation
    pattern: String,
    // lazy, thread-safe storage for compiled regex (Arc<Regex> stored in OnceCell)
    regex_cell: OnceCell<Arc<Regex>>,
    rule: SecretRule,
}

impl CompiledRule {
    // Initialize CompiledRule from a SecretRule (if it holds a regex pattern)
    pub fn new_from_rule(rule: &SecretRule) -> Option<Self> {
        if let crate::domain::value_objects::RulePattern::Regex(ref pattern) = rule.pattern {
            Some(Self {
                pattern: pattern.clone(),
                regex_cell: OnceCell::new(),
                rule: rule.clone(),
            })
        } else {
            None
        }
    }

    // Get compiled Arc<Regex> for this rule - compile once lazily
    pub fn get_regex(&self) -> Arc<Regex> {
        self.regex_cell
            .get_or_init(|| {
                Arc::new(Regex::new(&self.pattern).expect("Failed to compile regex pattern"))
            })
            .clone()
    }
}

impl RegexDetector {
    pub fn new(rules: Vec<SecretRule>) -> Self {
        let mut compiled_rules = HashMap::new();

        for rule in rules {
            if let crate::domain::value_objects::RulePattern::Regex(ref pattern) = rule.pattern {
                if let Ok(regex) = Regex::new(pattern) {
                    if let Some(compiled) = CompiledRule::new_from_rule(&rule) {
                        compiled.regex_cell.set(Arc::new(regex)).ok();
                        compiled_rules.insert(rule.id.clone(), compiled);
                    } else {
                        tracing::warn!(rule_id = %rule.id, "Rule pattern expected to be Regex but was not; skipping compiled rule setup");
                    }
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
        // Optimization: Lowercase content once if needed for keyword matching
        // We use a lazy initialization to avoid allocation if no rules have keywords (unlikely but good practice)
        let content_lower = once_cell::sync::Lazy::new(|| content.to_lowercase());

        for (rule_id, compiled_rule) in &self.compiled_rules {
            // Check keywords first (if any) for performance
            if !compiled_rule.rule.keywords.is_empty() {
                let has_keyword = compiled_rule
                    .rule
                    .keywords
                    .iter()
                    .any(|keyword| content_lower.contains(&keyword.to_lowercase()));
                if !has_keyword {
                    continue;
                }
            }

            // Apply regex
            for cap in compiled_rule.get_regex().captures_iter(content) {
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
