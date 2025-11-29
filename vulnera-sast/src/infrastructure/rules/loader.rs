//! Rule loader for loading rules from configuration files

use crate::domain::entities::{Rule, RulePattern};
use std::path::Path;
use tracing::{debug, error, warn};

/// Trait for loading rules from various sources
pub trait RuleLoader: Send + Sync {
    fn load_rules(&self) -> Result<Vec<Rule>, RuleLoadError>;
}

/// Error type for rule loading
#[derive(Debug, thiserror::Error)]
pub enum RuleLoadError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),
    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),
    #[error("Invalid rule: {0}")]
    InvalidRule(String),
}

/// File-based rule loader supporting TOML and JSON formats
pub struct FileRuleLoader {
    file_path: std::path::PathBuf,
}

impl FileRuleLoader {
    pub fn new<P: AsRef<Path>>(file_path: P) -> Self {
        Self {
            file_path: file_path.as_ref().to_path_buf(),
        }
    }
}

impl RuleLoader for FileRuleLoader {
    fn load_rules(&self) -> Result<Vec<Rule>, RuleLoadError> {
        let content = std::fs::read_to_string(&self.file_path)?;

        let rules = if self
            .file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("json"))
            .unwrap_or(false)
        {
            debug!(file = %self.file_path.display(), "Loading rules from JSON file");
            let rules_file: RulesFile = serde_json::from_str(&content)?;
            rules_file.rules
        } else {
            debug!(file = %self.file_path.display(), "Loading rules from TOML file");
            let rules_file: RulesFile = toml::from_str(&content)?;
            rules_file.rules
        };

        // Validate rules
        let mut validated_rules = Vec::new();
        for rule in rules {
            match validate_rule(&rule) {
                Ok(_) => validated_rules.push(rule),
                Err(e) => {
                    warn!(rule_id = %rule.id, error = %e, "Skipping invalid rule");
                }
            }
        }

        debug!(rule_count = validated_rules.len(), "Loaded rules from file");
        Ok(validated_rules)
    }
}

/// Rules file structure for TOML/JSON deserialization
#[derive(Debug, serde::Deserialize)]
struct RulesFile {
    rules: Vec<Rule>,
}

/// Validate a rule for correctness
fn validate_rule(rule: &Rule) -> Result<(), String> {
    if rule.id.is_empty() {
        return Err("Rule ID cannot be empty".to_string());
    }
    if rule.name.is_empty() {
        return Err("Rule name cannot be empty".to_string());
    }
    if rule.languages.is_empty() {
        return Err("Rule must specify at least one language".to_string());
    }

    // Validate pattern based on type
    match &rule.pattern {
        RulePattern::Regex(pattern) => {
            regex::Regex::new(pattern).map_err(|e| format!("Invalid regex pattern: {}", e))?;
        }
        RulePattern::FunctionCall(name) => {
            if name.is_empty() {
                return Err("Function call pattern cannot be empty".to_string());
            }
        }
        RulePattern::AstNodeType(node_type) => {
            if node_type.is_empty() {
                return Err("AST node type pattern cannot be empty".to_string());
            }
        }
        RulePattern::Custom(_) => {
            // Custom patterns are not validated
        }
        RulePattern::MethodCall(method_pattern) => {
            if method_pattern.name.is_empty() {
                return Err("MethodCall pattern name cannot be empty".to_string());
            }
        }
    }

    Ok(())
}
