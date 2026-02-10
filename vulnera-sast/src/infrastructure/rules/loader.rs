//! Rule loader for loading rules from configuration files
//!
//! Supports:
//! - TOML/JSON native rule format
//! - YAML native rule format

use crate::domain::pattern_types::{Pattern, PatternRule};
use crate::infrastructure::rules::default_rules::get_default_rules;
use serde::Deserialize;
use std::path::Path;
use tracing::{debug, warn};

/// Trait for loading rules from various sources
pub trait RuleLoader: Send + Sync {
    fn load_rules(&self) -> Result<Vec<PatternRule>, RuleLoadError>;
}

/// Loader for compile-time embedded TOML rules.
///
/// Wraps the `get_default_rules()` function behind the [`RuleLoader`] trait,
/// enabling uniform polymorphic usage alongside [`FileRuleLoader`].
pub struct BuiltinRuleLoader;

impl BuiltinRuleLoader {
    pub fn new() -> Self {
        Self
    }
}

impl Default for BuiltinRuleLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleLoader for BuiltinRuleLoader {
    fn load_rules(&self) -> Result<Vec<PatternRule>, RuleLoadError> {
        let rules = get_default_rules();
        debug!(
            rule_count = rules.len(),
            "Loaded built-in rules from embedded TOML"
        );
        Ok(rules)
    }
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
    #[error("YAML parse error: {0}")]
    YamlParse(#[from] serde_yml::Error),
    #[error("Invalid rule: {0}")]
    InvalidRule(String),
}

/// File-based rule loader supporting TOML, JSON, and YAML formats
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
    fn load_rules(&self) -> Result<Vec<PatternRule>, RuleLoadError> {
        let content = std::fs::read_to_string(&self.file_path)?;
        let extension = self
            .file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let rules = match extension.as_str() {
            "json" => {
                debug!(file = %self.file_path.display(), "Loading rules from JSON file");
                let rules_file: RulesFile = serde_json::from_str(&content)?;
                rules_file.rules
            }
            "yaml" | "yml" => {
                debug!(file = %self.file_path.display(), "Loading rules from YAML file");
                load_yaml_rules(&content)?
            }
            _ => {
                debug!(file = %self.file_path.display(), "Loading rules from TOML file");
                let rules_file: RulesFile = toml::from_str(&content)?;
                rules_file.rules
            }
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

/// Rules file structure for TOML/JSON/YAML deserialization (native format)
#[derive(Debug, Deserialize)]
struct RulesFile {
    rules: Vec<PatternRule>,
}

fn load_yaml_rules(content: &str) -> Result<Vec<PatternRule>, RuleLoadError> {
    let rules_file: RulesFile = serde_yml::from_str(content)?;
    Ok(rules_file.rules)
}

/// Validate a rule for correctness
fn validate_rule(rule: &PatternRule) -> Result<(), String> {
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
        Pattern::TreeSitterQuery(query) => {
            if query.is_empty() {
                return Err("Tree-sitter query pattern cannot be empty".to_string());
            }
        }
        Pattern::Metavariable(pattern) => {
            if pattern.is_empty() {
                return Err("Metavariable pattern cannot be empty".to_string());
            }
        }
        Pattern::AnyOf(patterns) => {
            if patterns.is_empty() {
                return Err("AnyOf pattern must contain at least one sub-pattern".to_string());
            }
        }
        Pattern::AllOf(patterns) => {
            if patterns.is_empty() {
                return Err("AllOf pattern must contain at least one sub-pattern".to_string());
            }
        }
        Pattern::Not(_) => {
            // Not pattern is always valid if it has a sub-pattern
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::finding::Severity;
    use crate::domain::value_objects::Language;

    #[test]
    fn test_native_yaml_rules() {
        let yaml = r#"
rules:
  - id: test-native
    name: "Test Rule"
    description: "Detects something"
    severity: "High"
    languages: ["Python"]
    pattern:
      type: "TreeSitterQuery"
      value: "(call function: (identifier) @fn)"
"#;

        let rules = load_yaml_rules(yaml).expect("Should parse native YAML");
        assert_eq!(rules.len(), 1);

        let rule = &rules[0];
        assert_eq!(rule.id, "test-native");
        assert_eq!(rule.severity, Severity::High);
        assert_eq!(rule.languages, vec![Language::Python]);

        match &rule.pattern {
            Pattern::TreeSitterQuery(q) => assert!(!q.is_empty()),
            other => panic!("Unexpected pattern: {:?}", other),
        }
    }
}
