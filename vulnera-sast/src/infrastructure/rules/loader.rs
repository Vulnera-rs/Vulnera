//! Rule loader for loading rules from configuration files
//!
//! Supports:
//! - TOML/JSON native rule format
//! - YAML native rule format

use crate::domain::pattern_types::{Pattern, PatternRule};
use crate::infrastructure::rules::default_rules::get_default_rules;
use git2::Repository;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use tracing::{debug, warn};
use vulnera_core::config::RulePackConfig;

/// Trait for loading rules from various sources
pub trait RuleLoader: Send + Sync {
    fn load_rules(&self) -> Result<Vec<PatternRule>, RuleLoadError>;
}

/// Composite loader that merges rules from multiple loaders
pub struct CompositeRuleLoader {
    loaders: Vec<Box<dyn RuleLoader>>,
}

impl CompositeRuleLoader {
    pub fn new(loaders: Vec<Box<dyn RuleLoader>>) -> Self {
        Self { loaders }
    }
}

impl RuleLoader for CompositeRuleLoader {
    fn load_rules(&self) -> Result<Vec<PatternRule>, RuleLoadError> {
        let mut rules = Vec::new();
        for loader in &self.loaders {
            match loader.load_rules() {
                Ok(mut loaded) => rules.append(&mut loaded),
                Err(e) => warn!(error = %e, "Rule loader failed; skipping source"),
            }
        }
        Ok(rules)
    }
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
                load_yaml_rules(&content)?.rules
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

/// Git-based rule pack loader
pub struct RulePackLoader {
    packs: Vec<RulePackConfig>,
    allowlist: Vec<String>,
}

impl RulePackLoader {
    pub fn new(packs: Vec<RulePackConfig>, allowlist: Vec<String>) -> Self {
        Self { packs, allowlist }
    }

    fn is_allowed(&self, url: &str) -> bool {
        if self.allowlist.is_empty() {
            return true;
        }
        self.allowlist.iter().any(|prefix| url.starts_with(prefix))
    }
}

impl RuleLoader for RulePackLoader {
    fn load_rules(&self) -> Result<Vec<PatternRule>, RuleLoadError> {
        let mut rules = Vec::new();

        for pack in &self.packs {
            if !pack.enabled {
                continue;
            }

            if !self.is_allowed(&pack.git_url) {
                warn!(pack = %pack.name, url = %pack.git_url, "Rule pack URL not allowlisted");
                continue;
            }

            let temp_dir = tempfile::TempDir::new()?;
            let repo = Repository::clone(&pack.git_url, temp_dir.path())
                .map_err(|e| RuleLoadError::InvalidRule(e.to_string()))?;

            if let Some(reference) = pack.reference.as_deref() {
                let obj = repo
                    .revparse_single(reference)
                    .map_err(|e| RuleLoadError::InvalidRule(e.to_string()))?;
                repo.checkout_tree(&obj, None)
                    .map_err(|e| RuleLoadError::InvalidRule(e.to_string()))?;
                repo.set_head_detached(obj.id())
                    .map_err(|e| RuleLoadError::InvalidRule(e.to_string()))?;
            }

            let rules_path = temp_dir.path().join(&pack.rules_path);
            let content = std::fs::read_to_string(&rules_path)?;

            if let Some(expected) = pack.checksum_sha256.as_deref() {
                let mut hasher = Sha256::new();
                hasher.update(content.as_bytes());
                let actual = hex::encode(hasher.finalize());
                if actual.to_lowercase() != expected.to_lowercase() {
                    warn!(
                        pack = %pack.name,
                        expected = %expected,
                        actual = %actual,
                        "Rule pack checksum mismatch"
                    );
                    continue;
                }
            }

            let extension = rules_path
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            let rules_file: RulesFile = match extension.as_str() {
                "json" => serde_json::from_str(&content)?,
                "yaml" | "yml" => load_yaml_rules(&content)?,
                _ => toml::from_str(&content)?,
            };

            for rule in rules_file.rules {
                match validate_rule(&rule) {
                    Ok(_) => rules.push(rule),
                    Err(e) => warn!(rule_id = %rule.id, error = %e, "Skipping invalid pack rule"),
                }
            }
        }

        Ok(rules)
    }
}

/// Rules file structure for TOML/JSON/YAML deserialization (native format)
#[derive(Debug, Deserialize)]
struct RulesFile {
    rules: Vec<PatternRule>,
}

fn load_yaml_rules(content: &str) -> Result<RulesFile, RuleLoadError> {
    let rules_file: RulesFile = serde_yml::from_str(content)?;
    Ok(rules_file)
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

        let rules_file = load_yaml_rules(yaml).expect("Should parse native YAML");
        assert_eq!(rules_file.rules.len(), 1);

        let rule = &rules_file.rules[0];
        assert_eq!(rule.id, "test-native");
        assert_eq!(rule.severity, Severity::High);
        assert_eq!(rule.languages, vec![Language::Python]);

        match &rule.pattern {
            Pattern::TreeSitterQuery(q) => assert!(!q.is_empty()),
            other => panic!("Unexpected pattern: {:?}", other),
        }
    }
}
