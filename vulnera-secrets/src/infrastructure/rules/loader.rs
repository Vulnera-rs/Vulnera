//! Rule loader for secret detection rules

use crate::domain::value_objects::SecretRule;
use crate::infrastructure::rules::default_rules::get_default_rules;
use std::path::Path;
use tracing::{error, info, warn};

/// Repository for secret detection rules
pub struct RuleRepository {
    rules: Vec<SecretRule>,
}

impl RuleRepository {
    /// Create a new rule repository with default rules
    pub fn new() -> Self {
        Self {
            rules: get_default_rules(),
        }
    }

    /// Create a rule repository with default rules and load additional rules from file
    pub fn with_file_and_defaults(rule_file_path: &Path) -> Self {
        let mut rules = get_default_rules();

        match Self::load_rules_from_file(rule_file_path) {
            Ok(mut file_rules) => {
                info!(
                    rule_count = file_rules.len(),
                    path = %rule_file_path.display(),
                    "Loaded rules from file"
                );
                rules.append(&mut file_rules);
            }
            Err(e) => {
                warn!(
                    error = %e,
                    path = %rule_file_path.display(),
                    "Failed to load rules from file, using defaults only"
                );
            }
        }

        Self { rules }
    }

    /// Load rules from a TOML or JSON file
    fn load_rules_from_file(rule_file_path: &Path) -> Result<Vec<SecretRule>, RuleLoadError> {
        let content = std::fs::read_to_string(rule_file_path)?;

        if rule_file_path.extension().and_then(|s| s.to_str()) == Some("toml") {
            Self::load_rules_from_toml(&content)
        } else if rule_file_path.extension().and_then(|s| s.to_str()) == Some("json") {
            Self::load_rules_from_json(&content)
        } else {
            Err(RuleLoadError::UnsupportedFormat(
                "Only TOML and JSON formats are supported".to_string(),
            ))
        }
    }

    /// Load rules from TOML content
    fn load_rules_from_toml(_content: &str) -> Result<Vec<SecretRule>, RuleLoadError> {
        // TODO: Implement TOML parsing
        // For now, return empty vector
        warn!("TOML rule loading not yet implemented");
        Ok(vec![])
    }

    /// Load rules from JSON content
    fn load_rules_from_json(content: &str) -> Result<Vec<SecretRule>, RuleLoadError> {
        serde_json::from_str(content).map_err(|e| RuleLoadError::ParseError(e.to_string()))
    }

    /// Get all rules
    pub fn get_all_rules(&self) -> &[SecretRule] {
        &self.rules
    }

    /// Get rules by secret type
    pub fn get_rules_by_type(&self, secret_type: &crate::domain::entities::SecretType) -> Vec<&SecretRule> {
        self.rules
            .iter()
            .filter(|rule| {
                // Compare secret types
                std::mem::discriminant(&rule.secret_type) == std::mem::discriminant(secret_type)
            })
            .collect()
    }
}

impl Default for RuleRepository {
    fn default() -> Self {
        Self::new()
    }
}

/// Error loading rules
#[derive(Debug, thiserror::Error)]
pub enum RuleLoadError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),
}

