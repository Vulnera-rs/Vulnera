//! Rule loader for secret detection rules

use crate::domain::value_objects::SecretRule;
use crate::infrastructure::rules::default_rules::get_default_rules;
use std::path::Path;
use tracing::{error, info, warn};

/// Repository for secret detection rules
#[derive(Clone)]
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
    fn load_rules_from_toml(content: &str) -> Result<Vec<SecretRule>, RuleLoadError> {
        // Parse TOML content
        let toml_value: toml::Value = toml::from_str(content)
            .map_err(|e| RuleLoadError::ParseError(format!("TOML parse error: {}", e)))?;

        let mut rules = Vec::new();

        // Extract rules array from TOML
        if let Some(rules_array) = toml_value.get("rules").and_then(|v| v.as_array()) {
            for rule_value in rules_array {
                if let Ok(rule) = Self::parse_rule_from_toml_value(rule_value) {
                    rules.push(rule);
                } else {
                    warn!("Failed to parse rule from TOML, skipping");
                }
            }
        } else if let Some(rule_value) = toml_value.get("rule") {
            // Single rule format
            if let Ok(rule) = Self::parse_rule_from_toml_value(rule_value) {
                rules.push(rule);
            }
        }

        Ok(rules)
    }

    /// Parse a single rule from TOML value
    fn parse_rule_from_toml_value(value: &toml::Value) -> Result<SecretRule, RuleLoadError> {
        let id = value
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RuleLoadError::ParseError("Missing 'id' field".to_string()))?
            .to_string();

        let name = value
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(&id)
            .to_string();

        let pattern = value
            .get("pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RuleLoadError::ParseError("Missing 'pattern' field".to_string()))?
            .to_string();

        let description = value
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Parse secret type (default to Other if not specified)
        let secret_type_str = value
            .get("secret_type")
            .and_then(|v| v.as_str())
            .unwrap_or("Other");
        let secret_type = Self::parse_secret_type(secret_type_str);

        // Parse optional fields
        let keywords = value
            .get("keywords")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let entropy_threshold = value
            .get("entropy_threshold")
            .and_then(|v| v.as_float())
            .or_else(|| value.get("entropy_threshold").and_then(|v| v.as_integer().map(|i| i as f64)));

        let path_patterns = value
            .get("path_patterns")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        Ok(SecretRule {
            id,
            name,
            pattern: crate::domain::value_objects::RulePattern::Regex(pattern),
            description,
            secret_type,
            keywords,
            entropy_threshold,
            path_patterns,
        })
    }

    /// Parse secret type from string
    fn parse_secret_type(s: &str) -> crate::domain::entities::SecretType {
        match s.to_lowercase().as_str() {
            "aws_access_key" => crate::domain::entities::SecretType::AwsAccessKey,
            "aws_secret_key" => crate::domain::entities::SecretType::AwsSecretKey,
            "aws_session_token" => crate::domain::entities::SecretType::AwsSessionToken,
            "api_key" => crate::domain::entities::SecretType::ApiKey,
            "github_token" => crate::domain::entities::SecretType::GitHubToken,
            "gitlab_token" => crate::domain::entities::SecretType::GitLabToken,
            "jwt_token" => crate::domain::entities::SecretType::JwtToken,
            "oauth_token" => crate::domain::entities::SecretType::OAuthToken,
            "bearer_token" => crate::domain::entities::SecretType::BearerToken,
            "ssh_private_key" => crate::domain::entities::SecretType::SshPrivateKey,
            "rsa_private_key" => crate::domain::entities::SecretType::RsaPrivateKey,
            "database_password" => crate::domain::entities::SecretType::DatabasePassword,
            "database_connection_string" => crate::domain::entities::SecretType::DatabaseConnectionString,
            _ => crate::domain::entities::SecretType::Other,
        }
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

