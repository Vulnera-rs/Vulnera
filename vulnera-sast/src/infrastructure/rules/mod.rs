//! Security detection rules

mod default_rules;
mod loader;

pub use default_rules::get_default_rules;
pub use loader::{FileRuleLoader, RuleLoadError, RuleLoader};

use crate::domain::entities::{Rule, RulePattern};
use crate::domain::value_objects::Language;
use crate::infrastructure::parsers::AstNode;
use tracing::debug;

/// Rule engine for matching security patterns
pub trait RuleEngine: Send + Sync {
    fn match_rule(&self, rule: &Rule, node: &AstNode) -> bool;
}

/// Simple rule engine implementation
pub struct SimpleRuleEngine;

impl RuleEngine for SimpleRuleEngine {
    fn match_rule(&self, rule: &Rule, node: &AstNode) -> bool {
        match &rule.pattern {
            RulePattern::AstNodeType(pattern) => node.node_type == *pattern,
            RulePattern::FunctionCall(func_name) => {
                // Check if node is a function call with matching name
                node.node_type == "call" && node.source.contains(func_name)
            }
            RulePattern::Regex(pattern) => {
                if let Ok(re) = regex::Regex::new(pattern) {
                    re.is_match(&node.source)
                } else {
                    false
                }
            }
            RulePattern::Custom(_) => false, // Custom patterns not implemented yet
        }
    }
}

/// Rule repository
pub struct RuleRepository {
    rules: Vec<Rule>,
}

impl RuleRepository {
    /// Create a new rule repository with default rules
    pub fn new() -> Self {
        Self::with_rules(get_default_rules())
    }

    /// Create a rule repository with custom rules
    pub fn with_rules(rules: Vec<Rule>) -> Self {
        debug!(rule_count = rules.len(), "Creating rule repository");
        Self { rules }
    }

    /// Create a rule repository by loading rules from a file (with default rules as fallback)
    pub fn from_file<P: AsRef<std::path::Path>>(file_path: P) -> Self {
        let loader = FileRuleLoader::new(file_path);
        match loader.load_rules() {
            Ok(rules) => {
                debug!(rule_count = rules.len(), "Loaded rules from file");
                Self::with_rules(rules)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to load rules from file, using defaults");
                Self::new()
            }
        }
    }

    /// Create a rule repository with both file rules and default rules
    pub fn with_file_and_defaults<P: AsRef<std::path::Path>>(file_path: P) -> Self {
        let mut rules = get_default_rules();

        let loader = FileRuleLoader::new(file_path);
        match loader.load_rules() {
            Ok(file_rules) => {
                debug!(
                    file_rule_count = file_rules.len(),
                    "Loaded additional rules from file"
                );
                rules.extend(file_rules);
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to load rules from file, using defaults only");
            }
        }

        Self::with_rules(rules)
    }

    pub fn get_rules_for_language(&self, language: &Language) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|rule| rule.languages.contains(language))
            .collect()
    }

    pub fn get_all_rules(&self) -> &[Rule] {
        &self.rules
    }
}

impl Default for RuleRepository {
    fn default() -> Self {
        Self::new()
    }
}
