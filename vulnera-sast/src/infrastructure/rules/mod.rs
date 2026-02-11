//! Security detection rules

mod default_rules;
mod loader;

pub use default_rules::get_default_rules;
pub use loader::{
    BuiltinRuleLoader, CompositeRuleLoader, FileRuleLoader, RuleLoadError, RuleLoader,
    RulePackLoader,
};

use crate::domain::pattern_types::PatternRule;
use crate::domain::value_objects::Language;
use tracing::debug;

/// Rule repository
pub struct RuleRepository {
    rules: Vec<PatternRule>,
}

impl RuleRepository {
    /// Create a new rule repository with default built-in rules.
    pub fn new() -> Self {
        let loader = BuiltinRuleLoader::new();
        let rules = loader.load_rules().unwrap_or_default();
        Self::with_rules(rules)
    }

    /// Create a rule repository from an arbitrary [`RuleLoader`].
    pub fn from_loader(loader: &dyn RuleLoader) -> Self {
        match loader.load_rules() {
            Ok(rules) => Self::with_rules(rules),
            Err(e) => {
                tracing::warn!(error = %e, "Loader failed, falling back to defaults");
                Self::new()
            }
        }
    }

    /// Create a rule repository with custom rules
    pub fn with_rules(rules: Vec<PatternRule>) -> Self {
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

    /// Create a rule repository with both file rules and default rules.
    pub fn with_file_and_defaults<P: AsRef<std::path::Path>>(file_path: P) -> Self {
        let builtin = BuiltinRuleLoader::new();
        let mut rules = builtin.load_rules().unwrap_or_default();

        let file_loader = FileRuleLoader::new(file_path);
        match file_loader.load_rules() {
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

    pub fn get_rules_for_language(&self, language: &Language) -> Vec<&PatternRule> {
        self.rules
            .iter()
            .filter(|rule| rule.languages.contains(language))
            .collect()
    }

    pub fn get_all_rules(&self) -> &[PatternRule] {
        &self.rules
    }
}

impl Default for RuleRepository {
    fn default() -> Self {
        Self::new()
    }
}
