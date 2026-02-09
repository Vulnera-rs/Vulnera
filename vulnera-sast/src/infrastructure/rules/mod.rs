//! Security detection rules

mod default_rules;
mod loader;

pub use default_rules::get_default_rules;
pub use loader::{BuiltinRuleLoader, FileRuleLoader, RuleLoadError, RuleLoader};

use crate::domain::{Pattern, Rule};
use crate::domain::value_objects::Language;
use crate::infrastructure::query_engine::QueryMatchResult;
use crate::infrastructure::sast_engine::{SastEngine, SastEngineError, SastEngineHandle};
use std::sync::Arc;
use tracing::debug;

/// Rule engine for matching security patterns using SastEngine
///
/// Thin wrapper around SastEngine for backward compatibility.
/// All pattern matching is delegated to the unified SastEngine.
pub struct RuleEngine {
    /// Unified SAST engine for pattern matching
    sast_engine: SastEngineHandle,
}

impl RuleEngine {
    /// Create a new rule engine with SastEngine
    pub fn new() -> Self {
        Self {
            sast_engine: Arc::new(SastEngine::new()),
        }
    }

    /// Create with a pre-built SastEngine (dependency injection)
    pub fn with_sast_engine(sast_engine: SastEngineHandle) -> Self {
        Self { sast_engine }
    }

    /// Execute a tree-sitter query against source code
    ///
    /// Returns all matches found in the source code for the given query pattern.
    /// This is the primary pattern matching mechanism for all rules.
    pub async fn execute_tree_sitter_query(
        &self,
        rule: &Rule,
        language: &Language,
        source_code: &str,
    ) -> Result<Vec<QueryMatchResult>, SastEngineError> {
        let query_str = match &rule.pattern {
            Pattern::TreeSitterQuery(query) => query.as_str(),
            _ => return Ok(Vec::new()), // Only tree-sitter queries supported
        };

        self.sast_engine
            .query(source_code, *language, query_str)
            .await
    }

    /// Execute multiple tree-sitter rules against source code
    ///
    /// Efficiently batches rule execution for the same language/source combination.
    pub async fn execute_tree_sitter_rules(
        &self,
        rules: &[&Rule],
        language: &Language,
        source_code: &str,
    ) -> Vec<(String, Vec<QueryMatchResult>)> {
        self.sast_engine
            .query_batch(source_code, *language, rules)
            .await
    }

    /// Execute multiple tree-sitter rules against a pre-parsed tree
    ///
    /// Useful for reusing ASTs across multiple phases.
    pub async fn execute_tree_sitter_rules_with_tree(
        &self,
        rules: &[&Rule],
        language: &Language,
        source_code: &str,
        _tree: &tree_sitter::Tree,
    ) -> Vec<(String, Vec<QueryMatchResult>)> {
        // For now, delegate to query_batch (tree reuse optimization can be added later)
        self.sast_engine
            .query_batch(source_code, *language, rules)
            .await
    }

    /// Get the underlying SastEngine handle
    pub fn sast_engine(&self) -> SastEngineHandle {
        Arc::clone(&self.sast_engine)
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during tree-sitter query execution
#[derive(Debug, thiserror::Error)]
pub enum TreeSitterQueryError {
    #[error("Query execution failed: {0}")]
    QueryExecution(#[from] SastEngineError),
}

/// Rule repository
pub struct RuleRepository {
    rules: Vec<Rule>,
}

impl RuleRepository {
    /// Create a new rule repository with default built-in rules.
    pub fn new() -> Self {
        let loader = BuiltinRuleLoader::new();
        // BuiltinRuleLoader is infallible in practice; unwrap is safe here.
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
