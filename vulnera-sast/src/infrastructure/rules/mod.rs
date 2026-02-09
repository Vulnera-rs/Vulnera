//! Security detection rules

mod default_rules;
mod loader;

pub use default_rules::get_default_rules;
pub use loader::{FileRuleLoader, RuleLoadError, RuleLoader};

use crate::domain::entities::{Pattern, Rule};
use crate::domain::value_objects::Language;
use crate::infrastructure::query_engine::{
    QueryEngineError, QueryMatchResult, TreeSitterQueryEngine,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

/// Rule engine for matching security patterns using tree-sitter queries
///
/// All rules use tree-sitter S-expression queries for pattern matching.
/// This provides consistent, powerful, and performant analysis across all languages.
pub struct RuleEngine {
    /// Tree-sitter query engine for S-expression pattern matching
    query_engine: Arc<RwLock<TreeSitterQueryEngine>>,
}

impl RuleEngine {
    /// Create a new rule engine with tree-sitter query support
    pub fn new() -> Self {
        Self {
            query_engine: Arc::new(RwLock::new(TreeSitterQueryEngine::new())),
        }
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
    ) -> Result<Vec<QueryMatchResult>, TreeSitterQueryError> {
        let query_str = match &rule.pattern {
            Pattern::TreeSitterQuery(query) => query.as_str(),
            _ => return Ok(Vec::new()), // Only tree-sitter queries supported
        };

        let mut engine = self.query_engine.write().await;
        engine
            .query(source_code, language, query_str)
            .map_err(TreeSitterQueryError::QueryExecution)
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
        let mut results = Vec::with_capacity(rules.len());
        let mut engine = self.query_engine.write().await;

        // Collect queries for batch execution
        let queries: Vec<(String, &str)> = rules
            .iter()
            .filter_map(|rule| match &rule.pattern {
                Pattern::TreeSitterQuery(query) => Some((rule.id.clone(), query.as_str())),
                _ => None,
            })
            .collect();

        if queries.is_empty() {
            return results;
        }

        // Execute batch query
        match engine.batch_query(source_code, language, &queries) {
            Ok(batch_results) => {
                for (rule_id, matches) in batch_results {
                    if !matches.is_empty() {
                        results.push((rule_id, matches));
                    }
                }
            }
            Err(e) => {
                debug!(error = %e, "Batch tree-sitter query execution failed");
            }
        }

        results
    }

    /// Execute multiple tree-sitter rules against a pre-parsed tree
    ///
    /// Useful for reusing ASTs across multiple phases.
    pub async fn execute_tree_sitter_rules_with_tree(
        &self,
        rules: &[&Rule],
        language: &Language,
        source_code: &str,
        tree: &tree_sitter::Tree,
    ) -> Vec<(String, Vec<QueryMatchResult>)> {
        let mut results = Vec::with_capacity(rules.len());
        let mut engine = self.query_engine.write().await;

        // Collect queries for batch execution
        let queries: Vec<(String, &str)> = rules
            .iter()
            .filter_map(|rule| match &rule.pattern {
                Pattern::TreeSitterQuery(query) => Some((rule.id.clone(), query.as_str())),
                _ => None,
            })
            .collect();

        if queries.is_empty() {
            return results;
        }

        // Execute batch query against provided tree
        match engine.batch_query_with_tree(tree, source_code, language, &queries) {
            Ok(batch_results) => {
                for (rule_id, matches) in batch_results {
                    if !matches.is_empty() {
                        results.push((rule_id, matches));
                    }
                }
            }
            Err(e) => {
                debug!(error = %e, "Batch tree-sitter query execution failed");
            }
        }

        results
    }

    /// Get the query engine for direct access (advanced usage)
    pub fn query_engine(&self) -> Arc<RwLock<TreeSitterQueryEngine>> {
        Arc::clone(&self.query_engine)
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
    QueryExecution(#[from] QueryEngineError),
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
