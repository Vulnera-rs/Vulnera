//! Pattern-based rule types for SAST analysis
//!
//! Types for defining pattern-based security detection rules.

use serde::{Deserialize, Serialize};

use super::value_objects::{Confidence, Language};

/// A pattern-based security detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternRule {
    /// Unique rule identifier (e.g., "python-sql-injection")
    pub id: String,
    /// Human-readable rule name
    pub name: String,
    /// Detailed description of what the rule detects
    pub description: String,
    /// Severity level
    pub severity: super::finding::Severity,
    /// Languages this rule applies to
    pub languages: Vec<Language>,
    /// The pattern to match
    pub pattern: Pattern,
    /// Rule-specific options
    #[serde(default)]
    pub options: RuleOptions,
    /// CWE identifiers (e.g., ["CWE-89", "CWE-78"])
    #[serde(default)]
    pub cwe_ids: Vec<String>,
    /// OWASP categories (e.g., ["A03:2021 - Injection"])
    #[serde(default)]
    pub owasp_categories: Vec<String>,
    /// Custom tags for categorization
    #[serde(default)]
    pub tags: Vec<String>,
    /// Message template with metavariable substitution
    #[serde(default)]
    pub message: Option<String>,
    /// Suggested fix (can include metavariables)
    #[serde(default)]
    pub fix: Option<String>,
}

/// Pattern types for matching code
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum Pattern {
    /// Native tree-sitter S-expression query
    /// Example: `(call function: (identifier) @fn (#eq? @fn "eval"))`
    TreeSitterQuery(String),

    /// Metavariable pattern (Semgrep-like syntax)
    /// Example: `$DB.execute($QUERY)`
    Metavariable(String),

    /// Multiple patterns (match any)
    AnyOf(Vec<Pattern>),

    /// Multiple patterns (match all in sequence)
    AllOf(Vec<Pattern>),

    /// Negated pattern (match if NOT present)
    Not(Box<Pattern>),
}

impl Pattern {
    /// Create a tree-sitter query pattern
    pub fn ts_query(query: impl Into<String>) -> Self {
        Pattern::TreeSitterQuery(query.into())
    }

    /// Create a metavariable pattern
    pub fn metavar(pattern: impl Into<String>) -> Self {
        Pattern::Metavariable(pattern.into())
    }
}

/// Rule-specific options for fine-tuning detection behavior
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleOptions {
    /// Suppress this rule in test code
    #[serde(default = "default_true")]
    pub suppress_in_tests: bool,
    /// Suppress this rule in example code
    #[serde(default)]
    pub suppress_in_examples: bool,
    /// Suppress this rule in benchmark code
    #[serde(default)]
    pub suppress_in_benches: bool,
    /// Related rule IDs
    #[serde(default)]
    pub related_rules: Vec<String>,
    /// Minimum confidence to report
    #[serde(default)]
    pub min_confidence: Option<Confidence>,
}

fn default_true() -> bool {
    true
}

/// Simple pattern for the pattern engine (not the rule's Pattern)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimplePattern {
    /// The pattern string
    pub pattern: String,
    /// Pattern kind
    pub kind: SimplePatternKind,
    /// Languages this pattern applies to
    pub languages: Option<Vec<String>>,
    /// Description
    pub description: Option<String>,
}

/// Simple pattern kinds for the pattern engine
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SimplePatternKind {
    /// Tree-sitter S-expression query
    TreeSitter,
    /// Regular expression
    Regex,
    /// Exact string match
    Exact,
}
