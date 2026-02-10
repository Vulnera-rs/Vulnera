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
    /// Metavariable constraints for filtering matches
    ///
    /// After the base pattern matches, each constraint is evaluated against
    /// the captured metavariable's AST subtree. A match is retained only if
    /// all constraints pass.
    ///
    #[serde(default)]
    pub metavariable_constraints: Vec<MetavariableConstraint>,
}

// =============================================================================
// Metavariable Constraints
// =============================================================================

/// A constraint on a captured metavariable.
///
/// After the base pattern matches and binds `$VAR` to a subtree, the
/// constraint is evaluated against that subtree to accept or reject
/// the match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetavariableConstraint {
    /// The metavariable name this constraint applies to (e.g. `"$ARG"`).
    pub metavariable: String,
    /// The condition to evaluate on the captured content.
    pub condition: MetavariableCondition,
}

/// The kind of condition to evaluate on a captured metavariable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum MetavariableCondition {
    /// The captured content must match (or not match) a nested pattern.
    ///
    /// Evaluated by re-running the pattern matcher on the captured AST
    /// subtree (see `Metavariable_pattern.ml`).
    #[serde(rename = "pattern")]
    Pattern {
        /// Patterns the captured content must satisfy.
        #[serde(default)]
        patterns: Vec<Pattern>,
        /// Patterns the captured content must NOT satisfy.
        #[serde(default)]
        patterns_not: Vec<Pattern>,
    },
    /// The captured content's text must match a regex.
    ///
    /// Evaluated by `Metavariable_regex.ml`.
    #[serde(rename = "regex")]
    Regex {
        /// Regex pattern applied to the metavariable's text representation.
        regex: String,
    },
}

/// Pattern types for matching code
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum Pattern {
    /// Native tree-sitter S-expression query
    /// Example: `(call function: (identifier) @fn (#eq? @fn "eval"))`
    TreeSitterQuery(String),

    /// Metavariable pattern
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
