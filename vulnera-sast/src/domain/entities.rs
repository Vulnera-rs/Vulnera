//! SAST domain entities

use serde::{Deserialize, Serialize};

use super::value_objects::{Confidence, Language};

/// Security finding from SAST analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub location: Location,
    pub severity: Severity,
    pub confidence: Confidence,
    pub description: String,
    pub recommendation: Option<String>,
}

/// Location of a finding in source code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub file_path: String,
    pub line: u32,
    pub column: Option<u32>,
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,
}

/// Finding severity
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Security detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub languages: Vec<Language>,
    pub pattern: RulePattern,
}

/// Rule pattern for matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RulePattern {
    /// AST node type pattern
    AstNodeType(String),
    /// Function call pattern
    FunctionCall(String),
    /// Regex pattern
    Regex(String),
    /// Custom pattern matcher
    Custom(String),
}


