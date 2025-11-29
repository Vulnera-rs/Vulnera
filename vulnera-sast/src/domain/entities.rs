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
    /// Rule-specific options
    #[serde(default)]
    pub options: RuleOptions,
}

/// Rule-specific options for fine-tuning detection behavior
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleOptions {
    /// Suppress this rule in test code (tests/ dir, #[cfg(test)], #[test])
    #[serde(default = "default_true")]
    pub suppress_in_tests: bool,
    /// Suppress this rule in example code (examples/ dir)
    #[serde(default)]
    pub suppress_in_examples: bool,
    /// Suppress this rule in benchmark code (benches/ dir)
    #[serde(default)]
    pub suppress_in_benches: bool,
    /// Related rule IDs (e.g., unwrap and expect are related)
    #[serde(default)]
    pub related_rules: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// Rule pattern for matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RulePattern {
    /// AST node type pattern
    AstNodeType(String),
    /// Function call pattern (legacy - matches any call containing the name)
    FunctionCall(String),
    /// Method call pattern with AST context validation
    MethodCall(MethodCallPattern),
    /// Regex pattern
    Regex(String),
    /// Custom pattern matcher
    Custom(String),
}

/// Method call pattern with context-aware matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodCallPattern {
    /// Method name to match (e.g., "unwrap", "expect")
    pub name: String,
    /// Require the match to be an actual AST method call node
    #[serde(default = "default_true")]
    pub require_ast_node: bool,
    /// Optional receiver type hints (not enforced without type analysis)
    #[serde(default)]
    pub receiver_hints: Vec<String>,
}

impl MethodCallPattern {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            require_ast_node: true,
            receiver_hints: vec![],
        }
    }

    pub fn with_receiver_hints(mut self, hints: Vec<String>) -> Self {
        self.receiver_hints = hints;
        self
    }
}

/// Suppression directive parsed from source comments
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suppression {
    /// The line this suppression applies to (1-based)
    pub target_line: u32,
    /// Specific rule IDs to suppress, or empty for all rules
    pub rule_ids: Vec<String>,
    /// Reason for suppression (optional)
    pub reason: Option<String>,
}

/// Collection of suppressions for a file
#[derive(Debug, Clone, Default)]
pub struct FileSuppressions {
    suppressions: Vec<Suppression>,
}

impl FileSuppressions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse suppressions from file content
    /// Supports:
    /// - `// vulnera-ignore-next-line` - suppress all rules on next line
    /// - `// vulnera-ignore-next-line: rule-id` - suppress specific rule
    /// - `// vulnera-ignore-next-line: rule-id1, rule-id2` - suppress multiple rules
    /// - `// vulnera-ignore-next-line: rule-id -- reason` - with reason
    /// - `# vulnera-ignore-next-line` (Python-style)
    /// - `/* vulnera-ignore-next-line */` (block comment style)
    /// - `#[allow(vulnera::rule_id)]` (Rust attribute style)
    pub fn parse(content: &str) -> Self {
        let mut suppressions = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            let line_num = (idx + 1) as u32;
            let trimmed = line.trim();

            // Check for vulnera-ignore-next-line comments
            if let Some(suppression) = Self::parse_ignore_next_line(trimmed, line_num) {
                suppressions.push(suppression);
            }

            // Check for Rust #[allow(vulnera::...)] attributes
            if let Some(suppression) = Self::parse_rust_allow_attribute(trimmed, line_num) {
                suppressions.push(suppression);
            }
        }

        Self { suppressions }
    }

    fn parse_ignore_next_line(line: &str, line_num: u32) -> Option<Suppression> {
        // Match comment prefixes: //, #, or /* ... */
        let comment_content = if let Some(rest) = line.strip_prefix("//") {
            rest.trim()
        } else if let Some(rest) = line.strip_prefix('#') {
            // Only if not followed by [ (Rust attribute)
            if rest.trim_start().starts_with('[') {
                return None;
            }
            rest.trim()
        } else if line.starts_with("/*") && line.ends_with("*/") {
            // Block comment on single line
            line[2..line.len() - 2].trim()
        } else {
            return None;
        };

        // Check for vulnera-ignore-next-line directive
        let directive = comment_content.strip_prefix("vulnera-ignore-next-line")?;
        let directive = directive.trim_start();

        // Parse optional rule IDs and reason
        let (rule_ids, reason) = if directive.is_empty() {
            (vec![], None)
        } else if let Some(rest) = directive.strip_prefix(':') {
            Self::parse_rule_ids_and_reason(rest.trim())
        } else {
            // No colon means suppress all
            (vec![], None)
        };

        Some(Suppression {
            target_line: line_num + 1, // Suppresses the NEXT line
            rule_ids,
            reason,
        })
    }

    fn parse_rust_allow_attribute(line: &str, line_num: u32) -> Option<Suppression> {
        // Match #[allow(vulnera::rule_id)] or #[allow(vulnera::rule_id, vulnera::other)]
        let attr_content = line.strip_prefix("#[allow(")?.strip_suffix(")]")?;

        let mut rule_ids = Vec::new();
        for part in attr_content.split(',') {
            let part = part.trim();
            if let Some(rule_id) = part.strip_prefix("vulnera::") {
                // Convert underscores to hyphens (Rust identifiers use underscores)
                rule_ids.push(rule_id.replace('_', "-"));
            }
        }

        if rule_ids.is_empty() {
            return None;
        }

        Some(Suppression {
            target_line: line_num + 1, // Attribute suppresses the next line/item
            rule_ids,
            reason: None,
        })
    }

    fn parse_rule_ids_and_reason(input: &str) -> (Vec<String>, Option<String>) {
        // Split by "--" to separate rule IDs from reason
        let (ids_part, reason) = if let Some(idx) = input.find("--") {
            let reason = input[idx + 2..].trim();
            (
                &input[..idx],
                if reason.is_empty() {
                    None
                } else {
                    Some(reason.to_string())
                },
            )
        } else {
            (input, None)
        };

        let rule_ids: Vec<String> = ids_part
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        (rule_ids, reason)
    }

    /// Check if a finding on the given line should be suppressed
    pub fn is_suppressed(&self, line: u32, rule_id: &str) -> bool {
        self.suppressions.iter().any(|s| {
            s.target_line == line
                && (s.rule_ids.is_empty() || s.rule_ids.contains(&rule_id.to_string()))
        })
    }

    /// Get suppressions for a specific line
    pub fn get_suppressions_for_line(&self, line: u32) -> Vec<&Suppression> {
        self.suppressions
            .iter()
            .filter(|s| s.target_line == line)
            .collect()
    }
}
