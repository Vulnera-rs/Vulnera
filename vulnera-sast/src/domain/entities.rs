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
    /// CWE identifiers (e.g., ["CWE-89", "CWE-78"])
    #[serde(default)]
    pub cwe_ids: Vec<String>,
    /// OWASP categories (e.g., ["A03:2021 - Injection"])
    #[serde(default)]
    pub owasp_categories: Vec<String>,
    /// Custom tags for categorization
    #[serde(default)]
    pub tags: Vec<String>,
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

/// Rule pattern for matching - uses tree-sitter S-expression queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RulePattern {
    /// Tree-sitter S-expression query pattern (primary pattern type)
    ///
    /// Example queries:
    /// - Function call: `(call_expression function: (identifier) @fn (#eq? @fn "eval"))`
    /// - Method call: `(call_expression function: (attribute object: (_) attribute: (identifier) @method) (#eq? @method "unwrap"))`
    /// - Unsafe block: `(unsafe_block) @unsafe`
    TreeSitterQuery(String),
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

// =============================================================================
// Semgrep Taint Analysis Types
// =============================================================================

/// Configuration for Semgrep taint mode analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintConfig {
    /// Taint sources (patterns that introduce untrusted data)
    pub sources: Vec<TaintPattern>,
    /// Taint sinks (patterns where tainted data is dangerous)
    pub sinks: Vec<TaintPattern>,
    /// Sanitizers (patterns that clean/validate tainted data)
    #[serde(default)]
    pub sanitizers: Vec<TaintPattern>,
    /// Propagators (patterns that transfer taint through functions)
    #[serde(default)]
    pub propagators: Vec<TaintPropagator>,
}

/// A taint pattern with optional label
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPattern {
    /// Semgrep pattern string
    pub pattern: String,
    /// Optional label for taint tracking
    #[serde(default)]
    pub label: Option<String>,
    /// Require specific labels (for labeled taint tracking)
    #[serde(default)]
    pub requires: Option<String>,
}

/// Taint propagator specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPropagator {
    /// Pattern to match
    pub pattern: String,
    /// Metavariable to propagate from
    pub from: String,
    /// Metavariable to propagate to
    pub to: String,
    /// Whether taint propagates by side-effect
    #[serde(default)]
    pub by_side_effect: bool,
}

/// Semgrep rule stored in database (separate table)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemgrepRule {
    /// Unique rule identifier
    pub id: String,
    /// Rule name
    pub name: String,
    /// Human-readable message
    pub message: String,
    /// Target languages
    pub languages: Vec<Language>,
    /// Severity level
    pub severity: Severity,
    /// Rule mode (search or taint)
    pub mode: SemgrepRuleMode,
    /// Pattern for search mode
    #[serde(default)]
    pub pattern: Option<String>,
    /// Patterns list for complex matching
    #[serde(default)]
    pub patterns: Option<Vec<String>>,
    /// Taint configuration for taint mode
    #[serde(default)]
    pub taint_config: Option<TaintConfig>,
    /// CWE identifiers
    #[serde(default)]
    pub cwe_ids: Vec<String>,
    /// OWASP categories
    #[serde(default)]
    pub owasp_categories: Vec<String>,
    /// Custom tags
    #[serde(default)]
    pub tags: Vec<String>,
    /// Autofix suggestion
    #[serde(default)]
    pub fix: Option<String>,
    /// Additional metadata
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
}

/// Semgrep rule mode
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SemgrepRuleMode {
    /// Standard pattern search mode
    Search,
    /// Taint tracking mode
    Taint,
}

impl Default for SemgrepRuleMode {
    fn default() -> Self {
        Self::Search
    }
}

// =============================================================================
// SARIF Export Types (v2.1.0)
// =============================================================================

/// SARIF report conforming to v2.1.0 schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

impl Default for SarifReport {
    fn default() -> Self {
        Self {
            schema:
                "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
                    .to_string(),
            version: "2.1.0".to_string(),
            runs: vec![],
        }
    }
}

/// A single SARIF run (one invocation of a tool)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
    #[serde(default)]
    pub invocations: Vec<SarifInvocation>,
}

/// SARIF tool information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifToolDriver,
}

/// SARIF tool driver (the main tool component)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifToolDriver {
    pub name: String,
    #[serde(default)]
    pub semantic_version: Option<String>,
    #[serde(default)]
    pub rules: Vec<SarifRule>,
}

/// SARIF rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRule {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub short_description: Option<SarifMessage>,
    #[serde(default)]
    pub full_description: Option<SarifMessage>,
    #[serde(default)]
    pub help: Option<SarifMessage>,
    #[serde(default)]
    pub help_uri: Option<String>,
    #[serde(default)]
    pub default_configuration: Option<SarifDefaultConfiguration>,
    #[serde(default)]
    pub properties: Option<SarifRuleProperties>,
}

/// SARIF message with text
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
    #[serde(default)]
    pub markdown: Option<String>,
}

/// SARIF default configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDefaultConfiguration {
    pub level: SarifLevel,
}

/// SARIF severity level
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SarifLevel {
    None,
    Note,
    Warning,
    Error,
}

impl From<&Severity> for SarifLevel {
    fn from(severity: &Severity) -> Self {
        match severity {
            Severity::Critical | Severity::High => SarifLevel::Error,
            Severity::Medium => SarifLevel::Warning,
            Severity::Low | Severity::Info => SarifLevel::Note,
        }
    }
}

/// SARIF rule properties (tags, CWE, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRuleProperties {
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub precision: Option<String>,
}

/// SARIF result (a single finding)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    pub rule_id: String,
    pub level: SarifLevel,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    #[serde(default)]
    pub fingerprints: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    pub fixes: Option<Vec<SarifFix>>,
}

/// SARIF location
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

/// SARIF physical location
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
    #[serde(default)]
    pub region: Option<SarifRegion>,
}

/// SARIF artifact location (file path)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactLocation {
    pub uri: String,
    #[serde(default)]
    pub uri_base_id: Option<String>,
}

/// SARIF region (line/column range)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRegion {
    pub start_line: u32,
    #[serde(default)]
    pub start_column: Option<u32>,
    #[serde(default)]
    pub end_line: Option<u32>,
    #[serde(default)]
    pub end_column: Option<u32>,
    #[serde(default)]
    pub snippet: Option<SarifSnippet>,
}

/// SARIF code snippet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifSnippet {
    pub text: String,
}

/// SARIF fix suggestion
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifFix {
    pub description: SarifMessage,
    pub artifact_changes: Vec<SarifArtifactChange>,
}

/// SARIF artifact change
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactChange {
    pub artifact_location: SarifArtifactLocation,
    pub replacements: Vec<SarifReplacement>,
}

/// SARIF replacement
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifReplacement {
    pub deleted_region: SarifRegion,
    pub inserted_content: SarifInsertedContent,
}

/// SARIF inserted content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifInsertedContent {
    pub text: String,
}

/// SARIF invocation (execution metadata)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifInvocation {
    pub execution_successful: bool,
    #[serde(default)]
    pub tool_execution_notifications: Vec<SarifNotification>,
}

/// SARIF notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifNotification {
    pub level: SarifLevel,
    pub message: SarifMessage,
}
