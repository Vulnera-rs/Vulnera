//! SAST domain entities
//!
//! Core domain types for the SAST analysis engine:
//! - Pattern-based rules for direct matching
//! - Data flow rules for taint tracking
//! - Findings and locations
//! - SARIF export types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::value_objects::{Confidence, Language};

// =============================================================================
// Core Finding Types
// =============================================================================

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
    /// Data flow path if this is a taint finding
    #[serde(default)]
    pub data_flow_path: Option<DataFlowPath>,
    /// Code snippet at the finding location
    #[serde(default)]
    pub snippet: Option<String>,
}

/// Location of a finding in source code
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Location {
    pub file_path: String,
    pub line: u32,
    pub column: Option<u32>,
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,
}

impl Location {
    pub fn new(file_path: String, line: u32) -> Self {
        Self {
            file_path,
            line,
            column: None,
            end_line: None,
            end_column: None,
        }
    }

    pub fn with_columns(mut self, column: u32, end_column: u32) -> Self {
        self.column = Some(column);
        self.end_column = Some(end_column);
        self
    }

    pub fn with_end_line(mut self, end_line: u32) -> Self {
        self.end_line = Some(end_line);
        self
    }
}

/// Finding severity
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Default for Severity {
    fn default() -> Self {
        Self::Medium
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "critical"),
            Severity::High => write!(f, "high"),
            Severity::Medium => write!(f, "medium"),
            Severity::Low => write!(f, "low"),
            Severity::Info => write!(f, "info"),
        }
    }
}

// =============================================================================
// Pattern-Based Rules
// =============================================================================

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
    pub severity: Severity,
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

// =============================================================================
// Data Flow Rules (Taint Tracking)
// =============================================================================

/// A data flow rule for tracking taint from sources to sinks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowRule {
    /// Unique rule identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description
    pub description: String,
    /// Severity when taint reaches sink
    pub severity: Severity,
    /// Target languages
    pub languages: Vec<Language>,
    /// Taint sources (where untrusted data enters)
    pub sources: Vec<TaintSource>,
    /// Taint sinks (where untrusted data is dangerous)
    pub sinks: Vec<TaintSink>,
    /// Sanitizers (patterns that clean tainted data)
    #[serde(default)]
    pub sanitizers: Vec<TaintSanitizer>,
    /// Propagators (custom taint propagation rules)
    #[serde(default)]
    pub propagators: Vec<TaintPropagator>,
    /// CWE identifiers
    #[serde(default)]
    pub cwe_ids: Vec<String>,
    /// OWASP categories
    #[serde(default)]
    pub owasp_categories: Vec<String>,
    /// Tags
    #[serde(default)]
    pub tags: Vec<String>,
    /// Message template
    #[serde(default)]
    pub message: Option<String>,
}

/// A taint source pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    /// Pattern that introduces taint
    pub pattern: Pattern,
    /// Label for this source (for labeled taint tracking)
    #[serde(default)]
    pub label: Option<String>,
    /// Description of the source
    #[serde(default)]
    pub description: Option<String>,
}

/// A taint sink pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    /// Pattern where taint is dangerous
    pub pattern: Pattern,
    /// Required label (only report if taint has this label)
    #[serde(default)]
    pub requires_label: Option<String>,
    /// Which metavariable in the pattern must be tainted
    #[serde(default)]
    pub tainted_arg: Option<String>,
    /// Description of the sink
    #[serde(default)]
    pub description: Option<String>,
}

/// A sanitizer pattern that clears taint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSanitizer {
    /// Pattern that sanitizes taint
    pub pattern: Pattern,
    /// Which labels this sanitizer clears (None = all)
    #[serde(default)]
    pub clears_labels: Option<Vec<String>>,
    /// Description
    #[serde(default)]
    pub description: Option<String>,
}

/// A propagator defines custom taint propagation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPropagator {
    /// Pattern to match
    pub pattern: Pattern,
    /// Metavariable that is the taint source
    pub from: String,
    /// Metavariable that receives the taint
    pub to: String,
    /// Whether this is a side-effect propagation
    #[serde(default)]
    pub by_side_effect: bool,
}

/// Data flow path showing how taint propagates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowPath {
    /// Source location where taint originated
    pub source: DataFlowNode,
    /// Intermediate steps in the flow
    pub steps: Vec<DataFlowNode>,
    /// Sink location where taint is consumed
    pub sink: DataFlowNode,
}

/// A node in the data flow path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowNode {
    /// Location in source code
    pub location: Location,
    /// Description of what happens at this node
    pub description: String,
    /// Variable or expression being tracked
    pub expression: String,
}

// =============================================================================
// Unified Rule Type
// =============================================================================

/// A SAST rule that can be either pattern-based or data-flow-based
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "rule_type")]
pub enum SastRule {
    /// Pattern-based rule for direct matching
    #[serde(rename = "pattern")]
    Pattern(PatternRule),
    /// Data flow rule for taint tracking
    #[serde(rename = "dataflow")]
    DataFlow(DataFlowRule),
}

impl SastRule {
    /// Get the rule ID
    pub fn id(&self) -> &str {
        match self {
            SastRule::Pattern(r) => &r.id,
            SastRule::DataFlow(r) => &r.id,
        }
    }

    /// Get the rule name
    pub fn name(&self) -> &str {
        match self {
            SastRule::Pattern(r) => &r.name,
            SastRule::DataFlow(r) => &r.name,
        }
    }

    /// Get the severity
    pub fn severity(&self) -> &Severity {
        match self {
            SastRule::Pattern(r) => &r.severity,
            SastRule::DataFlow(r) => &r.severity,
        }
    }

    /// Get the languages
    pub fn languages(&self) -> &[Language] {
        match self {
            SastRule::Pattern(r) => &r.languages,
            SastRule::DataFlow(r) => &r.languages,
        }
    }

    /// Check if rule applies to a language
    pub fn applies_to(&self, lang: &Language) -> bool {
        self.languages().contains(lang)
    }

    /// Get CWE IDs
    pub fn cwe_ids(&self) -> &[String] {
        match self {
            SastRule::Pattern(r) => &r.cwe_ids,
            SastRule::DataFlow(r) => &r.cwe_ids,
        }
    }
}

// =============================================================================
// Rule Set
// =============================================================================

/// A collection of related rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSet {
    /// Unique identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description
    pub description: String,
    /// Version
    #[serde(default)]
    pub version: Option<String>,
    /// Rules in this set
    pub rules: Vec<SastRule>,
}

// =============================================================================
// Suppression Directives
// =============================================================================

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
    pub fn parse(content: &str) -> Self {
        let mut suppressions = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            let line_num = (idx + 1) as u32;
            let trimmed = line.trim();

            if let Some(suppression) = Self::parse_ignore_next_line(trimmed, line_num) {
                suppressions.push(suppression);
            }

            if let Some(suppression) = Self::parse_rust_allow_attribute(trimmed, line_num) {
                suppressions.push(suppression);
            }
        }

        Self { suppressions }
    }

    fn parse_ignore_next_line(line: &str, line_num: u32) -> Option<Suppression> {
        let comment_content = if let Some(rest) = line.strip_prefix("//") {
            rest.trim()
        } else if let Some(rest) = line.strip_prefix('#') {
            if rest.trim_start().starts_with('[') {
                return None;
            }
            rest.trim()
        } else if line.starts_with("/*") && line.ends_with("*/") {
            line[2..line.len() - 2].trim()
        } else {
            return None;
        };

        let directive = comment_content.strip_prefix("vulnera-ignore-next-line")?;
        let directive = directive.trim_start();

        let (rule_ids, reason) = if directive.is_empty() {
            (vec![], None)
        } else if let Some(rest) = directive.strip_prefix(':') {
            Self::parse_rule_ids_and_reason(rest.trim())
        } else {
            (vec![], None)
        };

        Some(Suppression {
            target_line: line_num + 1,
            rule_ids,
            reason,
        })
    }

    fn parse_rust_allow_attribute(line: &str, line_num: u32) -> Option<Suppression> {
        let attr_content = line.strip_prefix("#[allow(")?.strip_suffix(")]")?;

        let mut rule_ids = Vec::new();
        for part in attr_content.split(',') {
            let part = part.trim();
            if let Some(rule_id) = part.strip_prefix("vulnera::") {
                rule_ids.push(rule_id.replace('_', "-"));
            }
        }

        if rule_ids.is_empty() {
            return None;
        }

        Some(Suppression {
            target_line: line_num + 1,
            rule_ids,
            reason: None,
        })
    }

    fn parse_rule_ids_and_reason(input: &str) -> (Vec<String>, Option<String>) {
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

/// SARIF tool driver
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

/// SARIF rule properties
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
    pub fingerprints: Option<HashMap<String, String>>,
    #[serde(default)]
    pub fixes: Option<Vec<SarifFix>>,
    #[serde(default)]
    pub code_flows: Option<Vec<SarifCodeFlow>>,
}

/// SARIF code flow (for data flow visualization)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifCodeFlow {
    pub thread_flows: Vec<SarifThreadFlow>,
}

/// SARIF thread flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifThreadFlow {
    pub locations: Vec<SarifThreadFlowLocation>,
}

/// SARIF thread flow location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifThreadFlowLocation {
    pub location: SarifLocation,
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

/// SARIF artifact location
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactLocation {
    pub uri: String,
    #[serde(default)]
    pub uri_base_id: Option<String>,
}

/// SARIF region
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

/// SARIF invocation
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

// =============================================================================
// Call Graph Types
// =============================================================================

/// A node in the call graph representing a function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphNode {
    /// Unique identifier (fully qualified name)
    pub id: String,
    /// Function signature
    pub signature: FunctionSignature,
    /// File containing this function
    pub file_path: String,
    /// Start line in source
    pub start_line: u32,
    /// End line in source
    pub end_line: u32,
}

/// Function signature for call graph nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    /// Function name
    pub name: String,
    /// Module path (e.g., "mypackage.mymodule")
    pub module_path: Option<String>,
    /// Parameter names and types
    pub parameters: Vec<ParameterInfo>,
    /// Return type (if known)
    pub return_type: Option<String>,
}

impl FunctionSignature {
    /// Get fully qualified name
    pub fn fully_qualified_name(&self) -> String {
        match &self.module_path {
            Some(path) => format!("{}.{}", path, self.name),
            None => self.name.clone(),
        }
    }
}

/// Parameter information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterInfo {
    /// Parameter name
    pub name: String,
    /// Parameter type (if known)
    pub type_hint: Option<String>,
    /// Default value (if any)
    pub default_value: Option<String>,
}

/// A call site (where a function is called)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    /// ID of the called function
    pub target_id: String,
    /// Name of the called function (for display)
    pub target_name: String,
    /// Arguments passed to the call
    pub arguments: Vec<ArgumentInfo>,
    /// Line of the call
    pub line: u32,
    /// Column of the call
    pub column: u32,
}

/// Argument information at a call site
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgumentInfo {
    /// Argument expression (source text)
    pub expression: String,
    /// Whether this argument is tainted
    pub is_tainted: bool,
}

// =============================================================================
// Taint Tracking Types (for data_flow module)
// =============================================================================

/// Taint label for labeled taint analysis
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TaintLabel {
    /// Source identifier
    pub source: String,
    /// Category (e.g., "user_input", "file_input")
    pub category: String,
}

/// Current taint state of a variable/expression
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintState {
    /// Labels attached to this value
    pub labels: Vec<TaintLabel>,
    /// File where taint originated
    pub origin_file: String,
    /// Line where taint originated
    pub origin_line: u32,
    /// Full flow path from origin to current point
    pub flow_path: Vec<FlowStep>,
}

/// A step in the data flow path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStep {
    /// Type of step
    pub kind: FlowStepKind,
    /// Expression at this step
    pub expression: String,
    /// File location
    pub file: String,
    /// Line number
    pub line: u32,
    /// Column number
    pub column: u32,
    /// Additional note
    pub note: Option<String>,
}

/// Kind of flow step
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FlowStepKind {
    /// Taint source (entry point)
    Source,
    /// Taint propagation
    Propagation,
    /// Sanitization (taint removed)
    Sanitizer,
    /// Taint sink (dangerous operation)
    Sink,
}

/// A complete data flow path from source to sink (for findings)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowFinding {
    /// Rule that detected this
    pub rule_id: String,
    /// Source step
    pub source: FlowStep,
    /// Intermediate propagation steps
    pub intermediate_steps: Vec<FlowStep>,
    /// Sink step
    pub sink: FlowStep,
    /// Taint labels involved
    pub labels: Vec<TaintLabel>,
}

// =============================================================================
// Pattern Engine Types
// =============================================================================

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

// =============================================================================
// Legacy Support - Type aliases for backwards compatibility
// =============================================================================

/// Alias for PatternRule (backwards compatibility)
pub type Rule = PatternRule;

/// Legacy RulePattern enum - use Pattern instead
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RulePattern {
    TreeSitterQuery(String),
}

impl From<RulePattern> for Pattern {
    fn from(rp: RulePattern) -> Self {
        match rp {
            RulePattern::TreeSitterQuery(q) => Pattern::TreeSitterQuery(q),
        }
    }
}
