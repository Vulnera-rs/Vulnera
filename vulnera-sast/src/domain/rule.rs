//! Rule types and SARIF export for SAST analysis
//!
//! Unified rule type, rule sets, and SARIF v2.1.0 export types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::finding::Severity;
use super::pattern_types::PatternRule;
use super::taint_types::DataFlowRule;
use super::value_objects::Language;

// =============================================================================
// Rule Metadata Trait
// =============================================================================

/// Common metadata for all rule types
pub trait RuleMetadata {
    /// Get the rule ID
    fn id(&self) -> &str;
    /// Get the rule name
    fn name(&self) -> &str;
    /// Get the severity
    fn severity(&self) -> &Severity;
    /// Get the languages
    fn languages(&self) -> &[Language];
    /// Get CWE IDs
    fn cwe_ids(&self) -> &[String];
}

impl RuleMetadata for PatternRule {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn severity(&self) -> &Severity {
        &self.severity
    }
    fn languages(&self) -> &[Language] {
        &self.languages
    }
    fn cwe_ids(&self) -> &[String] {
        &self.cwe_ids
    }
}

impl RuleMetadata for DataFlowRule {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn severity(&self) -> &Severity {
        &self.severity
    }
    fn languages(&self) -> &[Language] {
        &self.languages
    }
    fn cwe_ids(&self) -> &[String] {
        &self.cwe_ids
    }
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

impl RuleMetadata for SastRule {
    fn id(&self) -> &str {
        match self {
            SastRule::Pattern(r) => r.id(),
            SastRule::DataFlow(r) => r.id(),
        }
    }

    fn name(&self) -> &str {
        match self {
            SastRule::Pattern(r) => r.name(),
            SastRule::DataFlow(r) => r.name(),
        }
    }

    fn severity(&self) -> &Severity {
        match self {
            SastRule::Pattern(r) => r.severity(),
            SastRule::DataFlow(r) => r.severity(),
        }
    }

    fn languages(&self) -> &[Language] {
        match self {
            SastRule::Pattern(r) => r.languages(),
            SastRule::DataFlow(r) => r.languages(),
        }
    }

    fn cwe_ids(&self) -> &[String] {
        match self {
            SastRule::Pattern(r) => r.cwe_ids(),
            SastRule::DataFlow(r) => r.cwe_ids(),
        }
    }
}

impl SastRule {
    /// Check if rule applies to a language
    pub fn applies_to(&self, lang: &Language) -> bool {
        self.languages().contains(lang)
    }
}

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
// Legacy Support
// =============================================================================

/// Alias for PatternRule (backwards compatibility)
pub type Rule = PatternRule;

/// Legacy RulePattern enum - use Pattern instead
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RulePattern {
    TreeSitterQuery(String),
}

impl From<RulePattern> for super::pattern_types::Pattern {
    fn from(rp: RulePattern) -> Self {
        match rp {
            RulePattern::TreeSitterQuery(q) => {
                super::pattern_types::Pattern::TreeSitterQuery(q)
            }
        }
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
            schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
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
