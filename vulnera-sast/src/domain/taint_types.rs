//! Taint analysis types for SAST
//!
//! Types for tracking data flow from sources to sinks through sanitizers.

use serde::{Deserialize, Serialize};

use super::pattern_types::Pattern;
use super::value_objects::Language;

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
    pub severity: super::finding::Severity,
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

/// Summary of a function's taint behavior for inter-procedural analysis.
///
/// Computed during intra-procedural analysis and consumed by callers
/// to propagate taint across function boundaries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionTaintSummary {
    /// Function ID
    pub function_id: String,
    /// Which parameters get propagated to return value (param indices)
    pub params_to_return: std::collections::HashSet<usize>,
    /// Which parameters flow to sinks (param_idx -> sink categories)
    pub params_to_sinks: std::collections::HashMap<usize, Vec<String>>,
    /// Whether return value is inherently tainted (e.g., reads user input)
    pub return_tainted: bool,
    /// Source categories introduced by this function
    pub introduces_taint: Vec<String>,
    /// Whether this function acts as a sanitizer
    pub is_sanitizer: bool,
    /// Which labels this sanitizer clears
    pub clears_labels: Vec<String>,
}
