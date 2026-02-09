//! Finding types for SAST analysis
//!
//! Core types for security findings, locations, and data flow tracking.

use serde::{Deserialize, Serialize};

use super::value_objects::Confidence;

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
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum Severity {
    Critical,
    High,
    #[default]
    Medium,
    Low,
    Info,
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
