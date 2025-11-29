//! Semgrep output parsing types
//!
//! These types match the JSON output format of Semgrep CLI.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Root Semgrep JSON output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemgrepOutput {
    /// List of results (findings)
    #[serde(default)]
    pub results: Vec<SemgrepResult>,
    /// Errors encountered during analysis
    #[serde(default)]
    pub errors: Vec<SemgrepOutputError>,
    /// Paths that were scanned
    #[serde(default)]
    pub paths: SemgrepPaths,
    /// Timing information
    #[serde(default)]
    pub time: Option<SemgrepTiming>,
    /// Semgrep version
    #[serde(default)]
    pub version: Option<String>,
}

/// A single Semgrep result (finding)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemgrepResult {
    /// Rule ID that triggered
    pub check_id: String,
    /// File path where finding was detected
    pub path: String,
    /// Start position
    pub start: Position,
    /// End position
    pub end: Position,
    /// Additional result information
    pub extra: SemgrepResultExtra,
}

/// Position in file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Position {
    /// Line number (1-based)
    #[serde(alias = "line")]
    pub line: u32,
    /// Column number (1-based)
    #[serde(alias = "col")]
    pub col: u32,
    /// Byte offset (optional)
    #[serde(default)]
    pub offset: Option<u32>,
}

/// Extra information in a result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemgrepResultExtra {
    /// Message from the rule
    #[serde(default)]
    pub message: String,
    /// Matched source code lines
    #[serde(default)]
    pub lines: String,
    /// Severity level
    #[serde(default)]
    pub severity: String,
    /// Rule metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
    /// Suggested fix (if autofix is available)
    #[serde(default)]
    pub fix: Option<String>,
    /// Data flow for taint tracking (if applicable)
    #[serde(default)]
    pub dataflow_trace: Option<DataflowTrace>,
    /// Metavariables captured
    #[serde(default)]
    pub metavars: HashMap<String, MetavarValue>,
    /// Fingerprint for deduplication
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Is the finding from a taint rule
    #[serde(default)]
    pub is_ignored: bool,
}

/// Dataflow trace for taint tracking results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataflowTrace {
    /// Taint source location
    #[serde(default)]
    pub taint_source: Option<TaintLocation>,
    /// Intermediate locations
    #[serde(default)]
    pub intermediate_vars: Vec<IntermediateVar>,
    /// Taint sink location
    #[serde(default)]
    pub taint_sink: Option<TaintLocation>,
}

/// Location in taint tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintLocation {
    /// File path
    pub path: String,
    /// Start position
    pub start: Position,
    /// End position
    pub end: Position,
    /// Code content
    #[serde(default)]
    pub content: Option<String>,
}

/// Intermediate variable in taint flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntermediateVar {
    /// Variable location
    pub location: TaintLocation,
    /// Variable content
    #[serde(default)]
    pub content: Option<String>,
}

/// Metavariable value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetavarValue {
    /// Start position
    pub start: Position,
    /// End position
    pub end: Position,
    /// Abstract content (variable value)
    #[serde(default)]
    pub abstract_content: Option<String>,
    /// Propagated value (if known)
    #[serde(default)]
    pub propagated_value: Option<PropagatedValue>,
}

/// Propagated value information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagatedValue {
    /// Symbolic representation
    #[serde(default)]
    pub svalue_abstract_content: Option<String>,
}

/// Error entry from Semgrep output (parse/scan errors)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemgrepOutputError {
    /// Error code
    #[serde(default)]
    pub code: i32,
    /// Error level (error, warning)
    #[serde(default)]
    pub level: String,
    /// Error message
    #[serde(default)]
    pub message: String,
    /// Error type
    #[serde(default, rename = "type")]
    pub error_type: Option<String>,
    /// File path (if applicable)
    #[serde(default)]
    pub path: Option<String>,
    /// Rule ID (if applicable)
    #[serde(default)]
    pub rule_id: Option<String>,
    /// Span information
    #[serde(default)]
    pub spans: Vec<ErrorSpan>,
}

/// Error span information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorSpan {
    /// File path
    pub file: String,
    /// Start position
    pub start: Position,
    /// End position
    pub end: Position,
    /// Source context
    #[serde(default)]
    pub source_hash: Option<String>,
    /// Config start (optional)
    #[serde(default)]
    pub config_start: Option<Position>,
    /// Config end (optional)
    #[serde(default)]
    pub config_end: Option<Position>,
}

/// Scanned and skipped paths
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SemgrepPaths {
    /// Paths that were scanned
    #[serde(default)]
    pub scanned: Vec<String>,
    /// Paths that were skipped (with reasons)
    #[serde(default)]
    pub skipped: Vec<SkippedPath>,
}

/// A path that was skipped
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedPath {
    /// Path that was skipped
    pub path: String,
    /// Reason for skipping
    #[serde(default)]
    pub reason: String,
}

/// Timing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemgrepTiming {
    /// Total time in seconds
    #[serde(default)]
    pub total_time: f64,
    /// Rules timing breakdown
    #[serde(default)]
    pub rules: Vec<RuleTiming>,
    /// Per-file timing
    #[serde(default)]
    pub targets: Vec<TargetTiming>,
}

/// Timing for a single rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTiming {
    /// Rule ID
    pub id: String,
    /// Parse time
    #[serde(default)]
    pub parse_time: f64,
    /// Match time
    #[serde(default)]
    pub match_time: f64,
}

/// Timing for a single target file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetTiming {
    /// File path
    pub path: String,
    /// Total time for this file
    #[serde(default)]
    pub total_time: f64,
    /// Number of bytes
    #[serde(default)]
    pub num_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_output() {
        let json = r#"{
            "results": [
                {
                    "check_id": "python.lang.security.audit.dangerous-eval",
                    "path": "test.py",
                    "start": {"line": 5, "col": 1},
                    "end": {"line": 5, "col": 15},
                    "extra": {
                        "message": "Avoid eval()",
                        "lines": "eval(user_input)",
                        "severity": "WARNING",
                        "metadata": {}
                    }
                }
            ],
            "errors": [],
            "paths": {
                "scanned": ["test.py"],
                "skipped": []
            }
        }"#;

        let output: SemgrepOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.results.len(), 1);
        assert_eq!(
            output.results[0].check_id,
            "python.lang.security.audit.dangerous-eval"
        );
        assert_eq!(output.results[0].start.line, 5);
    }

    #[test]
    fn test_parse_taint_output() {
        let json = r#"{
            "results": [
                {
                    "check_id": "sql-injection",
                    "path": "app.py",
                    "start": {"line": 10, "col": 5},
                    "end": {"line": 10, "col": 40},
                    "extra": {
                        "message": "SQL injection detected",
                        "lines": "cursor.execute(query)",
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-89"]},
                        "dataflow_trace": {
                            "taint_source": {
                                "path": "app.py",
                                "start": {"line": 5, "col": 1},
                                "end": {"line": 5, "col": 20},
                                "content": "request.args.get('id')"
                            },
                            "intermediate_vars": [],
                            "taint_sink": {
                                "path": "app.py",
                                "start": {"line": 10, "col": 5},
                                "end": {"line": 10, "col": 40}
                            }
                        }
                    }
                }
            ],
            "errors": []
        }"#;

        let output: SemgrepOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.results.len(), 1);

        let result = &output.results[0];
        assert!(result.extra.dataflow_trace.is_some());

        let trace = result.extra.dataflow_trace.as_ref().unwrap();
        assert!(trace.taint_source.is_some());
        assert_eq!(
            trace.taint_source.as_ref().unwrap().content,
            Some("request.args.get('id')".to_string())
        );
    }

    #[test]
    fn test_parse_with_metavars() {
        let json = r#"{
            "results": [
                {
                    "check_id": "test-rule",
                    "path": "test.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 10},
                    "extra": {
                        "message": "Found function",
                        "lines": "def foo():",
                        "severity": "INFO",
                        "metadata": {},
                        "metavars": {
                            "$FUNC": {
                                "start": {"line": 1, "col": 5},
                                "end": {"line": 1, "col": 8},
                                "abstract_content": "foo"
                            }
                        }
                    }
                }
            ],
            "errors": []
        }"#;

        let output: SemgrepOutput = serde_json::from_str(json).unwrap();
        let result = &output.results[0];

        assert!(result.extra.metavars.contains_key("$FUNC"));
        assert_eq!(
            result.extra.metavars.get("$FUNC").unwrap().abstract_content,
            Some("foo".to_string())
        );
    }

    #[test]
    fn test_parse_errors() {
        let json = r#"{
            "results": [],
            "errors": [
                {
                    "code": 2,
                    "level": "error",
                    "message": "Failed to parse rule",
                    "type": "InvalidRule",
                    "rule_id": "broken-rule"
                }
            ]
        }"#;

        let output: SemgrepOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.errors.len(), 1);
        assert_eq!(output.errors[0].message, "Failed to parse rule");
    }
}
