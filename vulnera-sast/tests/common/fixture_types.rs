//! YAML fixture type definitions for CVE-based SAST testing
//!
//! Each YAML fixture describes a vulnerability class with multiple test cases containing
//! both **vulnerable** (true-positive) and **safe** (false-positive check) code samples.

#![allow(dead_code)]

use serde::Deserialize;
use std::path::Path;

/// Top-level CVE fixture parsed from a YAML file.
#[derive(Debug, Deserialize)]
pub struct CveFixture {
    /// Fixture identifier (e.g. "CVE-2019-12308", "PICKLE-YAML-RCE")
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Target language
    pub language: String,
    /// Vulnerability class (e.g. "sql_injection", "ssrf")
    pub vulnerability_type: String,
    /// Overall severity
    pub severity: String,
    /// CWE identifiers
    #[serde(default)]
    pub cwe: Vec<String>,
    /// Impact description
    #[serde(default)]
    pub impact: Option<String>,
    /// Detailed description
    #[serde(default)]
    pub description: Option<String>,
    /// Individual test cases
    pub test_cases: Vec<TestCase>,
}

/// A single test case within a fixture.
#[derive(Debug, Deserialize)]
pub struct TestCase {
    /// Test case name for diagnostics
    pub name: String,
    /// Whether this code is vulnerable (true → expect findings, false → expect none)
    pub vulnerable: bool,
    /// Source code to scan
    pub code: String,
    /// Expected findings for vulnerable=true cases
    #[serde(default)]
    pub expected_findings: Vec<ExpectedFinding>,
    /// Optional taint path description (informational, validated when taint tracking is active)
    #[serde(default)]
    pub taint_path: Option<String>,
}

/// Expected finding to assert against scanner output.
#[derive(Debug, Deserialize)]
pub struct ExpectedFinding {
    /// Rule ID that should trigger (may be a category like "sql_injection" or exact like "js-eval-direct")
    pub rule_id: String,
    /// Expected line number (1-based)
    #[serde(default)]
    pub line: Option<u32>,
    /// Expected severity
    #[serde(default)]
    pub severity: Option<String>,
    /// Substring that should appear in the finding message
    #[serde(default)]
    pub message_contains: Option<String>,
}

impl CveFixture {
    /// Parse a YAML fixture file from disk.
    pub fn from_file(path: &Path) -> Result<Self, FixtureError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| FixtureError::Io(path.display().to_string(), e))?;
        serde_yml::from_str(&content)
            .map_err(|e| FixtureError::Parse(path.display().to_string(), e.to_string()))
    }

    /// File extension for this fixture's language.
    pub fn file_extension(&self) -> &str {
        match self.language.to_lowercase().as_str() {
            "python" => "py",
            "javascript" => "js",
            "typescript" => "ts",
            "rust" => "rs",
            "go" => "go",
            "c" => "c",
            "cpp" | "c++" => "cpp",
            _ => "txt",
        }
    }

    /// Count of vulnerable test cases.
    pub fn tp_case_count(&self) -> usize {
        self.test_cases.iter().filter(|tc| tc.vulnerable).count()
    }

    /// Count of safe (non-vulnerable) test cases.
    pub fn fp_case_count(&self) -> usize {
        self.test_cases.iter().filter(|tc| !tc.vulnerable).count()
    }
}

/// Errors from fixture loading.
#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    #[error("IO error reading {0}: {1}")]
    Io(String, std::io::Error),
    #[error("YAML parse error in {0}: {1}")]
    Parse(String, String),
}
