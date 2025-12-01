//! Test data fixtures for vulnera-sast
//!
//! This module provides:
//! - Static code fixtures for basic tests
//! - CVE fixture loading from YAML files for comprehensive vulnerability testing
//! - Real-world vulnerability patterns that caused catastrophic damage

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

// =============================================================================
// CVE Fixture Types - For testing against real-world vulnerabilities
// =============================================================================

/// A CVE fixture containing vulnerable and safe code patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveFixture {
    /// CVE identifier (e.g., "CVE-2019-12308") or custom ID
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Programming language
    pub language: String,
    /// Vulnerability type (sql_injection, xss, rce, path_traversal, ssrf, etc.)
    pub vulnerability_type: String,
    /// Severity level
    pub severity: String,
    /// Associated CWE identifiers
    #[serde(default)]
    pub cwe: Vec<String>,
    /// Impact description
    pub impact: String,
    /// Detailed description
    pub description: String,
    /// Individual test cases
    pub test_cases: Vec<CveTestCase>,
}

/// A single test case within a CVE fixture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveTestCase {
    /// Test case name
    pub name: String,
    /// Whether this code is vulnerable (true) or safe (false)
    pub vulnerable: bool,
    /// The source code to analyze
    pub code: String,
    /// Expected findings (empty for safe code)
    #[serde(default)]
    pub expected_findings: Vec<ExpectedFinding>,
    /// Optional taint path description for documentation
    #[serde(default)]
    pub taint_path: Option<String>,
}

/// Expected finding from analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedFinding {
    /// Rule ID that should trigger
    pub rule_id: String,
    /// Expected line number (1-indexed)
    pub line: u32,
    /// Expected severity
    pub severity: String,
    /// Optional message pattern to match
    #[serde(default)]
    pub message_contains: Option<String>,
}

impl CveFixture {
    /// Load a CVE fixture from a YAML file
    pub fn from_file(path: &Path) -> Result<Self, CveFixtureError> {
        let content = fs::read_to_string(path)
            .map_err(|e| CveFixtureError::IoError(path.to_path_buf(), e))?;
        serde_yml::from_str(&content)
            .map_err(|e| CveFixtureError::ParseError(path.to_path_buf(), e.to_string()))
    }

    /// Load all CVE fixtures from a directory
    pub fn load_all(dir: &Path) -> Result<Vec<Self>, CveFixtureError> {
        let mut fixtures = Vec::new();

        if !dir.exists() {
            return Err(CveFixtureError::DirectoryNotFound(dir.to_path_buf()));
        }

        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|ext| ext == "yaml" || ext == "yml")
            })
        {
            let fixture = Self::from_file(entry.path())?;
            fixtures.push(fixture);
        }

        Ok(fixtures)
    }

    /// Get the file extension for this fixture's language
    pub fn file_extension(&self) -> &'static str {
        match self.language.to_lowercase().as_str() {
            "python" => "py",
            "javascript" | "js" => "js",
            "typescript" | "ts" => "ts",
            "go" | "golang" => "go",
            "rust" | "rs" => "rs",
            "c" => "c",
            "cpp" | "c++" => "cpp",
            _ => "txt",
        }
    }

    /// Get vulnerable test cases only
    pub fn vulnerable_cases(&self) -> impl Iterator<Item = &CveTestCase> {
        self.test_cases.iter().filter(|tc| tc.vulnerable)
    }

    /// Get safe test cases only
    pub fn safe_cases(&self) -> impl Iterator<Item = &CveTestCase> {
        self.test_cases.iter().filter(|tc| !tc.vulnerable)
    }
}

/// Errors that can occur when loading CVE fixtures
#[derive(Debug)]
pub enum CveFixtureError {
    IoError(PathBuf, std::io::Error),
    ParseError(PathBuf, String),
    DirectoryNotFound(PathBuf),
}

impl std::fmt::Display for CveFixtureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(path, e) => write!(f, "Failed to read {}: {}", path.display(), e),
            Self::ParseError(path, e) => write!(f, "Failed to parse {}: {}", path.display(), e),
            Self::DirectoryNotFound(path) => {
                write!(f, "Fixture directory not found: {}", path.display())
            }
        }
    }
}

impl std::error::Error for CveFixtureError {}

// =============================================================================
// Static Code Fixtures - For basic tests
// =============================================================================

/// Sample Python code with security issue
pub fn sample_python_vulnerable() -> &'static str {
    r#"import subprocess
def execute_command(user_input):
    subprocess.call(user_input, shell=True)
"#
}

/// Sample JavaScript code with security issue
pub fn sample_javascript_vulnerable() -> &'static str {
    r#"function queryDatabase(userInput) {
    const query = "SELECT * FROM users WHERE id = " + userInput;
    db.query(query);
}
"#
}

/// Sample safe Python code
pub fn sample_python_safe() -> &'static str {
    r#"import subprocess
def execute_command(command):
    # Safe implementation
    subprocess.call([command], shell=False)
"#
}

// =============================================================================
// CVE Fixture Discovery - Helper for test runners
// =============================================================================

/// Get the path to the CVE fixtures directory
pub fn cve_fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("cve-fixtures")
}

/// Load all CVE fixtures for testing
pub fn load_cve_fixtures() -> Result<Vec<CveFixture>, CveFixtureError> {
    CveFixture::load_all(&cve_fixtures_dir())
}

/// Load CVE fixtures for a specific language
pub fn load_cve_fixtures_for_language(language: &str) -> Result<Vec<CveFixture>, CveFixtureError> {
    let fixtures = load_cve_fixtures()?;
    Ok(fixtures
        .into_iter()
        .filter(|f| f.language.to_lowercase() == language.to_lowercase())
        .collect())
}

// =============================================================================
// Test Result Types - For validation
// =============================================================================

/// Result of running a CVE fixture test
#[derive(Debug)]
pub struct CveTestResult {
    pub fixture_id: String,
    pub test_case_name: String,
    pub passed: bool,
    pub expected_findings: usize,
    pub actual_findings: usize,
    pub missing_findings: Vec<ExpectedFinding>,
    pub unexpected_findings: Vec<String>,
}

impl CveTestResult {
    pub fn new(fixture_id: &str, test_case_name: &str) -> Self {
        Self {
            fixture_id: fixture_id.to_string(),
            test_case_name: test_case_name.to_string(),
            passed: true,
            expected_findings: 0,
            actual_findings: 0,
            missing_findings: Vec::new(),
            unexpected_findings: Vec::new(),
        }
    }
}

/// Summary of all CVE fixture test results
#[derive(Debug, Default)]
pub struct CveTestSummary {
    pub total_fixtures: usize,
    pub total_test_cases: usize,
    pub passed: usize,
    pub failed: usize,
    pub results: Vec<CveTestResult>,
}

impl CveTestSummary {
    pub fn add_result(&mut self, result: CveTestResult) {
        if result.passed {
            self.passed += 1;
        } else {
            self.failed += 1;
        }
        self.total_test_cases += 1;
        self.results.push(result);
    }

    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }

    pub fn coverage_percentage(&self) -> f64 {
        if self.total_test_cases == 0 {
            0.0
        } else {
            (self.passed as f64 / self.total_test_cases as f64) * 100.0
        }
    }
}
