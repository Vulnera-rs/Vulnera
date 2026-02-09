//! Core fixture runner: scans test case code and compares against expected findings.

#![allow(dead_code)]

use std::collections::HashMap;
use uuid::Uuid;

use vulnera_core::config::SastConfig;
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig};
use vulnera_sast::SastModule;

use super::accuracy::{CaseOutcome, LanguageMetrics};
use super::fixture_types::{CveFixture, ExpectedFinding, TestCase};

/// Result of running a single test case.
#[derive(Debug)]
pub struct TestCaseResult {
    /// Test case name
    pub name: String,
    /// Whether the fixture marked this as vulnerable
    pub expected_vulnerable: bool,
    /// Rule IDs detected by the scanner
    pub detected_rule_ids: Vec<String>,
    /// All findings from the scanner for this test case
    pub findings: Vec<FindingSummary>,
    /// Outcome classification (TP, FP, TN, FN)
    pub outcome: CaseOutcome,
    /// Detailed failure message (None = passed)
    pub failure: Option<String>,
}

/// Condensed finding info for assertion.
#[derive(Debug, Clone)]
pub struct FindingSummary {
    pub rule_id: String,
    pub line: Option<u32>,
    pub severity: String,
    pub description: String,
}

/// Result of running an entire fixture file.
#[derive(Debug)]
pub struct FixtureResult {
    pub fixture_id: String,
    pub language: String,
    pub case_results: Vec<TestCaseResult>,
}

impl FixtureResult {
    /// Count of passed test cases.
    pub fn passed(&self) -> usize {
        self.case_results.iter().filter(|r| r.failure.is_none()).count()
    }

    /// Count of failed test cases.
    pub fn failed(&self) -> usize {
        self.case_results.iter().filter(|r| r.failure.is_some()).count()
    }

    /// Accumulate metrics into a `LanguageMetrics`.
    pub fn accumulate_metrics(&self, metrics: &mut LanguageMetrics) {
        for result in &self.case_results {
            match result.outcome {
                CaseOutcome::TruePositive => metrics.true_positives += 1,
                CaseOutcome::FalseNegative => metrics.false_negatives += 1,
                CaseOutcome::TrueNegative => metrics.true_negatives += 1,
                CaseOutcome::FalsePositive => metrics.false_positives += 1,
            }
        }
    }
}

/// Run all test cases in a fixture through the SAST scanner.
pub async fn run_fixture(fixture: &CveFixture) -> FixtureResult {
    let mut case_results = Vec::with_capacity(fixture.test_cases.len());

    for test_case in &fixture.test_cases {
        let result = run_test_case(test_case, fixture.file_extension()).await;
        case_results.push(result);
    }

    FixtureResult {
        fixture_id: fixture.id.clone(),
        language: fixture.language.clone(),
        case_results,
    }
}

/// Run a single test case: write code to temp file, scan, compare results.
async fn run_test_case(test_case: &TestCase, file_ext: &str) -> TestCaseResult {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let file_name = format!("test_fixture.{file_ext}");
    let file_path = temp_dir.path().join(&file_name);
    std::fs::write(&file_path, &test_case.code).expect("Failed to write test file");

    let config = SastConfig {
        enable_data_flow: true,
        enable_call_graph: true,
        ..Default::default()
    };

    let module = SastModule::with_config(&config);
    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "fixture-runner".to_string(),
        source_uri: temp_dir.path().to_string_lossy().to_string(),
        config: HashMap::new(),
    };

    let module_result = module
        .execute(&module_config)
        .await
        .expect("Module execution should not fail");

    let findings: Vec<FindingSummary> = module_result
        .findings
        .iter()
        .map(|f| FindingSummary {
            rule_id: f.rule_id.clone().unwrap_or_default(),
            line: f.location.line,
            severity: format!("{:?}", f.severity),
            description: f.description.clone(),
        })
        .collect();

    let detected_rule_ids: Vec<String> = findings.iter().map(|f| f.rule_id.clone()).collect();

    let (outcome, failure) = classify_outcome(test_case, &findings);

    TestCaseResult {
        name: test_case.name.clone(),
        expected_vulnerable: test_case.vulnerable,
        detected_rule_ids,
        findings,
        outcome,
        failure,
    }
}

/// Classify a test case outcome and produce a failure message if it fails.
fn classify_outcome(
    test_case: &TestCase,
    findings: &[FindingSummary],
) -> (CaseOutcome, Option<String>) {
    if test_case.vulnerable {
        // Expected to find vulnerabilities
        if test_case.expected_findings.is_empty() {
            // No specific expectation, just needs at least one finding
            if findings.is_empty() {
                (
                    CaseOutcome::FalseNegative,
                    Some(format!(
                        "MISS: '{}' — expected at least one finding but got none",
                        test_case.name
                    )),
                )
            } else {
                (CaseOutcome::TruePositive, None)
            }
        } else {
            // Check each expected finding
            let mut unmatched = Vec::new();
            for expected in &test_case.expected_findings {
                if !matches_any_finding(expected, findings) {
                    unmatched.push(expected);
                }
            }

            if unmatched.is_empty() {
                (CaseOutcome::TruePositive, None)
            } else {
                let found_ids: Vec<&str> =
                    findings.iter().map(|f| f.rule_id.as_str()).collect();
                let msg = format!(
                    "MISS: '{}' — expected rule(s) [{}] but found {:?}",
                    test_case.name,
                    unmatched
                        .iter()
                        .map(|e| e.rule_id.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    found_ids,
                );
                (CaseOutcome::FalseNegative, Some(msg))
            }
        }
    } else {
        // Safe code — expect NO findings
        if findings.is_empty() {
            (CaseOutcome::TrueNegative, None)
        } else {
            let found_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
            (
                CaseOutcome::FalsePositive,
                Some(format!(
                    "FP: '{}' — expected no findings but found {:?}",
                    test_case.name, found_ids,
                )),
            )
        }
    }
}

/// Check if an expected finding matches any actual finding.
///
/// Uses fuzzy matching: a fixture `rule_id` of "sql_injection" matches actual
/// rule IDs containing "sql" AND "injection" (e.g. "js-sql-injection", "go-sql-injection").
/// Exact matches are also accepted.
fn matches_any_finding(expected: &ExpectedFinding, findings: &[FindingSummary]) -> bool {
    findings.iter().any(|f| {
        let rule_match = rule_id_matches(&expected.rule_id, &f.rule_id);

        let line_match = expected
            .line
            .map(|el| {
                f.line
                    .map(|fl| {
                        // Allow ±2 line tolerance for minor formatting differences
                        (el as i64 - fl as i64).unsigned_abs() <= 2
                    })
                    .unwrap_or(false)
            })
            .unwrap_or(true);

        let severity_match = expected
            .severity
            .as_ref()
            .map(|es| f.severity.to_lowercase().contains(&es.to_lowercase()))
            .unwrap_or(true);

        let message_match = expected
            .message_contains
            .as_ref()
            .map(|substr| {
                f.description
                    .to_lowercase()
                    .contains(&substr.to_lowercase())
            })
            .unwrap_or(true);

        rule_match && line_match && severity_match && message_match
    })
}

/// Fuzzy rule ID matching.
///
/// - Exact match: "js-eval-direct" == "js-eval-direct"
/// - Category match: "sql_injection" matches "js-sql-injection" (splits on _ and checks all parts)
/// - Partial match: "deserialization" matches "unsafe-deserialization"
/// - SSRF match: "ssrf" matches "go-ssrf"
fn rule_id_matches(expected: &str, actual: &str) -> bool {
    let expected_lower = expected.to_lowercase();
    let actual_lower = actual.to_lowercase();

    // Exact match
    if expected_lower == actual_lower {
        return true;
    }

    // Split expected by _ or - and check if all parts appear in actual
    let parts: Vec<&str> = expected_lower.split(['_', '-']).collect();
    if parts.len() > 1 && parts.iter().all(|part| actual_lower.contains(part)) {
        return true;
    }

    // Simple substring: "ssrf" in "go-ssrf", "deserialization" in "unsafe-deserialization"
    if actual_lower.contains(&expected_lower) || expected_lower.contains(&actual_lower) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::rule_id_matches;

    #[test]
    fn test_rule_id_exact_match() {
        assert!(rule_id_matches("js-eval-direct", "js-eval-direct"));
    }

    #[test]
    fn test_rule_id_category_match() {
        assert!(rule_id_matches("sql_injection", "js-sql-injection"));
        assert!(rule_id_matches("sql_injection", "go-sql-injection"));
    }

    #[test]
    fn test_rule_id_partial_match() {
        assert!(rule_id_matches("ssrf", "go-ssrf"));
        assert!(rule_id_matches("ssrf", "data-flow-ssrf")); // Data flow findings
        assert!(rule_id_matches("deserialization", "unsafe-deserialization"));
        assert!(rule_id_matches("ssti", "js-ssti"));
        assert!(rule_id_matches("path_traversal", "data-flow-path_traversal"));
    }

    #[test]
    fn test_rule_id_no_match() {
        assert!(!rule_id_matches("xss", "sql-injection"));
    }
}
