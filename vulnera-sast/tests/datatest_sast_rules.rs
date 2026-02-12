//! Data-driven tests for SAST rules using CVE fixture YAML files
//!
//! Each YAML fixture in `tests/data/cve-fixtures/` describes a vulnerability class
//! with multiple test cases. The harness:
//! 1. Parses the YAML fixture
//! 2. For each test case, writes code to a temp file and runs the SAST scanner
//! 3. Asserts true positives (vulnerable code detected) and true negatives (safe code clean)
// cspell:ignore datatest

mod common;

use common::fixture_runner;
use common::fixture_types::CveFixture;
use std::path::Path;

fn test_cve_fixture(path: &Path) -> datatest_stable::Result<()> {
    let fixture = CveFixture::from_file(path)
        .map_err(|e| format!("Failed to parse fixture {}: {e}", path.display()))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime");

    let result = rt.block_on(fixture_runner::run_fixture(&fixture));

    let mut failures = Vec::new();
    for case_result in &result.case_results {
        if let Some(ref msg) = case_result.failure {
            failures.push(msg.clone());
        }
    }

    if !failures.is_empty() {
        let summary = format!(
            "Fixture '{}' ({}) — {}/{} cases passed\nFailures:\n  {}",
            fixture.id,
            fixture.language,
            result.passed(),
            result.case_results.len(),
            failures.join("\n  "),
        );
        return Err(summary.into());
    }

    Ok(())
}

datatest_stable::harness! {
    { test = test_cve_fixture, root = "tests/data/cve-fixtures", pattern = r".*\.yaml$" },
}
