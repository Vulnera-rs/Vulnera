//! Data-driven tests for secret patterns
// cspell:ignore datatest
use std::fs;
use std::path::Path;

fn test_secret_pattern_with_file(path: &Path) -> datatest_stable::Result<()> {
    let content = fs::read_to_string(path)?;

    // Test that secret patterns can be detected
    // Placeholder for actual pattern detection
    assert!(!content.is_empty());

    Ok(())
}

datatest_stable::harness! {
    { test = test_secret_pattern_with_file, root = "tests/data/secrets", pattern = r".*\.(env|txt|key|pem)$" },
}
