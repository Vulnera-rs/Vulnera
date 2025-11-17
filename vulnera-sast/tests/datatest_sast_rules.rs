//! Data-driven tests for SAST rules
// cspell:ignore datatest
use std::fs;
use std::path::Path;

fn test_sast_rule_with_file(path: &Path) -> datatest_stable::Result<()> {
    let content = fs::read_to_string(path)?;

    // Test that rule file can be parsed
    // Placeholder for actual rule parsing
    assert!(!content.is_empty());

    Ok(())
}

datatest_stable::harness! {
    { test = test_sast_rule_with_file, root = "tests/data/sast", pattern = r".*\.(py|js|rs)$" },
}
