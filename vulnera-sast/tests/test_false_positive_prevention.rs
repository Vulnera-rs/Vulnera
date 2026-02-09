//! Tests for false positive prevention in SAST scanning
//!
//! This module tests:
//! - unwrap()/expect() detection and proper line numbers
//! - Suppression comments (// vulnera-ignore-next-line)
//! - Rust allow attributes (#[allow(vulnera::rule_id)])
//! - Test code auto-suppression
//! - AST-aware matching vs regex matching

use std::collections::HashMap;
use tempfile::TempDir;
use uuid::Uuid;
use vulnera_core::config::SastConfig;
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig};
use vulnera_sast::SastModule;
use vulnera_sast::domain::FileSuppressions;

async fn create_source_file(dir: &TempDir, filename: &str, content: &str) -> std::path::PathBuf {
    let path = dir.path().join(filename);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    tokio::fs::write(&path, content)
        .await
        .expect("Failed to write source file");
    path
}

// ============================================================================
// Suppression Comment Tests
// ============================================================================

#[test]
fn test_parse_simple_ignore_next_line() {
    let content = r#"fn main() {
    // vulnera-ignore-next-line
    let x = dangerous().unwrap();
}
"#;
    let suppressions = FileSuppressions::parse(content);
    assert!(suppressions.is_suppressed(3, "null-pointer"));
    assert!(suppressions.is_suppressed(3, "any-rule")); // No specific rule = suppress all
    assert!(!suppressions.is_suppressed(2, "null-pointer")); // Wrong line
}

#[test]
fn test_parse_ignore_with_specific_rule() {
    let content = r#"fn main() {
    // vulnera-ignore-next-line: null-pointer
    let x = result.unwrap();
    let y = other.expect("msg"); // Not suppressed
}
"#;
    let suppressions = FileSuppressions::parse(content);
    assert!(suppressions.is_suppressed(3, "null-pointer"));
    assert!(!suppressions.is_suppressed(3, "expect-panic")); // Different rule
    assert!(!suppressions.is_suppressed(4, "expect-panic")); // No suppression on line 4
}

#[test]
fn test_parse_ignore_with_multiple_rules() {
    let content = r#"fn main() {
    // vulnera-ignore-next-line: null-pointer, expect-panic
    let x = result.unwrap().then(|v| v.expect("msg"));
}
"#;
    let suppressions = FileSuppressions::parse(content);
    assert!(suppressions.is_suppressed(3, "null-pointer"));
    assert!(suppressions.is_suppressed(3, "expect-panic"));
    assert!(!suppressions.is_suppressed(3, "other-rule"));
}

#[test]
fn test_parse_ignore_with_reason() {
    let content = r#"fn main() {
    // vulnera-ignore-next-line: null-pointer -- This is safe because we validate above
    let x = validated.unwrap();
}
"#;
    let suppressions = FileSuppressions::parse(content);
    assert!(suppressions.is_suppressed(3, "null-pointer"));
    let supp = suppressions.get_suppressions_for_line(3);
    assert_eq!(supp.len(), 1);
    assert_eq!(
        supp[0].reason.as_deref(),
        Some("This is safe because we validate above")
    );
}

#[test]
fn test_parse_python_style_comment() {
    let content = r#"def main():
    # vulnera-ignore-next-line
    subprocess.call(user_input, shell=True)
"#;
    let suppressions = FileSuppressions::parse(content);
    assert!(suppressions.is_suppressed(3, "python-subprocess"));
}

#[test]
fn test_parse_block_comment() {
    let content = r#"function main() {
    /* vulnera-ignore-next-line */
    eval(userInput);
}
"#;
    let suppressions = FileSuppressions::parse(content);
    assert!(suppressions.is_suppressed(3, "js-eval"));
}

#[test]
fn test_parse_rust_allow_attribute() {
    let content = r#"fn main() {
    #[allow(vulnera::null_pointer)]
    let x = result.unwrap();
}
"#;
    let suppressions = FileSuppressions::parse(content);
    // Attribute converts underscores to hyphens
    assert!(suppressions.is_suppressed(3, "null-pointer"));
}

#[test]
fn test_parse_rust_allow_multiple_rules() {
    let content = r#"fn main() {
    #[allow(vulnera::null_pointer, vulnera::expect_panic)]
    let x = result.unwrap().map(|v| v.expect("msg"));
}
"#;
    let suppressions = FileSuppressions::parse(content);
    assert!(suppressions.is_suppressed(3, "null-pointer"));
    assert!(suppressions.is_suppressed(3, "expect-panic"));
}

#[test]
fn test_no_suppression_without_directive() {
    let content = r#"fn main() {
    // This is just a regular comment
    let x = result.unwrap();
}
"#;
    let suppressions = FileSuppressions::parse(content);
    assert!(!suppressions.is_suppressed(3, "null-pointer"));
}

// ============================================================================
// Test Code Detection Tests
// ============================================================================

#[tokio::test]
async fn test_suppress_in_tests_directory() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Create a file in tests/ directory with unwrap
    let test_code = r#"fn test_something() {
    let result = some_function();
    let value = result.unwrap(); // Should be suppressed
}
"#;
    create_source_file(&temp_dir, "tests/my_test.rs", test_code).await;

    let config = SastConfig::default();
    let module = SastModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: temp_dir.path().to_string_lossy().to_string(),
        config: HashMap::new(),
    };

    let result = module
        .execute(&module_config)
        .await
        .expect("Module execution failed");

    // Findings in tests/ should be suppressed for rules with suppress_in_tests=true
    let unwrap_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id.as_deref() == Some("null-pointer"))
        .collect();

    assert!(
        unwrap_findings.is_empty(),
        "unwrap findings should be suppressed in tests/ directory"
    );
}

#[tokio::test]
async fn test_suppress_with_cfg_test_attribute() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Create a file with #[cfg(test)] module
    let code = r#"fn production_code() {
    // This should produce a finding
}

#[cfg(test)]
mod tests {
    fn test_something() {
        let value = result.unwrap(); // This is in test context
    }
}
"#;
    create_source_file(&temp_dir, "src/lib.rs", code).await;

    let config = SastConfig::default();
    let module = SastModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: temp_dir.path().to_string_lossy().to_string(),
        config: HashMap::new(),
    };

    let result = module
        .execute(&module_config)
        .await
        .expect("Module execution failed");

    // File contains #[cfg(test)], so entire file is considered test context
    // This is a simplification - ideally we'd only suppress within the test module
    let unwrap_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id.as_deref() == Some("null-pointer"))
        .collect();

    // The current implementation treats whole file as test context if it contains #[cfg(test)]
    // This is acceptable behavior for reducing false positives
    assert!(
        unwrap_findings.is_empty(),
        "unwrap findings should be suppressed in files with #[cfg(test)]"
    );
}

// ============================================================================
// Integration: Suppression Directive in Scanned File
// ============================================================================

#[tokio::test]
async fn test_suppression_directive_prevents_finding() {
    let temp_dir = tempfile::tempdir().unwrap();

    let code = r#"fn main() {
    // vulnera-ignore-next-line
    let suppressed = result.unwrap();
    let not_suppressed = other.unwrap();
}
"#;
    create_source_file(&temp_dir, "main.rs", code).await;

    let config = SastConfig::default();
    let module = SastModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: temp_dir.path().to_string_lossy().to_string(),
        config: HashMap::new(),
    };

    let result = module
        .execute(&module_config)
        .await
        .expect("Module execution failed");

    let unwrap_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id.as_deref() == Some("null-pointer"))
        .collect();

    // Should have exactly 1 finding (line 4), not 2
    assert_eq!(
        unwrap_findings.len(),
        1,
        "Expected 1 unwrap finding (suppressed line should be excluded)"
    );

    // The finding should be on line 4
    assert_eq!(
        unwrap_findings[0].location.line,
        Some(4),
        "Finding should be on line 4 (the non-suppressed unwrap)"
    );
}

// ============================================================================
// Line Number Accuracy Tests
// ============================================================================

#[tokio::test]
async fn test_rust_unwrap_reports_correct_line() {
    let temp_dir = tempfile::tempdir().unwrap();

    let code = r#"// Line 1: Comment
// Line 2: Comment
fn main() { // Line 3
    let x = 1; // Line 4
    let result = something(); // Line 5
    let value = result.unwrap(); // Line 6 - the unwrap
    println!("{}", value); // Line 7
}
"#;
    create_source_file(&temp_dir, "main.rs", code).await;

    let config = SastConfig::default();
    let module = SastModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: temp_dir.path().to_string_lossy().to_string(),
        config: HashMap::new(),
    };

    let result = module
        .execute(&module_config)
        .await
        .expect("Module execution failed");

    let unwrap_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id.as_deref() == Some("null-pointer"))
        .collect();

    assert_eq!(
        unwrap_findings.len(),
        1,
        "Expected exactly 1 unwrap finding"
    );
    assert_eq!(
        unwrap_findings[0].location.line,
        Some(6),
        "unwrap finding should be on line 6, not line 1"
    );
}

#[tokio::test]
async fn test_expect_rule_detects_expect_calls() {
    let temp_dir = tempfile::tempdir().unwrap();

    let code = r#"fn main() {
    let result = something();
    let value = result.expect("should not fail"); // Line 3
}
"#;
    create_source_file(&temp_dir, "main.rs", code).await;

    let config = SastConfig::default();
    let module = SastModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: temp_dir.path().to_string_lossy().to_string(),
        config: HashMap::new(),
    };

    let result = module
        .execute(&module_config)
        .await
        .expect("Module execution failed");

    let expect_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id.as_deref() == Some("expect-panic"))
        .collect();

    assert_eq!(
        expect_findings.len(),
        1,
        "Expected exactly 1 expect finding"
    );
    assert_eq!(
        expect_findings[0].location.line,
        Some(3),
        "expect finding should be on line 3"
    );
}

// ============================================================================
// False Positive Prevention Tests
// ============================================================================

#[tokio::test]
async fn test_no_false_positive_on_variable_named_unwrap() {
    let temp_dir = tempfile::tempdir().unwrap();

    // This code has a variable named "unwrap" but doesn't call .unwrap()
    let code = r#"fn main() {
    let unwrap = "some string"; // Should NOT trigger rust-unwrap
    let unwrap_result = process(unwrap); // Should NOT trigger
    println!("{}", unwrap);
}
"#;
    create_source_file(&temp_dir, "main.rs", code).await;

    let config = SastConfig::default();
    let module = SastModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: temp_dir.path().to_string_lossy().to_string(),
        config: HashMap::new(),
    };

    let result = module
        .execute(&module_config)
        .await
        .expect("Module execution failed");

    let unwrap_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id.as_deref() == Some("null-pointer"))
        .collect();

    // With AST-aware matching (MethodCall pattern), variables named "unwrap"
    // should NOT trigger false positives
    assert!(
        unwrap_findings.is_empty(),
        "Variables named 'unwrap' should not trigger false positives"
    );
}

#[tokio::test]
async fn test_no_false_positive_on_comment_containing_unwrap() {
    let temp_dir = tempfile::tempdir().unwrap();

    let code = r#"fn main() {
    // Don't use unwrap() in production code
    let x = 1; // This unwrap mention is in a comment
    /* 
     * Also avoid expect() and unwrap()
     */
    let y = 2;
}
"#;
    create_source_file(&temp_dir, "main.rs", code).await;

    let config = SastConfig::default();
    let module = SastModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: temp_dir.path().to_string_lossy().to_string(),
        config: HashMap::new(),
    };

    let result = module
        .execute(&module_config)
        .await
        .expect("Module execution failed");

    let unwrap_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id.as_deref() == Some("null-pointer"))
        .collect();

    assert!(
        unwrap_findings.is_empty(),
        "Comments mentioning 'unwrap' should not trigger false positives"
    );
}

#[tokio::test]
async fn test_no_false_positive_on_string_containing_unwrap() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Test that strings containing "unwrap" don't trigger false positives
    // Using different delimiter to avoid nesting issues
    let code = r##"fn main() {
    let msg = "Please don't call .unwrap()";
    let doc = r#"
        Avoid using unwrap() in production.
    "#;
}
"##;
    create_source_file(&temp_dir, "main.rs", code).await;

    let config = SastConfig::default();
    let module = SastModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: temp_dir.path().to_string_lossy().to_string(),
        config: HashMap::new(),
    };

    let result = module
        .execute(&module_config)
        .await
        .expect("Module execution failed");

    let unwrap_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id.as_deref() == Some("null-pointer"))
        .collect();

    assert!(
        unwrap_findings.is_empty(),
        "Strings containing unwrap text should not trigger false positives"
    );
}

// ============================================================================
// Edge Cases
// ============================================================================

#[tokio::test]
async fn test_multiple_unwraps_same_line() {
    let temp_dir = tempfile::tempdir().unwrap();

    let code = r#"fn main() {
    let value = result.unwrap().inner.unwrap(); // Two unwraps on one line
}
"#;
    create_source_file(&temp_dir, "main.rs", code).await;

    let config = SastConfig::default();
    let module = SastModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: temp_dir.path().to_string_lossy().to_string(),
        config: HashMap::new(),
    };

    let result = module
        .execute(&module_config)
        .await
        .expect("Module execution failed");

    let unwrap_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id.as_deref() == Some("null-pointer"))
        .collect();

    // AST-based detection may find 1 or 2 depending on tree structure
    // The important thing is we detect the pattern
    assert!(
        !unwrap_findings.is_empty(),
        "Should detect unwrap calls on the line"
    );
}

#[tokio::test]
async fn test_suppress_only_specific_rule_on_line() {
    let temp_dir = tempfile::tempdir().unwrap();

    let code = r#"fn main() {
    // vulnera-ignore-next-line: null-pointer
    let value = result.unwrap().expect("msg"); // unwrap suppressed, expect not
}
"#;
    create_source_file(&temp_dir, "main.rs", code).await;

    let config = SastConfig::default();
    let module = SastModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: temp_dir.path().to_string_lossy().to_string(),
        config: HashMap::new(),
    };

    let result = module
        .execute(&module_config)
        .await
        .expect("Module execution failed");

    let unwrap_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id.as_deref() == Some("null-pointer"))
        .collect();

    let expect_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id.as_deref() == Some("expect-panic"))
        .collect();

    assert!(unwrap_findings.is_empty(), "unwrap should be suppressed");
    assert_eq!(expect_findings.len(), 1, "expect should NOT be suppressed");
}
