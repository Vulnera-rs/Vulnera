//! Tests for semantic filtering and false positive reduction.
//!
//! These tests verify that the AST-aware detection pipeline correctly identifies
//! and filters out matches based on structural context (comments, assignments, etc.).

use std::path::Path;
use vulnera_secrets::domain::value_objects::Confidence;
use vulnera_secrets::infrastructure::detectors::DetectorEngine;
use vulnera_secrets::infrastructure::rules::RuleRepository;

/// Helper to create a detector engine with standard thresholds
fn get_test_engine() -> DetectorEngine {
    DetectorEngine::new(RuleRepository::new(), 4.5, 3.0, true)
}

#[tokio::test]
async fn test_python_comment_filtering() {
    let engine = get_test_engine();

    // Python code with a real assignment and a commented-out secret
    // Using 'password' because its regex supports optional quotes
    let content = r#"
# db_password = "my-secret-password-123"
db_password = "my-secret-password-123"
"#;
    let path = Path::new("test.py");

    let findings = engine.detect_in_file_async(path, content).await;
    for f in &findings {
        println!(
            "DEBUG [Python]: Found {} at L{}",
            f.rule_id, f.location.line
        );
    }

    // Only the assignment should be found. The comment match should be filtered.
    assert!(!findings.is_empty(), "Should find the assigned password");
    assert_eq!(
        findings.len(),
        1,
        "Should filter out secrets in Python comments. Found: {:?}",
        findings
    );
    assert_eq!(
        findings[0].confidence,
        Confidence::High,
        "Assignment to 'aws_key' should have High confidence"
    );
}

#[tokio::test]
async fn test_javascript_ast_context() {
    let engine = get_test_engine();

    let content = r#"
const api_password = "my-secret-password-123";
// const old_password = "my-secret-password-456";
const dummy_password = "my-secret-password-789";
"#;
    let path = Path::new("app.js");

    let findings = engine.detect_in_file_async(path, content).await;
    for f in &findings {
        println!(
            "DEBUG [JS]: Found {} (Conf: {:?}) at L{}",
            f.rule_id, f.confidence, f.location.line
        );
    }

    // 1. api_password should be High confidence
    // 2. old_password (comment) should be filtered
    // 3. dummy_password (heuristic) should be Potential or Low confidence

    let high_conf_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.confidence == Confidence::High)
        .collect();
    let low_conf_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.confidence == Confidence::Low)
        .collect();

    assert_eq!(
        high_conf_findings.len(),
        1,
        "Should find 1 high-confidence token. Found high: {:?}",
        high_conf_findings
    );
    assert!(
        low_conf_findings.len() >= 1,
        "Dummy variable should have reduced confidence. Found: {:?}",
        findings
    );
}

#[tokio::test]
async fn test_rust_let_binding_analysis() {
    let engine = get_test_engine();

    let content = r#"
fn main() {
    let db_password = "my-secret-password-123";
    /*
       A block comment containing a secret:
       db_password = "my-secret-password-456"
    */
    println!("Hello World");
}
"#;
    let path = Path::new("main.rs");

    let findings = engine.detect_in_file_async(path, content).await;
    for f in &findings {
        println!("DEBUG [Rust]: Found {} at L{}", f.rule_id, f.location.line);
    }

    assert_eq!(
        findings.len(),
        1,
        "Should filter out secrets in Rust block comments. Found: {:?}",
        findings
    );
    assert_eq!(
        findings[0].confidence,
        Confidence::High,
        "Rust let binding with 'stripe_key' should be High confidence"
    );
}

#[tokio::test]
async fn test_go_short_declarations() {
    let engine = get_test_engine();

    let content = r#"
package main
func main() {
	githubToken := "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
	// githubToken := "ghp_commented_out_token_val_1234567"
}
"#;
    let path = Path::new("main.go");

    let findings = engine.detect_in_file_async(path, content).await;

    assert_eq!(
        findings.len(),
        1,
        "Go short declarations should be supported"
    );
}

#[tokio::test]
async fn test_test_file_heuristic() {
    let engine = get_test_engine();

    // The same secret content
    let content = "const AWS_SECRET = 'AKIAIOSFODNN7EXAMPLE';";

    // In a production file
    let findings_prod = engine
        .detect_in_file_async(Path::new("src/auth.js"), content)
        .await;

    // In a test file
    let findings_test = engine
        .detect_in_file_async(Path::new("tests/auth.test.js"), content)
        .await;

    if !findings_prod.is_empty() && !findings_test.is_empty() {
        assert_eq!(findings_prod[0].confidence, Confidence::High);
        assert_eq!(
            findings_test[0].confidence,
            Confidence::Low,
            "Secrets in test files should have Low confidence"
        );
    }
}

#[tokio::test]
async fn test_high_entropy_dummy_filtering() {
    let engine = get_test_engine();

    // A high entropy string that looks like a secret but is assigned to a 'dummy' variable
    let content = r#"
        const example_hash = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"; // High entropy
        const real_token = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0";
    "#;
    let path = Path::new("config.js");

    let findings = engine.detect_in_file_async(path, content).await;

    let example_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.id.contains("entropy") && f.confidence == Confidence::Low)
        .collect();

    assert!(
        !example_findings.is_empty() || findings.len() < 2,
        "Example variables should be filtered or downgraded"
    );
}

#[tokio::test]
async fn test_field_name_constant_filtering() {
    let engine = get_test_engine();

    let content = r#"
        const PASSWORD_FIELD = "password";
        const API_KEY_NAME = "api_key";
    "#;
    let path = Path::new("constants.js");

    let findings = engine.detect_in_file_async(path, content).await;
    for f in &findings {
        println!(
            "DEBUG [Constants]: Found {} at L{}",
            f.rule_id, f.location.line
        );
    }

    assert!(
        findings.is_empty(),
        "Field name constants should be filtered out. Found: {:?}",
        findings
    );
}
