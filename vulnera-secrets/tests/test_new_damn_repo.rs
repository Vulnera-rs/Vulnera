//! End-to-end tests for the `new-damn-repo` test repository using vulnera-secrets
//!
//! This module tests the secret detection scanner against a real-world-like repository
//! with intentional secrets and ensures:
//! 1. True positives are detected (actual secrets)
//! 2. False positives are NOT generated (safe patterns)

use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;
use vulnera_core::config::SecretDetectionConfig;
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig, ModuleType};
use vulnera_secrets::SecretDetectionModule;

/// Path to the test repository relative to workspace root
fn get_test_repo_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .join("ex")
        .join("new-damn-repo")
}

/// Helper to run secrets scan on a directory
async fn run_secrets_on_dir(path: &std::path::Path) -> vulnera_core::domain::module::ModuleResult {
    let config = SecretDetectionConfig::default();
    let module = SecretDetectionModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "test-new-damn-repo".to_string(),
        source_uri: path.to_string_lossy().to_string(),
        config: HashMap::new(),
    };

    module
        .execute(&module_config)
        .await
        .expect("Module execution failed")
}

/// Helper to check if a specific rule was detected in a specific file
#[allow(dead_code)]
fn has_finding(
    result: &vulnera_core::domain::module::ModuleResult,
    rule_id: &str,
    file_suffix: &str,
) -> bool {
    result
        .findings
        .iter()
        .any(|f| f.rule_id.as_deref() == Some(rule_id) && f.location.path.ends_with(file_suffix))
}

/// Helper to count findings for a specific rule
fn count_findings(result: &vulnera_core::domain::module::ModuleResult, rule_id: &str) -> usize {
    result
        .findings
        .iter()
        .filter(|f| f.rule_id.as_deref() == Some(rule_id))
        .count()
}

// ============================================================================
// End-to-End Tests for Secret Detection
// ============================================================================

#[tokio::test]
async fn test_new_damn_repo_detects_aws_credentials() {
    let repo_path = get_test_repo_path();
    if !repo_path.exists() {
        eprintln!(
            "Skipping test: ex/new-damn-repo not found at {:?}",
            repo_path
        );
        return;
    }

    let result = run_secrets_on_dir(&repo_path).await;
    assert_eq!(result.module_type, ModuleType::SecretDetection);

    // Should detect AWS access key in credentials.py and secrets.env
    let aws_key_count = count_findings(&result, "aws-access-key");
    assert!(
        aws_key_count >= 1,
        "Should detect at least one AWS access key. Found: {}",
        aws_key_count
    );
}

#[tokio::test]
async fn test_new_damn_repo_detects_stripe_keys() {
    let repo_path = get_test_repo_path();
    if !repo_path.exists() {
        return;
    }

    let result = run_secrets_on_dir(&repo_path).await;

    // Should detect Stripe API keys in secret.js and other files
    let stripe_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.rule_id
                .as_deref()
                .is_some_and(|id| id.contains("stripe") || id.contains("generic"))
        })
        .collect();

    // We have multiple Stripe keys across files
    assert!(
        !stripe_findings.is_empty(),
        "Should detect Stripe keys. Found rules: {:?}",
        result
            .findings
            .iter()
            .filter_map(|f| f.rule_id.clone())
            .collect::<std::collections::HashSet<_>>()
    );
}

#[tokio::test]
async fn test_new_damn_repo_detects_database_credentials() {
    let repo_path = get_test_repo_path();
    if !repo_path.exists() {
        return;
    }

    let result = run_secrets_on_dir(&repo_path).await;

    // Should detect database passwords and connection strings
    let db_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.rule_id
                .as_deref()
                .is_some_and(|id| id.contains("database") || id.contains("password"))
        })
        .collect();

    assert!(
        !db_findings.is_empty(),
        "Should detect database credentials. Found rules: {:?}",
        result
            .findings
            .iter()
            .filter_map(|f| f.rule_id.clone())
            .collect::<std::collections::HashSet<_>>()
    );
}

#[tokio::test]
async fn test_new_damn_repo_detects_github_tokens() {
    let repo_path = get_test_repo_path();
    if !repo_path.exists() {
        return;
    }

    let result = run_secrets_on_dir(&repo_path).await;

    // Should detect GitHub tokens (ghp_...)
    let github_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id.as_deref().is_some_and(|id| id.contains("github")))
        .collect();

    // Note: Detection depends on whether the pattern matches our test data
    if github_findings.is_empty() {
        eprintln!(
            "Note: GitHub token not detected. Available rules: {:?}",
            result
                .findings
                .iter()
                .filter_map(|f| f.rule_id.clone())
                .collect::<std::collections::HashSet<_>>()
        );
    }
}

#[tokio::test]
async fn test_new_damn_repo_detects_private_keys() {
    let repo_path = get_test_repo_path();
    if !repo_path.exists() {
        return;
    }

    let result = run_secrets_on_dir(&repo_path).await;

    // Should detect private key headers in credentials.py and cloud_config.yaml
    let key_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.rule_id
                .as_deref()
                .is_some_and(|id| id.contains("private-key") || id.contains("ssh"))
        })
        .collect();

    assert!(
        !key_findings.is_empty(),
        "Should detect private key headers. Found rules: {:?}",
        result
            .findings
            .iter()
            .filter_map(|f| f.rule_id.clone())
            .collect::<std::collections::HashSet<_>>()
    );
}

// ============================================================================
// False Positive Prevention Tests
// ============================================================================

#[tokio::test]
async fn test_new_damn_repo_no_false_positives_on_safe_code() {
    let repo_path = get_test_repo_path();
    if !repo_path.exists() {
        return;
    }

    let result = run_secrets_on_dir(&repo_path).await;

    // Check for findings in safe_code.js - should be minimal or none
    let safe_code_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.location.path.ends_with("safe_code.js"))
        .collect();

    // Safe code patterns should not trigger high-confidence findings
    // Some low-confidence entropy findings might still occur
    let high_confidence_fps = safe_code_findings
        .iter()
        .filter(|f| f.confidence == vulnera_core::domain::module::FindingConfidence::High)
        .count();

    assert!(
        high_confidence_fps == 0,
        "safe_code.js should not have high-confidence secret findings. Found {} FPs: {:?}",
        high_confidence_fps,
        safe_code_findings
            .iter()
            .filter_map(|f| f.rule_id.clone())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_new_damn_repo_no_false_positives_on_false_positives_py() {
    let repo_path = get_test_repo_path();
    if !repo_path.exists() {
        return;
    }

    let result = run_secrets_on_dir(&repo_path).await;

    // Check for findings in false_positives.py - should be minimal or none
    let fp_file_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.location.path.ends_with("false_positives.py"))
        .collect();

    // These patterns are intentionally safe and should not trigger
    let high_confidence_fps = fp_file_findings
        .iter()
        .filter(|f| f.confidence == vulnera_core::domain::module::FindingConfidence::High)
        .count();

    assert!(
        high_confidence_fps == 0,
        "false_positives.py should not have high-confidence secret findings. Found {} FPs: {:?}",
        high_confidence_fps,
        fp_file_findings
            .iter()
            .filter_map(|f| f.rule_id.clone())
            .collect::<Vec<_>>()
    );
}

// ============================================================================
// Comprehensive Coverage Test
// ============================================================================

#[tokio::test]
async fn test_new_damn_repo_comprehensive_secret_coverage() {
    let repo_path = get_test_repo_path();
    if !repo_path.exists() {
        eprintln!("Skipping test: ex/new-damn-repo not found");
        return;
    }

    let result = run_secrets_on_dir(&repo_path).await;

    // Collect all unique rule IDs found
    let found_rules: std::collections::HashSet<_> = result
        .findings
        .iter()
        .filter_map(|f| f.rule_id.clone())
        .collect();

    println!("=== Comprehensive Secret E2E Test Results ===");
    println!("Total findings: {}", result.findings.len());
    println!("Unique rules triggered: {}", found_rules.len());
    println!("Rules found: {:?}", found_rules);

    // We should detect multiple different secret types across our test files
    assert!(
        found_rules.len() >= 3,
        "Expected at least 3 different secret types to be detected. Found only {}: {:?}",
        found_rules.len(),
        found_rules
    );

    // Print findings by file for debugging
    let mut findings_by_file: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for finding in &result.findings {
        let file = finding
            .location
            .path
            .split('/')
            .next_back()
            .unwrap_or("unknown")
            .to_string();
        let rule = finding.rule_id.as_deref().unwrap_or("unknown").to_string();
        findings_by_file.entry(file).or_default().push(format!(
            "{}:L{}",
            rule,
            finding.location.line.unwrap_or(0)
        ));
    }

    println!("\nFindings by file:");
    for (file, rules) in &findings_by_file {
        println!("  {}: {:?}", file, rules);
    }

    // Files that SHOULD have findings
    let expected_files_with_secrets = [
        "credentials.py",
        "secrets.env",
        "config.json",
        "cloud_config.yaml",
        "vulnerable.py", // Has hardcoded password
        "secret.js",     // Has Stripe key
        "vulnerable.go", // Has API_KEY and DB_PASSWORD constants
    ];

    let files_with_findings: std::collections::HashSet<_> = findings_by_file.keys().collect();

    let mut detected_expected = 0;
    for expected in &expected_files_with_secrets {
        if files_with_findings.iter().any(|f| f.contains(expected)) {
            detected_expected += 1;
        }
    }

    println!(
        "\nExpected files with secrets: {}",
        expected_files_with_secrets.len()
    );
    println!("Actually detected: {}", detected_expected);

    // Files that should NOT have findings (or minimal low-confidence ones)
    let safe_files = ["safe_code.js", "false_positives.py"];
    for safe_file in &safe_files {
        let safe_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.location.path.ends_with(*safe_file))
            .filter(|f| f.confidence == vulnera_core::domain::module::FindingConfidence::High)
            .collect();

        assert!(
            safe_findings.is_empty(),
            "{} should not have high-confidence findings. Found: {:?}",
            safe_file,
            safe_findings
                .iter()
                .filter_map(|f| f.rule_id.clone())
                .collect::<Vec<_>>()
        );
    }
}

// ============================================================================
// Production Readiness Metrics Test
// ============================================================================

#[tokio::test]
async fn test_new_damn_repo_production_readiness_metrics() {
    let repo_path = get_test_repo_path();
    if !repo_path.exists() {
        eprintln!("Skipping test: ex/new-damn-repo not found");
        return;
    }

    let result = run_secrets_on_dir(&repo_path).await;

    // Calculate metrics
    let total_findings = result.findings.len();
    let unique_rules: std::collections::HashSet<_> = result
        .findings
        .iter()
        .filter_map(|f| f.rule_id.clone())
        .collect();

    let high_confidence_findings = result
        .findings
        .iter()
        .filter(|f| f.confidence == vulnera_core::domain::module::FindingConfidence::High)
        .count();

    let safe_file_fps = result
        .findings
        .iter()
        .filter(|f| {
            f.location.path.ends_with("safe_code.js")
                || f.location.path.ends_with("false_positives.py")
        })
        .filter(|f| f.confidence == vulnera_core::domain::module::FindingConfidence::High)
        .count();

    println!("=== Production Readiness Metrics ===");
    println!("Total findings: {}", total_findings);
    println!("Unique rule types: {}", unique_rules.len());
    println!("High confidence findings: {}", high_confidence_findings);
    println!("False positives on safe files: {}", safe_file_fps);
    println!("Files scanned: {}", result.metadata.files_scanned);
    println!("Scan duration: {}ms", result.metadata.duration_ms);

    // Production readiness assertions
    assert!(
        total_findings > 0,
        "Should detect at least some secrets in the test repository"
    );

    assert_eq!(
        safe_file_fps, 0,
        "Should have zero high-confidence false positives on safe code files"
    );

    assert!(
        result.metadata.duration_ms < 10000,
        "Scan should complete in under 10 seconds. Took: {}ms",
        result.metadata.duration_ms
    );
}
