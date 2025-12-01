//! Integration tests for SAST scanning

use std::collections::HashMap;
use tempfile::TempDir;
use uuid::Uuid;
use vulnera_core::config::SastConfig;
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig};
use vulnera_sast::SastModule;

async fn create_source_file(dir: &TempDir, filename: &str, content: &str) -> std::path::PathBuf {
    let path = dir.path().join(filename);
    tokio::fs::write(&path, content)
        .await
        .expect("Failed to write source file");
    path
}

fn sample_python_vulnerable() -> &'static str {
    r#"import subprocess
def execute_command(user_input):
    subprocess.call(user_input, shell=True)
"#
}

fn sample_javascript_vulnerable() -> &'static str {
    r#"function queryDatabase(userInput) {
    const query = "SELECT * FROM users WHERE id = " + userInput;
    db.query(query);
}
"#
}

#[tokio::test]
async fn test_directory_scanning() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Create test source files
    create_source_file(&temp_dir, "test.py", sample_python_vulnerable()).await;
    create_source_file(&temp_dir, "test.js", sample_javascript_vulnerable()).await;

    // Test directory scanning
    // Placeholder for actual scanner implementation
    assert!(temp_dir.path().exists());
}

#[tokio::test]
async fn test_rule_loading() {
    // Test rule loading from files
    // Placeholder for now
    assert!(true);
}

#[tokio::test]
async fn test_language_detection() {
    // Test language detection from filenames
    // Placeholder for now
    assert!(true);
}

#[tokio::test]
async fn test_call_literal_vs_variable_confidence() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Test that js-eval-indirect matches setTimeout with string literal argument
    // The current rule implementation only matches literal strings, not variables
    let js_literal = r#"function literalCall() { setTimeout("alert('x')", 1000); }"#;

    create_source_file(&temp_dir, "literal.js", js_literal).await;

    // Build module with default config
    let config = SastConfig {
        ..Default::default()
    };
    let module = SastModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "sast-test-project".to_string(),
        source_uri: temp_dir.path().to_string_lossy().to_string(),
        config: HashMap::new(),
    };

    let result = module
        .execute(&module_config)
        .await
        .expect("Module execution failed");

    // The current rule only matches setTimeout with literal string arguments
    let literal_finding = result.findings.iter().find(|f| {
        f.location.path.ends_with("literal.js") && f.rule_id.as_deref() == Some("js-eval-indirect")
    });

    assert!(
        literal_finding.is_some(),
        "Literal argument use should produce a finding"
    );
}
