//! Integration tests for SAST scanning

use std::collections::HashMap;
use tempfile::TempDir;
use uuid::Uuid;
use vulnera_core::config::SastConfig;
use vulnera_core::domain::module::{AnalysisModule, FindingConfidence, ModuleConfig};
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

    // Create two JS files - one with a literal argument in setTimeout; one with variable argument
    let js_literal = r#"function literalCall() { setTimeout("alert('x')", 1000); }"#;
    let js_variable = r#"function variableCall(userInput) { setTimeout(userInput, 1000); }"#;

    create_source_file(&temp_dir, "literal.js", js_literal).await;
    create_source_file(&temp_dir, "variable.js", js_variable).await;

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

    // Expect both files to produce findings (matching setTimeout)
    let literal_finding = result.findings.iter().find(|f| {
        f.location.path.ends_with("literal.js") && f.rule_id.as_deref() == Some("js-eval-indirect")
    });
    let variable_finding = result.findings.iter().find(|f| {
        f.location.path.ends_with("variable.js") && f.rule_id.as_deref() == Some("js-eval-indirect")
    });

    assert!(
        variable_finding.is_some(),
        "Variable argument use should produce a finding"
    );
    assert!(
        literal_finding.is_some(),
        "Literal argument use should produce a finding"
    );

    let var_conf = variable_finding.unwrap().confidence.clone();
    let lit_conf = literal_finding.unwrap().confidence.clone();
    assert_eq!(
        var_conf,
        FindingConfidence::High,
        "variable call should have High confidence"
    );
    assert_eq!(
        lit_conf,
        FindingConfidence::Low,
        "literal call should have Low confidence"
    );
}
