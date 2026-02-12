//! SARIF snapshot tests using `insta`
//!
//! Runs the SAST scanner on known-vulnerable code samples and snapshots the
//! resulting SARIF export. This catches regressions in:
//! - Finding structure (rule_id, severity, location)
//! - SARIF schema compliance
//! - Tool metadata

use vulnera_core::config::SastConfig;
use vulnera_sast::application::use_cases::{AnalysisConfig, ScanProjectUseCase};
use vulnera_sast::infrastructure::rules::RuleRepository;

/// Helper: scan a single source string, return SARIF JSON with stable fields.
async fn scan_to_sarif(code: &str, filename: &str) -> serde_json::Value {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let file_path = temp_dir.path().join(filename);
    std::fs::write(&file_path, code).expect("write");

    let config = SastConfig::default();
    let analysis_config = AnalysisConfig::from(&config);
    let use_case = ScanProjectUseCase::with_config(&config, analysis_config);

    let result = use_case.execute(temp_dir.path()).await.expect("scan");

    // Get rules for SARIF export
    let repo = RuleRepository::new();
    let rules = repo.get_all_rules();

    let sarif_json = result
        .to_sarif_json(rules, Some("vulnera-sast"), Some("0.0.0-test"))
        .expect("SARIF export");

    // Parse to Value so we can redact non-deterministic fields
    let mut sarif: serde_json::Value = serde_json::from_str(&sarif_json).expect("parse JSON");

    // Redact dynamic fields for snapshot stability
    redact_dynamic_fields(&mut sarif);

    sarif
}

/// Redact fields that change between runs (file paths, timestamps, etc.)
fn redact_dynamic_fields(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            // Redact absolute file URIs
            if let Some(uri) = map.get_mut("uri") {
                if let Some(s) = uri.as_str() {
                    if s.contains('/') || s.contains('\\') {
                        // Keep only the filename
                        let filename = s.rsplit('/').next().unwrap_or(s);
                        *uri = serde_json::Value::String(format!("<REDACTED>/{filename}"));
                    }
                }
            }

            // Redact non-deterministic fingerprints
            if let Some(fingerprints) = map.get_mut("fingerprints") {
                if let Some(f_map) = fingerprints.as_object_mut() {
                    for v in f_map.values_mut() {
                        *v = serde_json::Value::String("<REDACTED>".to_string());
                    }
                }
            }

            // Recurse
            for v in map.values_mut() {
                redact_dynamic_fields(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                redact_dynamic_fields(v);
            }
        }
        _ => {}
    }
}

// ─── Snapshot tests ──────────────────────────────

#[tokio::test]
async fn sarif_snapshot_python_eval() {
    let code = r#"
import os

def vulnerable():
    user_input = input("cmd: ")
    eval(user_input)
    exec(user_input)
    os.system(user_input)
"#;

    let sarif = scan_to_sarif(code, "vuln.py").await;
    insta::assert_yaml_snapshot!("sarif_python_eval", sarif);
}

#[tokio::test]
async fn sarif_snapshot_javascript_xss() {
    let code = r#"
function showMessage(userInput) {
    document.innerHTML = userInput;
    document.write(userInput);
    eval(userInput);
}
"#;

    let sarif = scan_to_sarif(code, "vuln.js").await;
    insta::assert_yaml_snapshot!("sarif_javascript_xss", sarif);
}

#[tokio::test]
async fn sarif_snapshot_rust_unsafe() {
    let code = r#"
fn dangerous() {
    let x: i32 = unsafe { std::mem::zeroed() };
    let _ = some_option.unwrap();
    let _ = some_result.expect("boom");
}
"#;

    let sarif = scan_to_sarif(code, "vuln.rs").await;
    insta::assert_yaml_snapshot!("sarif_rust_unsafe", sarif);
}

#[tokio::test]
async fn sarif_snapshot_empty_scan() {
    let code = "# just a comment\n";

    let sarif = scan_to_sarif(code, "safe.py").await;
    insta::assert_yaml_snapshot!("sarif_empty_scan", sarif);
}

#[tokio::test]
async fn sarif_snapshot_go_command_injection() {
    let code = r#"
package main

import (
    "os/exec"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    cmd := r.URL.Query().Get("cmd")
    exec.Command("sh", "-c", cmd).Run()
}
"#;

    let sarif = scan_to_sarif(code, "vuln.go").await;
    insta::assert_yaml_snapshot!("sarif_go_command_injection", sarif);
}

#[tokio::test]
async fn sarif_schema_structure() {
    // Verify SARIF output has the required top-level structure
    let code = "eval('test');\n";
    let sarif = scan_to_sarif(code, "test.js").await;

    let obj = sarif.as_object().expect("SARIF should be an object");
    assert!(
        obj.contains_key("$schema") || obj.contains_key("schema"),
        "SARIF should contain schema reference"
    );
    assert!(obj.contains_key("version"), "SARIF should contain version");
    assert!(obj.contains_key("runs"), "SARIF should contain runs array");

    let runs = obj["runs"].as_array().expect("runs should be array");
    assert!(!runs.is_empty(), "SARIF should have at least one run");

    let run = &runs[0];
    assert!(
        run.get("tool").is_some(),
        "Run should contain tool information"
    );
    assert!(
        run.get("results").is_some(),
        "Run should contain results array"
    );
}
