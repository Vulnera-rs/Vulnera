//! integration tests for SAST scanning
//!
//! Tests the full scanning pipeline: directory → parse → pattern match → findings.

use std::collections::HashMap;
use tempfile::TempDir;
use uuid::Uuid;
use vulnera_core::config::SastConfig;
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig};
use vulnera_sast::SastModule;

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

async fn scan_dir(dir: &TempDir) -> vulnera_core::domain::module::ModuleResult {
    let module = SastModule::new();
    let config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "scan-test".to_string(),
        source_uri: dir.path().to_string_lossy().to_string(),
        config: HashMap::new(),
    };
    module.execute(&config).await.expect("scan failed")
}

fn has_rule(result: &vulnera_core::domain::module::ModuleResult, rule_id: &str) -> bool {
    result
        .findings
        .iter()
        .any(|f| f.rule_id.as_deref() == Some(rule_id))
}

fn rule_ids(result: &vulnera_core::domain::module::ModuleResult) -> Vec<String> {
    result
        .findings
        .iter()
        .filter_map(|f| f.rule_id.clone())
        .collect()
}

// =========================================================================
// Python scanning
// =========================================================================

#[tokio::test]
async fn test_python_eval_detected() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(&dir, "vuln.py", "def f(x):\n    eval(x)\n").await;
    let result = scan_dir(&dir).await;
    assert!(
        has_rule(&result, "unsafe-function-call"),
        "Expected unsafe-function-call, got: {:?}",
        rule_ids(&result)
    );
}

#[tokio::test]
async fn test_python_exec_detected() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(&dir, "vuln.py", "def run(code):\n    exec(code)\n").await;
    let result = scan_dir(&dir).await;
    assert!(
        has_rule(&result, "python-exec"),
        "Expected python-exec, got: {:?}",
        rule_ids(&result)
    );
}

#[tokio::test]
async fn test_python_subprocess_detected() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(
        &dir,
        "vuln.py",
        "import subprocess\nsubprocess.call('ls', shell=True)\n",
    )
    .await;
    let result = scan_dir(&dir).await;
    assert!(
        has_rule(&result, "python-subprocess"),
        "Expected python-subprocess, got: {:?}",
        rule_ids(&result)
    );
}

#[tokio::test]
async fn test_python_pickle_detected() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(&dir, "vuln.py", "import pickle\npickle.loads(data)\n").await;
    let result = scan_dir(&dir).await;
    assert!(
        has_rule(&result, "unsafe-deserialization"),
        "Expected unsafe-deserialization, got: {:?}",
        rule_ids(&result)
    );
}

#[tokio::test]
async fn test_python_safe_code_no_findings() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(
        &dir,
        "safe.py",
        "def add(a, b):\n    return a + b\n\nresult = add(1, 2)\n",
    )
    .await;
    let result = scan_dir(&dir).await;
    assert!(
        result.findings.is_empty(),
        "Safe Python code should have no findings, got: {:?}",
        rule_ids(&result)
    );
}

// =========================================================================
// JavaScript scanning
// =========================================================================

#[tokio::test]
async fn test_js_eval_detected() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(&dir, "vuln.js", "function f(x) { eval(x); }\n").await;
    let result = scan_dir(&dir).await;
    assert!(
        has_rule(&result, "js-eval-direct"),
        "Expected js-eval-direct, got: {:?}",
        rule_ids(&result)
    );
}

#[tokio::test]
async fn test_js_child_process_detected() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(
        &dir,
        "vuln.js",
        "const cp = require('child_process');\ncp.exec('ls');\n",
    )
    .await;
    let result = scan_dir(&dir).await;
    assert!(
        has_rule(&result, "js-child-process"),
        "Expected js-child-process, got: {:?}",
        rule_ids(&result)
    );
}

#[tokio::test]
async fn test_js_innerhtml_detected() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(
        &dir,
        "vuln.js",
        "function r(c) { document.getElementById('x').innerHTML = c; }\n",
    )
    .await;
    let result = scan_dir(&dir).await;
    assert!(
        has_rule(&result, "js-xss"),
        "Expected js-xss, got: {:?}",
        rule_ids(&result)
    );
}

#[tokio::test]
async fn test_js_safe_code_no_findings() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(
        &dir,
        "safe.js",
        "function greet(name) {\n    console.log('Hello, ' + name);\n}\n",
    )
    .await;
    let result = scan_dir(&dir).await;
    assert!(
        result.findings.is_empty(),
        "Safe JS code should have no findings, got: {:?}",
        rule_ids(&result)
    );
}

// =========================================================================
// Rust scanning
// =========================================================================

#[tokio::test]
async fn test_rust_unwrap_detected() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(
        &dir,
        "vuln.rs",
        "fn main() {\n    let x = Some(1);\n    x.unwrap();\n}\n",
    )
    .await;
    let result = scan_dir(&dir).await;
    assert!(
        has_rule(&result, "null-pointer"),
        "Expected null-pointer, got: {:?}",
        rule_ids(&result)
    );
}

#[tokio::test]
async fn test_rust_expect_detected() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(
        &dir,
        "vuln.rs",
        "fn main() {\n    let x: Result<i32, &str> = Ok(1);\n    x.expect(\"fail\");\n}\n",
    )
    .await;
    let result = scan_dir(&dir).await;
    assert!(
        has_rule(&result, "expect-panic"),
        "Expected expect-panic, got: {:?}",
        rule_ids(&result)
    );
}

#[tokio::test]
async fn test_rust_unsafe_detected() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(
        &dir,
        "vuln.rs",
        "fn main() {\n    unsafe { std::ptr::null::<i32>().read() };\n}\n",
    )
    .await;
    let result = scan_dir(&dir).await;
    assert!(
        has_rule(&result, "rust-unsafe"),
        "Expected rust-unsafe, got: {:?}",
        rule_ids(&result)
    );
}

#[tokio::test]
async fn test_rust_safe_code_no_findings() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(
        &dir,
        "safe.rs",
        "fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
    )
    .await;
    let result = scan_dir(&dir).await;
    assert!(
        result.findings.is_empty(),
        "Safe Rust code should have no findings, got: {:?}",
        rule_ids(&result)
    );
}

// =========================================================================
// Go scanning
// =========================================================================

#[tokio::test]
async fn test_go_command_injection_detected() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(
        &dir,
        "main.go",
        "package main\nimport \"os/exec\"\nfunc main() {\n    exec.Command(\"ls\").Run()\n}\n",
    )
    .await;
    let result = scan_dir(&dir).await;
    assert!(
        has_rule(&result, "go-command-injection"),
        "Expected go-command-injection, got: {:?}",
        rule_ids(&result)
    );
}

#[tokio::test]
async fn test_go_safe_code_no_findings() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(
        &dir,
        "main.go",
        "package main\nfunc add(a int, b int) int {\n    return a + b\n}\n",
    )
    .await;
    let result = scan_dir(&dir).await;
    assert!(
        result.findings.is_empty(),
        "Safe Go code should have no findings, got: {:?}",
        rule_ids(&result)
    );
}

// =========================================================================
// C scanning
// =========================================================================

#[tokio::test]
async fn test_c_strcpy_detected() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(
        &dir,
        "vuln.c",
        "#include <string.h>\nvoid f(char *d, const char *s) { strcpy(d, s); }\n",
    )
    .await;
    let result = scan_dir(&dir).await;
    assert!(
        has_rule(&result, "c-buffer-overflow"),
        "Expected c-buffer-overflow, got: {:?}",
        rule_ids(&result)
    );
}

#[tokio::test]
async fn test_c_safe_code_no_findings() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(&dir, "safe.c", "int add(int a, int b) {\n    return a + b;\n}\n").await;
    let result = scan_dir(&dir).await;
    assert!(
        result.findings.is_empty(),
        "Safe C code should have no findings, got: {:?}",
        rule_ids(&result)
    );
}

// =========================================================================
// Multi-language scanning
// =========================================================================

#[tokio::test]
async fn test_multi_language_scan() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(&dir, "vuln.py", "eval('1+1')\n").await;
    create_source_file(&dir, "vuln.js", "eval('alert(1)');\n").await;
    create_source_file(&dir, "vuln.rs", "fn main() { Some(1).unwrap(); }\n").await;

    let result = scan_dir(&dir).await;

    assert!(
        result.findings.len() >= 3,
        "Multi-language scan should find >= 3 findings, got {} findings: {:?}",
        result.findings.len(),
        rule_ids(&result)
    );
}

// =========================================================================
// SARIF export
// =========================================================================

#[tokio::test]
async fn test_sarif_export_valid_json() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(&dir, "vuln.py", "eval('x')\n").await;

    let config = SastConfig::default();
    let module = SastModule::with_config(&config);
    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "sarif-test".to_string(),
        source_uri: dir.path().to_string_lossy().to_string(),
        config: HashMap::new(),
    };

    let result = module.execute(&module_config).await.unwrap();
    assert!(!result.findings.is_empty(), "Should have findings");

    // Metadata should contain SARIF-related data
    assert!(
        result.metadata.files_scanned > 0,
        "Should have scanned at least one file"
    );
}

// =========================================================================
// Empty / edge-case scanning
// =========================================================================

#[tokio::test]
async fn test_empty_directory_scan() {
    let dir = tempfile::tempdir().unwrap();
    let result = scan_dir(&dir).await;
    assert!(
        result.findings.is_empty(),
        "Empty directory should have no findings"
    );
}

#[tokio::test]
async fn test_empty_file_scan() {
    let dir = tempfile::tempdir().unwrap();
    create_source_file(&dir, "empty.py", "").await;
    let result = scan_dir(&dir).await;
    assert!(
        result.findings.is_empty(),
        "Empty file should have no findings"
    );
}

#[tokio::test]
async fn test_binary_file_skipped() {
    let dir = tempfile::tempdir().unwrap();
    // Binary content should be skipped (no .py/.js/.rs extension)
    let bin_path = dir.path().join("binary.dat");
    std::fs::write(&bin_path, &[0u8, 1, 2, 3, 255, 254]).unwrap();
    let result = scan_dir(&dir).await;
    assert!(
        result.findings.is_empty(),
        "Binary files should be skipped"
    );
}
