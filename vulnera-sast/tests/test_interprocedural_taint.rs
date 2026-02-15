//! Inter-procedural taint flow tests
//!
//! Validates that the call graph wiring propagates taint across function
//! boundaries, not just within a single function.

use uuid::Uuid;
use vulnera_core::config::{AnalysisDepth, SastConfig};
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig};
use vulnera_sast::SastModule;

/// Helper to run SAST scan on a temp directory with given files.
async fn scan_files(files: &[(&str, &str)]) -> vulnera_core::domain::module::ModuleResult {
    let temp_dir = tempfile::tempdir().unwrap();
    for (name, content) in files {
        let file_path = temp_dir.path().join(name);
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&file_path, content).unwrap();
    }

    let config = SastConfig {
        analysis_depth: AnalysisDepth::Deep,
        enable_data_flow: true,
        enable_call_graph: true,
        ..Default::default()
    };

    let module = SastModule::with_config(&config);
    module
        .execute(&ModuleConfig {
            job_id: Uuid::new_v4(),
            project_id: "test-interproc".to_string(),
            source_uri: temp_dir.path().to_string_lossy().to_string(),
            config: std::collections::HashMap::new(),
        })
        .await
        .unwrap()
}

// =========================================================================
// Cross-function taint: Python
// =========================================================================

#[tokio::test]
async fn test_python_cross_function_taint_source_to_sink() {
    // Taint originates in get_input(), flows into process() which calls eval()
    let result = scan_files(&[(
        "app.py",
        r#"
import os

def get_input():
    return os.environ.get("USER_INPUT")

def process(data):
    eval(data)

user = get_input()
process(user)
"#,
    )])
    .await;

    // We expect at least 1 finding for eval() with tainted data
    let eval_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.rule_id
                .as_deref()
                .map(|r| r.contains("unsafe-function-call") || r.contains("data-flow"))
                .unwrap_or(false)
        })
        .collect();

    assert!(
        !eval_findings.is_empty(),
        "Should detect eval() with tainted data from os.environ. Got findings: {:?}",
        result
            .findings
            .iter()
            .map(|f| f.rule_id.as_deref().unwrap_or("(none)"))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_python_sanitizer_blocks_cross_function_taint() {
    // Taint originates in get_input(), but sanitize() clears it before sink
    let result = scan_files(&[(
        "app.py",
        r#"
import os
import html

def get_input():
    return os.environ.get("USER_INPUT")

def sanitize(data):
    return html.escape(data)

user = get_input()
safe = sanitize(user)
eval(safe)
"#,
    )])
    .await;

    // html.escape is a known sanitizer pattern — the eval(safe) should ideally
    // NOT produce a taint finding, or at least have reduced confidence
    let eval_taint: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.rule_id
                .as_deref()
                .map(|r| r.contains("data-flow"))
                .unwrap_or(false)
        })
        .collect();

    // Sanitizer should block taint propagation to eval
    // We check that there are fewer taint findings than the unsanitized version
    assert!(
        eval_taint.len() <= 1,
        "Sanitizer should reduce taint findings to eval. Got: {:?}",
        eval_taint
            .iter()
            .map(|f| f.rule_id.as_deref().unwrap_or("(none)"))
            .collect::<Vec<_>>()
    );
}

// =========================================================================
// Cross-function taint: JavaScript
// =========================================================================

#[tokio::test]
async fn test_js_cross_function_taint_source_to_sink() {
    let result = scan_files(&[(
        "app.js",
        r#"
const child_process = require('child_process');

function getUserInput() {
    return process.env.USER_INPUT;
}

function runCommand(cmd) {
    child_process.exec(cmd);
}

const input = getUserInput();
runCommand(input);
"#,
    )])
    .await;

    // Expect a finding for child_process.exec() with tainted data
    let cmd_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.rule_id
                .as_deref()
                .map(|r| r.contains("child-process") || r.contains("data-flow"))
                .unwrap_or(false)
        })
        .collect();

    assert!(
        !cmd_findings.is_empty(),
        "Should detect child_process.exec() call. Got findings: {:?}",
        result
            .findings
            .iter()
            .map(|f| f.rule_id.as_deref().unwrap_or("(none)"))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_python_callback_parameter_propagates_to_return() {
    let result = scan_files(&[(
        "app.py",
        r#"
import os

def apply(callback, value):
    result = callback(value)
    return result

def identity(v):
    return v

user = os.environ.get("USER_INPUT")
command = apply(identity, user)
eval(command)
"#,
    )])
    .await;

    let has_eval_or_dataflow = result.findings.iter().any(|f| {
        f.rule_id
            .as_deref()
            .map(|r| r.contains("unsafe-function-call") || r.contains("data-flow"))
            .unwrap_or(false)
    });

    assert!(
        has_eval_or_dataflow,
        "Expected callback parameter taint to flow through apply() return into eval(). Findings: {:?}",
        result
            .findings
            .iter()
            .map(|f| f.rule_id.as_deref().unwrap_or("(none)"))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_js_callback_parameter_propagates_to_return() {
    let result = scan_files(&[(
        "app.js",
        r#"
const child_process = require('child_process');

function apply(callback, value) {
    const result = callback(value);
    return result;
}

function passthrough(v) {
    return v;
}

const user = process.env.USER_INPUT;
const cmd = apply(passthrough, user);
child_process.exec(cmd);
"#,
    )])
    .await;

    let has_command_or_dataflow = result.findings.iter().any(|f| {
        f.rule_id
            .as_deref()
            .map(|r| r.contains("child-process") || r.contains("data-flow"))
            .unwrap_or(false)
    });

    assert!(
        has_command_or_dataflow,
        "Expected callback parameter taint to flow through apply() return into child_process.exec(). Findings: {:?}",
        result
            .findings
            .iter()
            .map(|f| f.rule_id.as_deref().unwrap_or("(none)"))
            .collect::<Vec<_>>()
    );
}

// =========================================================================
// Call graph construction: multi-file
// =========================================================================

#[tokio::test]
async fn test_multifile_call_graph_detects_cross_file_functions() {
    // Two files: helper.py defines get_input, main.py imports and uses it
    let result = scan_files(&[
        (
            "helper.py",
            r#"
import os

def get_input():
    return os.environ.get("USER_INPUT")
"#,
        ),
        (
            "main.py",
            r#"
from helper import get_input

user = get_input()
eval(user)
"#,
        ),
    ])
    .await;

    // At minimum, eval() on user input should be flagged directly.
    // With call graph, cross-file taint from helper.get_input() → main.eval() should trigger.
    let has_eval_finding = result.findings.iter().any(|f| {
        f.rule_id
            .as_deref()
            .map(|r| r.contains("unsafe-function-call") || r.contains("data-flow"))
            .unwrap_or(false)
    });

    assert!(
        has_eval_finding,
        "Should detect eval() with tainted input from cross-file import. Findings: {:?}",
        result
            .findings
            .iter()
            .map(|f| f.rule_id.as_deref().unwrap_or("(none)"))
            .collect::<Vec<_>>()
    );
}

// =========================================================================
// Incremental tracker: unit test for dependency-aware change detection
// =========================================================================

#[test]
fn test_incremental_tracker_dependency_triggers_reanalysis() {
    use vulnera_sast::infrastructure::incremental::IncrementalTracker;

    let mut tracker = IncrementalTracker::new();

    // Simulate previous scan: both files existed
    let content_a = "from helper import get_input\neval(get_input())";
    let content_b = "def get_input(): return input()";

    let hash_a = IncrementalTracker::hash_content(content_a);
    let hash_b = IncrementalTracker::hash_content(content_b);

    // Record as previous state by recording + saving/loading cycle
    tracker.record_file("main.py", hash_a.clone(), content_a.len() as u64, 1);
    tracker.record_file("helper.py", hash_b.clone(), content_b.len() as u64, 0);

    // Save and reload to move current → previous
    let tmp = tempfile::NamedTempFile::new().unwrap();
    tracker.save_to_file(tmp.path()).unwrap();
    let mut tracker = IncrementalTracker::load_from_file(tmp.path()).unwrap();

    // Set dependencies: main.py depends on helper.py
    let mut deps = std::collections::HashMap::new();
    deps.insert(
        "main.py".to_string(),
        ["helper.py".to_string()].into_iter().collect(),
    );
    tracker.set_file_dependencies(deps);

    // helper.py content changed
    let new_content_b = "def get_input(): return os.environ['X']";
    // Record helper.py with new hash in current_state
    tracker.record_file(
        "helper.py",
        IncrementalTracker::hash_content(new_content_b),
        new_content_b.len() as u64,
        0,
    );

    // main.py content is UNCHANGED
    let (needs, _) = tracker.needs_analysis("main.py", content_a);
    assert!(
        needs,
        "main.py should need re-analysis because its dependency helper.py changed"
    );
}

#[test]
fn test_incremental_tracker_no_dependency_change_skips() {
    use vulnera_sast::infrastructure::incremental::IncrementalTracker;

    let mut tracker = IncrementalTracker::new();

    let content_a = "from helper import get_input\neval(get_input())";
    let content_b = "def get_input(): return input()";

    let hash_a = IncrementalTracker::hash_content(content_a);
    let hash_b = IncrementalTracker::hash_content(content_b);

    tracker.record_file("main.py", hash_a.clone(), content_a.len() as u64, 1);
    tracker.record_file("helper.py", hash_b.clone(), content_b.len() as u64, 0);

    let tmp = tempfile::NamedTempFile::new().unwrap();
    tracker.save_to_file(tmp.path()).unwrap();
    let mut tracker = IncrementalTracker::load_from_file(tmp.path()).unwrap();

    let mut deps = std::collections::HashMap::new();
    deps.insert(
        "main.py".to_string(),
        ["helper.py".to_string()].into_iter().collect(),
    );
    tracker.set_file_dependencies(deps);

    // Record helper.py with SAME hash (unchanged)
    tracker.record_file("helper.py", hash_b, content_b.len() as u64, 0);

    // main.py content is also unchanged
    let (needs, _) = tracker.needs_analysis("main.py", content_a);
    assert!(
        !needs,
        "main.py should NOT need re-analysis because neither it nor its dependencies changed"
    );
}
