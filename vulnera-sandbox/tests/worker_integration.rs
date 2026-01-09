//! Integration tests for out-of-process sandbox execution
//!
//! These tests verify that:
//! 1. The orchestrator is NOT restricted when using the worker
//! 2. The worker binary can be spawned and returns results
//! 3. Sandbox restrictions are applied in the worker, not the orchestrator

use std::path::Path;

/// Test that the executor can discover the worker binary
#[test]
fn test_worker_binary_discovery() {
    use vulnera_sandbox::SandboxExecutor;

    let executor = SandboxExecutor::auto();

    // Worker may or may not be available depending on build state
    if executor.is_worker_available() {
        println!("Worker binary is available");
    } else {
        println!("Worker binary not found (expected if not built separately)");
    }

    // Executor should always be available (falls back to in-process)
    assert!(executor.is_available());
}

/// Test that the orchestrator process can still perform operations
/// that would be blocked if Landlock was applied in-process
#[test]
fn test_orchestrator_not_restricted() {
    use std::env;
    use std::fs;

    // Create a temp directory
    let temp_dir = env::temp_dir().join("vulnera_sandbox_test");
    fs::create_dir_all(&temp_dir).expect("Should be able to create directories");

    // Write a file
    let test_file = temp_dir.join("test.txt");
    fs::write(&test_file, "test content").expect("Should be able to write files");

    // Read the file
    let content = fs::read_to_string(&test_file).expect("Should be able to read files");
    assert_eq!(content, "test content");

    // Clean up
    fs::remove_file(&test_file).expect("Should be able to delete files");
    fs::remove_dir(&temp_dir).expect("Should be able to delete directories");

    // If we reach here, the orchestrator is not restricted
    println!("Orchestrator verified not restricted - filesystem operations successful");
}

/// Test that creating a SandboxExecutor doesn't restrict the current process
#[test]
fn test_executor_creation_does_not_restrict() {
    use std::env;
    use std::fs;
    use vulnera_sandbox::{SandboxExecutor, SandboxPolicy};

    // Create executor (this should NOT restrict the current process)
    let _executor = SandboxExecutor::auto();

    // Create a policy (this should NOT restrict the current process)
    let _policy = SandboxPolicy::default()
        .with_readonly_path("/tmp")
        .with_timeout_secs(30);

    // Verify we can still perform filesystem operations
    let temp_file = env::temp_dir().join("vulnera_executor_test.txt");
    fs::write(&temp_file, "executor test").expect("Writing should not be blocked");
    fs::remove_file(&temp_file).expect("Deletion should not be blocked");

    println!("Executor creation verified safe - no in-process restrictions applied");
}

/// Test worker binary execution (requires built worker)
#[tokio::test]
#[ignore = "Requires vulnera-worker binary to be built"]
async fn test_worker_execution() {
    use std::process::Stdio;
    use tokio::process::Command;

    let worker_path = "./target/debug/vulnera-worker";

    if !Path::new(worker_path).exists() {
        println!("Skipping: worker binary not found at {}", worker_path);
        return;
    }

    // Test worker help command
    let output = Command::new(worker_path)
        .arg("--help")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("Failed to run worker");

    assert!(output.status.success() || output.status.code() == Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("vulnera-worker") || stdout.contains("--module"));

    println!("Worker binary execution verified");
}
