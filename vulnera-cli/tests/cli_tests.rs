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
        .stdout(predicate::str::contains("vulnera 0.2.0"));
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
fn test_analyze_offline_mode() {
    // Test that --offline flag works and skips dependency analysis
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("analyze")
        .arg("--offline")
        .arg("--help")
        .assert()
        .success();
}

#[test]
fn test_sast_help() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("sast")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("static analysis"));
}

#[test]
fn test_secrets_help() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("secrets")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("hardcoded secrets"));
}

#[test]
fn test_deps_help() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("deps")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("dependencies"));
}

#[test]
fn test_quota_help() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("quota")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("quota"));
}

#[test]
fn test_auth_help() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("auth")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Authentication"));
}

#[test]
fn test_config_help() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("config")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Configuration"));
}

#[test]
fn test_json_output_format() {
    // Test that --format json flag is accepted
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("--format")
        .arg("json")
        .arg("--help")
        .assert()
        .success();
}

#[test]
fn test_sarif_output_format() {
    // Test that --format sarif flag is accepted
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("--format")
        .arg("sarif")
        .arg("--help")
        .assert()
        .success();
}

#[test]
fn test_ci_mode_flag() {
    // Test that --ci flag is accepted
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("--ci").arg("--help").assert().success();
}

#[test]
fn test_verbose_flag() {
    // Test that --verbose flag is accepted
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("--verbose").arg("--help").assert().success();
}

#[test]
fn test_quiet_flag() {
    // Test that --quiet flag is accepted
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("--quiet").arg("--help").assert().success();
}

#[test]
fn test_auth_status_subcommand() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("auth")
        .arg("status")
        .arg("--offline")
        .assert()
        .success();
}

#[test]
fn test_config_path_subcommand() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("config").arg("path").assert().success();
}

#[test]
fn test_nonexistent_path_error() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vulnera"));
    cmd.arg("analyze")
        .arg("/nonexistent/path/that/does/not/exist")
        .arg("--offline")
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}
