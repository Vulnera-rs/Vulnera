//! Tests for false positive prevention in secrets scanning
//!
//! This module tests:
//! - database-password regex doesn't match type constructors like Password::new()
//! - Various false positive scenarios

use once_cell::sync::Lazy;
use regex::Regex;
use vulnera_secrets::domain::RulePattern;
use vulnera_secrets::infrastructure::rules::default_rules::database_password_rule;

// ============================================================================
// Database Password Regex Tests
// ============================================================================

static DB_PASSWORD_REGEX: Lazy<Regex> = Lazy::new(|| {
    let rule = database_password_rule();
    match rule.pattern {
        RulePattern::Regex(pattern) => Regex::new(&pattern).expect("Invalid regex"),
        _ => panic!("Expected Regex pattern"),
    }
});

fn get_database_password_regex() -> Regex {
    DB_PASSWORD_REGEX.clone()
}

#[test]
fn test_does_not_match_rust_type_constructor() {
    let regex = get_database_password_regex();

    // These should NOT match - they're Rust type constructors, not password assignments
    let false_positives = [
        "Password::new()",             // No = sign
        "Password::from(secret)",      // No = sign
        "pwd::Config::default()",      // :: immediately after pwd
        "passwd::Hash::new()",         // :: immediately after passwd
        "use password::PasswordHash;", // No = sign
    ];

    for input in &false_positives {
        assert!(
            !regex.is_match(input),
            "Should NOT match type constructor: {}",
            input
        );
    }
}

#[test]
fn test_matches_actual_password_assignments() {
    let regex = get_database_password_regex();

    // These SHOULD match - they're actual password assignments
    let true_positives = [
        "password=mysecretpassword",
        "PASSWORD=hunter2hunter2",
        "password: supersecret123",
        "PWD=mypassword123",
        r#"password="secretvalue1""#,
        "password = verysecretpwd",
        "db_password=production123",
        "DB_PASSWORD=secretkey12",
    ];

    for input in &true_positives {
        assert!(
            regex.is_match(input),
            "Should match password assignment: {}",
            input
        );
    }
}

#[test]
fn test_does_not_match_short_passwords() {
    let regex = get_database_password_regex();

    // Passwords shorter than 8 chars should not match (rule requires 8+)
    let short_passwords = ["password=short", "pwd=test", "passwd=abc"];

    for input in &short_passwords {
        assert!(
            !regex.is_match(input),
            "Should NOT match short password (< 8 chars): {}",
            input
        );
    }
}

#[test]
fn test_does_not_match_function_calls() {
    let regex = get_database_password_regex();

    // Function calls should not match
    let function_calls = [
        "password(user_input)",
        "getPassword()",
        "set_password(new_pwd)",
        "validate_password(input)",
    ];

    for input in &function_calls {
        assert!(
            !regex.is_match(input),
            "Should NOT match function call: {}",
            input
        );
    }
}

#[test]
fn test_does_not_match_method_definitions() {
    let regex = get_database_password_regex();

    // Method definitions should not match
    let method_defs = [
        "fn password(&self) -> String",
        "def password(self):",
        "function password() {",
    ];

    for input in &method_defs {
        assert!(
            !regex.is_match(input),
            "Should NOT match method definition: {}",
            input
        );
    }
}

#[test]
fn test_does_not_match_double_colon_paths() {
    let regex = get_database_password_regex();

    // Rust :: paths should not match
    let rust_paths = [
        "config::password::DEFAULT",
        "crate::password::validate",
        "super::password",
        "self::password",
    ];

    for input in &rust_paths {
        assert!(
            !regex.is_match(input),
            "Should NOT match Rust path: {}",
            input
        );
    }
}

#[test]
fn test_regex_captures_password_value() {
    let regex = get_database_password_regex();

    let input = "password=mysecretpassword";
    let captures = regex.captures(input).expect("Should match");

    // The first capture group should contain the password value
    let password = captures.get(1).map(|m| m.as_str());
    assert_eq!(password, Some("mysecretpassword"));
}

#[test]
fn test_case_insensitive_matching() {
    let regex = get_database_password_regex();

    let variants = [
        "PASSWORD=mysecretpassword",
        "Password=mysecretpassword",
        "password=mysecretpassword",
        "PassWord=mysecretpassword",
    ];

    for input in &variants {
        assert!(
            regex.is_match(input),
            "Should match case variant: {}",
            input
        );
    }
}

#[test]
fn test_handles_quoted_passwords() {
    let regex = get_database_password_regex();

    let quoted = [r#"password="secretvalue1""#, "password='secretvalue1'"];

    for input in &quoted {
        assert!(
            regex.is_match(input),
            "Should match quoted password: {}",
            input
        );
    }
}

#[test]
fn test_handles_whitespace_variations() {
    let regex = get_database_password_regex();

    let variations = [
        "password = secretvalue1",
        "password=secretvalue1",
        "password:secretvalue1",
        "password : secretvalue1",
    ];

    for input in &variations {
        assert!(
            regex.is_match(input),
            "Should match whitespace variation: {}",
            input
        );
    }
}

#[test]
fn test_does_not_match_environment_variable_reference() {
    let regex = get_database_password_regex();

    // References to env vars should not match because of the [a-z0-9] start requirement
    // in the pattern: r#"(?i)(?:password|pwd|passwd)[\s_-]*(?:=|:[^:])\s*["']?([a-z0-9][^\s"'`:]{7,})"#
    // Since it starts with [a-z0-9], symbols like $ or { should not match.

    let env_refs = [
        "password=$PASSWORD",
        "password=${DB_PASSWORD}",
        r#"password="%PASSWORD%""#,
    ];

    for input in &env_refs {
        assert!(
            !regex.is_match(input),
            "Should NOT match environment variable reference: {}",
            input
        );
    }
}

#[test]
fn test_realistic_config_file_lines() {
    let regex = get_database_password_regex();

    // Lines from real config files that SHOULD be detected
    let should_match = [
        "DATABASE_PASSWORD=productionSecret123",
        "db.password=mysqlPassword!",
        "spring.datasource.password=jdbcSecret99",
        "POSTGRES_PASSWORD=pgAdminPass",
    ];

    for input in &should_match {
        assert!(regex.is_match(input), "Should match config line: {}", input);
    }
}

#[test]
fn test_realistic_code_lines_should_not_match() {
    let regex = get_database_password_regex();

    // Lines from real code that should NOT be detected
    let should_not_match = [
        "fn validate_password(pwd: &str) -> bool", // No = after password keyword
        "/// Sets the password field",             // Doc comment, no assignment
        "Password::verify(hash, attempt)",         // No = sign
    ];

    for input in &should_not_match {
        assert!(
            !regex.is_match(input),
            "Should NOT match code line: {}",
            input
        );
    }
}

#[test]
fn test_known_limitations() {
    let regex = get_database_password_regex();

    // Document known limitations - these currently DO match but ideally shouldn't
    // because the (?i) flag makes [a-z0-9] case-insensitive, so it matches Uppercase starts.
    let known_limitations = [
        "password = \"SecretWithUpper\"",
        "self.password = Password::hash(raw);",
    ];

    for input in &known_limitations {
        assert!(
            regex.is_match(input),
            "Documenting known limitation - this currently matches: {}",
            input
        );
    }
}
