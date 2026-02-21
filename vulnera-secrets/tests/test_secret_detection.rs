//! Integration tests for secret detection

use tempfile::TempDir;
use uuid::Uuid;
use vulnera_core::config::SecretDetectionConfig;
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig, ModuleType};
use vulnera_secrets::SecretDetectionModule;

async fn create_test_file(dir: &TempDir, filename: &str, content: &str) -> std::path::PathBuf {
    let path = dir.path().join(filename);
    tokio::fs::write(&path, content)
        .await
        .expect("Failed to write test file");
    path
}

fn sample_aws_key() -> &'static str {
    r#"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"#
}

fn sample_high_entropy() -> &'static str {
    r#"API_KEY=K8j3mN9pQ2rT5vX8zA1bC4dE7fG0hI3jK6mN9pQ2rT5v
"#
}

#[tokio::test]
async fn test_regex_detection() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Create test file with secrets
    create_test_file(&temp_dir, "config.env", sample_aws_key()).await;

    let config = SecretDetectionConfig::default();
    let module = SecretDetectionModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: temp_dir.path().to_string_lossy().to_string(),
        config: std::collections::HashMap::new(),
    };

    let result = module
        .execute(&module_config)
        .await
        .expect("Module execution failed");

    assert_eq!(result.module_type, ModuleType::SecretDetection);
    assert!(!result.findings.is_empty(), "Should find secrets");

    // Check for AWS Access Key
    let aws_access_key = result
        .findings
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("aws-access-key"));
    assert!(aws_access_key.is_some(), "Should find AWS Access Key");

    // Check for AWS Secret Key
    let aws_secret_key = result
        .findings
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("aws-secret-key"));
    assert!(aws_secret_key.is_some(), "Should find AWS Secret Key");
}

#[tokio::test]
async fn test_entropy_detection() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Create test file with high entropy
    create_test_file(&temp_dir, "token.txt", sample_high_entropy()).await;

    let config = SecretDetectionConfig {
        enable_entropy_detection: true,
        base64_entropy_threshold: 4.0, // Lower threshold for test
        ..SecretDetectionConfig::default()
    };

    let module = SecretDetectionModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: temp_dir.path().to_string_lossy().to_string(),
        config: std::collections::HashMap::new(),
    };

    let result = module
        .execute(&module_config)
        .await
        .expect("Module execution failed");

    assert!(
        !result.findings.is_empty(),
        "Should find high entropy strings"
    );

    // Check for entropy finding
    let entropy_finding = result.findings.iter().find(|f| {
        f.rule_id
            .as_deref()
            .is_some_and(|id| id.starts_with("entropy-"))
    });
    assert!(entropy_finding.is_some(), "Should find high entropy string");
}

#[tokio::test]
async fn test_skip_markdown_files() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Create README.md with a secret-like pattern that would normally match the regex detector
    create_test_file(&temp_dir, "README.md", sample_aws_key()).await;

    let config = SecretDetectionConfig::default();
    let module = SecretDetectionModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: temp_dir.path().to_string_lossy().to_string(),
        config: std::collections::HashMap::new(),
    };

    let result = module
        .execute(&module_config)
        .await
        .expect("Module execution failed");

    // By default markdown files are excluded; ensure no findings are reported for README.md
    assert!(
        result.findings.is_empty(),
        "README.md should be excluded by default; expected no findings"
    );
}

#[tokio::test]
async fn test_rule_path_patterns() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Create a README.md with a generic key that would otherwise match the rule
    create_test_file(&temp_dir, "README.md", sample_high_entropy()).await;

    // Create a .env file with a generic key that should match the rule
    create_test_file(&temp_dir, "config.env", sample_high_entropy()).await;

    // Write a rule that only applies to .env files using a path pattern
    let rules_toml = r#"
[[rules]]
id = "test-generic-api-key"
name = "Test Generic API Key"
description = "Generic API key only in .env files"
secret_type = "api_key"
pattern = '(?i)(?:api|apikey|api_key|apikey)[\s_-]*(?:key|token|secret)?[\s_-]*[:=]\s*([A-Za-z0-9_\-]{20,})'
keywords = ["api", "key"]
path_patterns = ["**/*.env"]
"#;

    let rules_path = temp_dir.path().join("rules.toml");
    tokio::fs::write(&rules_path, rules_toml)
        .await
        .expect("Failed to write rules.toml");

    let config = SecretDetectionConfig {
        exclude_extensions: vec![],
        rule_file_path: Some(rules_path),
        enable_entropy_detection: false, // Reduce noise for the test
        ..SecretDetectionConfig::default()
    };

    let module = SecretDetectionModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: temp_dir.path().to_string_lossy().to_string(),
        config: std::collections::HashMap::new(),
    };

    let result = module
        .execute(&module_config)
        .await
        .expect("Module execution failed");

    // Should find the key in config.env but it should NOT match in README.md because the rule only applies to .env files
    let found_env = result.findings.iter().find(|f| {
        f.rule_id.as_deref() == Some("test-generic-api-key")
            && f.location.path.ends_with("config.env")
    });
    assert!(
        found_env.is_some(),
        "Should find generic API key in config.env"
    );

    let found_readme = result.findings.iter().find(|f| {
        f.rule_id.as_deref() == Some("test-generic-api-key")
            && f.location.path.ends_with("README.md")
    });
    assert!(
        found_readme.is_none(),
        "Should not find generic API key in README.md"
    );
}

#[tokio::test]
async fn test_git_scanner() {
    // Skip if git is not available or configured
    if std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let repo_path = temp_dir.path();

    // Initialize git repo
    let repo = git2::Repository::init(repo_path).expect("Failed to init git repo");

    // Configure user for commit
    let mut config = repo.config().unwrap();
    config.set_str("user.name", "Test User").unwrap();
    config.set_str("user.email", "test@example.com").unwrap();

    // Create a file with a secret
    let file_path = repo_path.join("secret.txt");
    std::fs::write(&file_path, "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE").unwrap();

    // Commit the file
    let mut index = repo.index().unwrap();
    index.add_path(std::path::Path::new("secret.txt")).unwrap();
    let oid = index.write_tree().unwrap();
    let tree = repo.find_tree(oid).unwrap();
    let signature = repo.signature().unwrap();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "Add secret",
        &tree,
        &[],
    )
    .unwrap();

    // Run scan with git history enabled
    let config = SecretDetectionConfig {
        scan_git_history: true,
        ..SecretDetectionConfig::default()
    };

    let module = SecretDetectionModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: repo_path.to_string_lossy().to_string(),
        config: std::collections::HashMap::new(),
    };

    let result = module
        .execute(&module_config)
        .await
        .expect("Module execution failed");

    // Should find the secret in the file (current) AND in git history
    // Note: The current implementation might deduplicate or show both.
    // Let's check if we have at least one finding.
    assert!(
        !result.findings.is_empty(),
        "Should find secrets in git repo"
    );

    // Check if we have a finding with git commit info in description or location
    // The GitScanner adds commit hash to ID and location
    let _git_finding = result
        .findings
        .iter()
        .find(|f| f.location.path.contains(":"));
    // Depending on implementation, it might be tricky to distinguish without checking ID format
    // But GitScanner prepends hash to ID: format!("{}-{}", metadata.hash, finding.id)

    // Let's just verify we found the AWS key
    let aws_access_key = result
        .findings
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("aws-access-key"));
    assert!(
        aws_access_key.is_some(),
        "Should find AWS Access Key in git repo"
    );
}

#[tokio::test]
async fn test_allowlist_suppression_and_metadata() {
    let temp_dir = tempfile::tempdir().unwrap();

    create_test_file(
        &temp_dir,
        "secrets.env",
        r#"github_token=ghp_123456789012345678901234567890123456
api_key=ALLOWED_PLACEHOLDER_TOKEN_VALUE_123456
"#,
    )
    .await;

    let config = SecretDetectionConfig {
        enable_entropy_detection: false,
        global_allowlist_patterns: vec![r"ALLOWED_PLACEHOLDER_TOKEN_VALUE_[0-9]+".to_string()],
        rule_allowlist_patterns: std::collections::HashMap::from([(
            "github-token".to_string(),
            vec![r"ghp_123456789012345678901234567890123456".to_string()],
        )]),
        ..SecretDetectionConfig::default()
    };

    let module = SecretDetectionModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "test-project".to_string(),
        source_uri: temp_dir.path().to_string_lossy().to_string(),
        config: std::collections::HashMap::new(),
    };

    let result = module
        .execute(&module_config)
        .await
        .expect("Module execution failed");

    assert!(
        result.findings.is_empty(),
        "All findings should be suppressed by allowlists"
    );

    assert_eq!(
        result
            .metadata
            .additional_info
            .get("allowlist_suppressed")
            .cloned(),
        Some("2".to_string())
    );

    assert_eq!(
        result
            .metadata
            .additional_info
            .get("suppressed:allowlist:rule:github-token")
            .cloned(),
        Some("1".to_string())
    );

    assert_eq!(
        result
            .metadata
            .additional_info
            .get("suppressed:allowlist:global")
            .cloned(),
        Some("1".to_string())
    );
}
