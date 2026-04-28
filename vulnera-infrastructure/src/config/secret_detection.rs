use serde::Deserialize;

/// Secret detection configuration
#[derive(Debug, Clone, Deserialize)]
pub struct SecretDetectionConfig {
    /// Enable entropy-based detection
    pub enable_entropy_detection: bool,
    /// Minimum entropy threshold (0.0 - 8.0)
    pub min_entropy: f64,
    /// Enable pattern-based regex detection
    pub enable_regex_detection: bool,
    /// Enable AST-aware secret extraction
    pub enable_ast_extraction: bool,
    /// Enable live secret verification (AWS, GitHub, GitLab)
    pub enable_verification: bool,
    /// Enable Git history scanning
    pub enable_git_scanning: bool,
    /// Minimum finding severity to report
    pub min_finding_severity: String,
    /// Enable known-secret baselining
    pub enable_baseline: bool,
    /// Path to custom rules file
    pub rule_file_path: Option<String>,
}

impl Default for SecretDetectionConfig {
    fn default() -> Self {
        Self {
            enable_entropy_detection: true,
            min_entropy: 4.5,
            enable_regex_detection: true,
            enable_ast_extraction: true,
            enable_verification: false,
            enable_git_scanning: false,
            min_finding_severity: "info".into(),
            enable_baseline: true,
            rule_file_path: None,
        }
    }
}
