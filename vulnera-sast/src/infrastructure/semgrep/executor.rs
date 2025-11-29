//! Semgrep OSS executor
//!
//! This module executes Semgrep via subprocess for taint tracking and advanced analysis.
//! Key features:
//! - Temporary YAML rule file generation
//! - JSON output parsing
//! - Configurable timeout and memory limits
//! - Support for both search and taint modes

use crate::domain::entities::{
    Finding, Location, SemgrepRule, SemgrepRuleMode, Severity, TaintConfig, TaintPattern,
    TaintPropagator,
};
use crate::domain::value_objects::{Confidence, Language};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;
use tokio::process::Command;
use tracing::{debug, error, instrument};

/// Default timeout for Semgrep execution (5 minutes)
const DEFAULT_TIMEOUT_SECS: u64 = 300;

/// Default max memory for Semgrep (2GB)
const DEFAULT_MAX_MEMORY_MB: u64 = 2048;

/// Errors that can occur during Semgrep execution
#[derive(Debug, Error)]
pub enum SemgrepError {
    #[error("Semgrep not found in PATH. Install with: pip install semgrep")]
    NotInstalled,

    #[error("Failed to create temporary rule file: {0}")]
    TempFileError(#[from] std::io::Error),

    #[error("Semgrep execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Semgrep timed out after {0} seconds")]
    Timeout(u64),

    #[error("Failed to parse Semgrep output: {0}")]
    OutputParseError(String),

    #[error("Invalid rule configuration: {0}")]
    InvalidRule(String),
}

/// Configuration for Semgrep execution
#[derive(Debug, Clone)]
pub struct SemgrepConfig {
    /// Path to semgrep executable (or "semgrep" if in PATH)
    pub executable: String,
    /// Execution timeout
    pub timeout: Duration,
    /// Maximum memory in MB
    pub max_memory_mb: u64,
    /// Number of parallel jobs
    pub jobs: u32,
    /// Enable verbose output
    pub verbose: bool,
    /// Additional CLI arguments
    pub extra_args: Vec<String>,
}

impl Default for SemgrepConfig {
    fn default() -> Self {
        Self {
            executable: "semgrep".to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            max_memory_mb: DEFAULT_MAX_MEMORY_MB,
            jobs: 4,
            verbose: false,
            extra_args: vec![],
        }
    }
}

/// Semgrep executor for running analysis
pub struct SemgrepExecutor {
    config: SemgrepConfig,
}

impl SemgrepExecutor {
    /// Create a new Semgrep executor with default config
    pub fn new() -> Self {
        Self {
            config: SemgrepConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: SemgrepConfig) -> Self {
        Self { config }
    }

    /// Check if Semgrep is installed and accessible
    #[instrument(skip(self))]
    pub async fn check_installation(&self) -> Result<String, SemgrepError> {
        let output = Command::new(&self.config.executable)
            .arg("--version")
            .output()
            .await
            .map_err(|_| SemgrepError::NotInstalled)?;

        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            debug!(version = %version, "Semgrep found");
            Ok(version)
        } else {
            Err(SemgrepError::NotInstalled)
        }
    }

    /// Execute Semgrep with the given rules on the target path
    #[instrument(skip(self, rules), fields(rule_count = rules.len()))]
    pub async fn execute(
        &self,
        rules: &[SemgrepRule],
        target_path: &Path,
    ) -> Result<Vec<Finding>, SemgrepError> {
        if rules.is_empty() {
            return Ok(Vec::new());
        }

        // Generate YAML rules file
        let rules_yaml = self.generate_rules_yaml(rules)?;
        let temp_dir = tempfile::tempdir()?;
        let rules_file = temp_dir.path().join("rules.yaml");
        std::fs::write(&rules_file, &rules_yaml)?;

        debug!(
            rules_file = %rules_file.display(),
            yaml_size = rules_yaml.len(),
            "Generated Semgrep rules file"
        );

        // Build command
        let mut cmd = Command::new(&self.config.executable);
        cmd.arg("--json")
            .arg("--config")
            .arg(&rules_file)
            .arg("--timeout")
            .arg(self.config.timeout.as_secs().to_string())
            .arg("--max-memory")
            .arg(self.config.max_memory_mb.to_string())
            .arg("--jobs")
            .arg(self.config.jobs.to_string())
            .arg("--no-git-ignore") // Scan all files
            .arg("--metrics=off") // Disable telemetry
            .arg(target_path);

        if self.config.verbose {
            cmd.arg("--verbose");
        }

        for arg in &self.config.extra_args {
            cmd.arg(arg);
        }

        debug!(command = ?cmd, "Executing Semgrep");

        // Execute with timeout
        let output = tokio::time::timeout(
            self.config.timeout + Duration::from_secs(10), // Extra buffer
            cmd.output(),
        )
        .await
        .map_err(|_| SemgrepError::Timeout(self.config.timeout.as_secs()))?
        .map_err(|e| SemgrepError::ExecutionFailed(e.to_string()))?;

        // Parse output
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() && !stdout.contains("\"results\"") {
            error!(
                exit_code = output.status.code(),
                stderr = %stderr,
                "Semgrep execution failed"
            );
            return Err(SemgrepError::ExecutionFailed(stderr.to_string()));
        }

        // Parse JSON output
        self.parse_output(&stdout, rules)
    }

    /// Generate YAML rules from SemgrepRule definitions
    fn generate_rules_yaml(&self, rules: &[SemgrepRule]) -> Result<String, SemgrepError> {
        let mut yaml_rules = Vec::new();

        for rule in rules {
            let rule_yaml = self.rule_to_yaml(rule)?;
            yaml_rules.push(rule_yaml);
        }

        Ok(format!("rules:\n{}", yaml_rules.join("\n")))
    }

    /// Convert a SemgrepRule to YAML format
    fn rule_to_yaml(&self, rule: &SemgrepRule) -> Result<String, SemgrepError> {
        let mut yaml = String::new();

        // Rule ID
        yaml.push_str(&format!("  - id: {}\n", rule.id));

        // Languages
        let langs: Vec<&str> = rule.languages.iter().map(|l| l.to_semgrep_id()).collect();
        yaml.push_str(&format!("    languages: [{}]\n", langs.join(", ")));

        // Message
        yaml.push_str(&format!(
            "    message: \"{}\"\n",
            rule.message.replace('\"', "\\\"")
        ));

        // Severity
        let severity_str = match rule.severity {
            Severity::Critical | Severity::High => "ERROR",
            Severity::Medium => "WARNING",
            Severity::Low | Severity::Info => "INFO",
        };
        yaml.push_str(&format!("    severity: {}\n", severity_str));

        // Pattern or taint config based on mode
        match &rule.mode {
            SemgrepRuleMode::Search => {
                if let Some(pattern) = &rule.pattern {
                    yaml.push_str(&format!(
                        "    pattern: |\n      {}\n",
                        pattern.replace('\n', "\n      ")
                    ));
                } else if let Some(patterns) = &rule.patterns {
                    yaml.push_str("    patterns:\n");
                    for p in patterns {
                        yaml.push_str(&format!(
                            "      - pattern: |\n          {}\n",
                            p.replace('\n', "\n          ")
                        ));
                    }
                } else {
                    return Err(SemgrepError::InvalidRule(format!(
                        "Rule {} has no pattern defined",
                        rule.id
                    )));
                }
            }
            SemgrepRuleMode::Taint => {
                if let Some(taint) = &rule.taint_config {
                    yaml.push_str("    mode: taint\n");
                    yaml.push_str(&self.taint_config_to_yaml(taint));
                } else {
                    return Err(SemgrepError::InvalidRule(format!(
                        "Taint rule {} has no taint configuration",
                        rule.id
                    )));
                }
            }
        }

        // Metadata
        if !rule.cwe_ids.is_empty() || !rule.owasp_categories.is_empty() || !rule.tags.is_empty() {
            yaml.push_str("    metadata:\n");
            if !rule.cwe_ids.is_empty() {
                yaml.push_str(&format!("      cwe: [{}]\n", rule.cwe_ids.join(", ")));
            }
            if !rule.owasp_categories.is_empty() {
                yaml.push_str(&format!(
                    "      owasp: [{}]\n",
                    rule.owasp_categories.join(", ")
                ));
            }
            if !rule.tags.is_empty() {
                yaml.push_str(&format!("      tags: [{}]\n", rule.tags.join(", ")));
            }
        }

        // Fix suggestion
        if let Some(fix) = &rule.fix {
            yaml.push_str(&format!(
                "    fix: |\n      {}\n",
                fix.replace('\n', "\n      ")
            ));
        }

        Ok(yaml)
    }

    /// Convert TaintConfig to YAML string
    fn taint_config_to_yaml(&self, config: &TaintConfig) -> String {
        let mut yaml = String::new();

        // Pattern sources
        yaml.push_str("    pattern-sources:\n");
        for source in &config.sources {
            yaml.push_str(&self.taint_pattern_to_yaml(&source, "pattern"));
        }

        // Pattern sinks
        yaml.push_str("    pattern-sinks:\n");
        for sink in &config.sinks {
            yaml.push_str(&self.taint_pattern_to_yaml(&sink, "pattern"));
        }

        // Pattern sanitizers (optional)
        if !config.sanitizers.is_empty() {
            yaml.push_str("    pattern-sanitizers:\n");
            for sanitizer in &config.sanitizers {
                yaml.push_str(&self.taint_pattern_to_yaml(&sanitizer, "pattern"));
            }
        }

        // Pattern propagators (optional)
        if !config.propagators.is_empty() {
            yaml.push_str("    pattern-propagators:\n");
            for propagator in &config.propagators {
                yaml.push_str(&self.taint_propagator_to_yaml(propagator));
            }
        }

        yaml
    }

    /// Convert TaintPattern to YAML
    fn taint_pattern_to_yaml(&self, pattern: &TaintPattern, key: &str) -> String {
        let mut yaml = format!(
            "      - {}: |\n          {}\n",
            key,
            pattern.pattern.replace('\n', "\n          ")
        );

        if let Some(label) = &pattern.label {
            yaml.push_str(&format!("        label: {}\n", label));
        }
        if let Some(requires) = &pattern.requires {
            yaml.push_str(&format!("        requires: {}\n", requires));
        }

        yaml
    }

    /// Convert TaintPropagator to YAML
    fn taint_propagator_to_yaml(&self, propagator: &TaintPropagator) -> String {
        let mut yaml = format!(
            "      - pattern: |\n          {}\n",
            propagator.pattern.replace('\n', "\n          ")
        );
        yaml.push_str(&format!("        from: {}\n", propagator.from));
        yaml.push_str(&format!("        to: {}\n", propagator.to));
        if propagator.by_side_effect {
            yaml.push_str("        by-side-effect: true\n");
        }
        yaml
    }

    /// Parse Semgrep JSON output into Findings
    fn parse_output(
        &self,
        json_output: &str,
        rules: &[SemgrepRule],
    ) -> Result<Vec<Finding>, SemgrepError> {
        let output: super::output::SemgrepOutput = serde_json::from_str(json_output)
            .map_err(|e| SemgrepError::OutputParseError(format!("JSON parse error: {}", e)))?;

        // Build rule lookup map
        let rule_map: HashMap<&str, &SemgrepRule> =
            rules.iter().map(|r| (r.id.as_str(), r)).collect();

        let mut findings = Vec::new();

        for result in output.results {
            let severity = rule_map
                .get(result.check_id.as_str())
                .map(|r| r.severity.clone())
                .unwrap_or(Severity::Medium);

            let finding = Finding {
                id: format!(
                    "{}-{}-{}",
                    result.check_id,
                    result.path.replace(['/', '\\'], "_"),
                    result.start.line
                ),
                rule_id: result.check_id.clone(),
                location: Location {
                    file_path: result.path.clone(),
                    line: result.start.line,
                    column: Some(result.start.col),
                    end_line: Some(result.end.line),
                    end_column: Some(result.end.col),
                },
                severity,
                confidence: self.semgrep_to_confidence(&result.extra.severity),
                description: format!(
                    "{}\n\nMatched code:\n```\n{}\n```",
                    result.extra.message,
                    result.extra.lines.trim()
                ),
                recommendation: result.extra.fix.map(|f| format!("Suggested fix: {}", f)),
            };

            findings.push(finding);
        }

        debug!(finding_count = findings.len(), "Parsed Semgrep output");
        Ok(findings)
    }

    /// Convert Semgrep severity to Confidence
    fn semgrep_to_confidence(&self, severity: &str) -> Confidence {
        match severity.to_uppercase().as_str() {
            "ERROR" => Confidence::High,
            "WARNING" => Confidence::Medium,
            _ => Confidence::Low,
        }
    }
}

impl Default for SemgrepExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating SemgrepRule instances
pub struct SemgrepRuleBuilder {
    rule: SemgrepRule,
}

impl SemgrepRuleBuilder {
    /// Create a new builder with required fields
    pub fn new(id: impl Into<String>, name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            rule: SemgrepRule {
                id: id.into(),
                name: name.into(),
                message: message.into(),
                languages: vec![],
                severity: Severity::Medium,
                mode: SemgrepRuleMode::Search,
                pattern: None,
                patterns: None,
                taint_config: None,
                cwe_ids: vec![],
                owasp_categories: vec![],
                tags: vec![],
                fix: None,
                metadata: HashMap::new(),
            },
        }
    }

    /// Add languages
    pub fn languages(mut self, langs: Vec<Language>) -> Self {
        self.rule.languages = langs;
        self
    }

    /// Set severity
    pub fn severity(mut self, severity: Severity) -> Self {
        self.rule.severity = severity;
        self
    }

    /// Set search mode with pattern
    pub fn search_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.rule.mode = SemgrepRuleMode::Search;
        self.rule.pattern = Some(pattern.into());
        self
    }

    /// Set taint mode with configuration
    pub fn taint_config(mut self, config: TaintConfig) -> Self {
        self.rule.mode = SemgrepRuleMode::Taint;
        self.rule.taint_config = Some(config);
        self
    }

    /// Add CWE IDs
    pub fn cwe_ids(mut self, cwe_ids: Vec<String>) -> Self {
        self.rule.cwe_ids = cwe_ids;
        self
    }

    /// Add OWASP categories
    pub fn owasp_categories(mut self, categories: Vec<String>) -> Self {
        self.rule.owasp_categories = categories;
        self
    }

    /// Add tags
    pub fn tags(mut self, tags: Vec<String>) -> Self {
        self.rule.tags = tags;
        self
    }

    /// Set fix suggestion
    pub fn fix(mut self, fix: impl Into<String>) -> Self {
        self.rule.fix = Some(fix.into());
        self
    }

    /// Build the rule
    pub fn build(self) -> SemgrepRule {
        self.rule
    }
}

/// Helper to create a taint tracking rule for SQL injection
pub fn sql_injection_taint_rule(languages: Vec<Language>) -> SemgrepRule {
    SemgrepRuleBuilder::new(
        "sql-injection",
        "SQL Injection",
        "Potential SQL injection vulnerability. User input flows into SQL query without sanitization.",
    )
    .languages(languages)
    .severity(Severity::Critical)
    .taint_config(TaintConfig {
        sources: vec![
            TaintPattern {
                pattern: "request.args.get(...)".to_string(),
                label: Some("user_input".to_string()),
                requires: None,
            },
            TaintPattern {
                pattern: "request.form.get(...)".to_string(),
                label: Some("user_input".to_string()),
                requires: None,
            },
            TaintPattern {
                pattern: "request.params[...]".to_string(),
                label: Some("user_input".to_string()),
                requires: None,
            },
        ],
        sinks: vec![
            TaintPattern {
                pattern: "cursor.execute($QUERY, ...)".to_string(),
                label: None,
                requires: None,
            },
            TaintPattern {
                pattern: "db.execute($QUERY)".to_string(),
                label: None,
                requires: None,
            },
        ],
        sanitizers: vec![
            TaintPattern {
                pattern: "escape(...)".to_string(),
                label: None,
                requires: None,
            },
            TaintPattern {
                pattern: "sanitize(...)".to_string(),
                label: None,
                requires: None,
            },
        ],
        propagators: vec![],
    })
    .cwe_ids(vec!["CWE-89".to_string()])
    .owasp_categories(vec!["A03:2021 - Injection".to_string()])
    .tags(vec!["security".to_string(), "injection".to_string()])
    .build()
}

/// Helper to create a taint tracking rule for command injection
pub fn command_injection_taint_rule(languages: Vec<Language>) -> SemgrepRule {
    SemgrepRuleBuilder::new(
        "command-injection",
        "Command Injection",
        "Potential command injection vulnerability. User input flows into shell command.",
    )
    .languages(languages)
    .severity(Severity::Critical)
    .taint_config(TaintConfig {
        sources: vec![
            TaintPattern {
                pattern: "request.args.get(...)".to_string(),
                label: None,
                requires: None,
            },
            TaintPattern {
                pattern: "input(...)".to_string(),
                label: None,
                requires: None,
            },
            TaintPattern {
                pattern: "sys.argv[...]".to_string(),
                label: None,
                requires: None,
            },
        ],
        sinks: vec![
            TaintPattern {
                pattern: "os.system($CMD)".to_string(),
                label: None,
                requires: None,
            },
            TaintPattern {
                pattern: "subprocess.run($CMD, shell=True, ...)".to_string(),
                label: None,
                requires: None,
            },
            TaintPattern {
                pattern: "subprocess.call($CMD, shell=True, ...)".to_string(),
                label: None,
                requires: None,
            },
        ],
        sanitizers: vec![TaintPattern {
            pattern: "shlex.quote(...)".to_string(),
            label: None,
            requires: None,
        }],
        propagators: vec![],
    })
    .cwe_ids(vec!["CWE-78".to_string()])
    .owasp_categories(vec!["A03:2021 - Injection".to_string()])
    .tags(vec!["security".to_string(), "injection".to_string()])
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_builder() {
        let rule = SemgrepRuleBuilder::new("test-rule", "Test Rule", "Test message")
            .languages(vec![Language::Python])
            .severity(Severity::High)
            .search_pattern("eval(...)")
            .cwe_ids(vec!["CWE-95".to_string()])
            .build();

        assert_eq!(rule.id, "test-rule");
        assert_eq!(rule.languages, vec![Language::Python]);
        assert_eq!(rule.severity, Severity::High);
        assert_eq!(rule.pattern, Some("eval(...)".to_string()));
        assert_eq!(rule.mode, SemgrepRuleMode::Search);
    }

    #[test]
    fn test_taint_rule_builder() {
        let rule = sql_injection_taint_rule(vec![Language::Python]);

        assert_eq!(rule.id, "sql-injection");
        assert_eq!(rule.mode, SemgrepRuleMode::Taint);
        assert!(rule.taint_config.is_some());

        let taint = rule.taint_config.unwrap();
        assert!(!taint.sources.is_empty());
        assert!(!taint.sinks.is_empty());
    }

    #[test]
    fn test_rule_to_yaml() {
        let executor = SemgrepExecutor::new();
        let rule = SemgrepRuleBuilder::new("test", "Test", "Test message")
            .languages(vec![Language::Python])
            .search_pattern("eval(...)")
            .build();

        let yaml = executor.rule_to_yaml(&rule).unwrap();

        assert!(yaml.contains("id: test"));
        assert!(yaml.contains("languages: [python]"));
        assert!(yaml.contains("pattern:"));
        assert!(yaml.contains("eval(...)"));
    }

    #[test]
    fn test_taint_rule_to_yaml() {
        let executor = SemgrepExecutor::new();
        let rule = sql_injection_taint_rule(vec![Language::Python]);

        let yaml = executor.rule_to_yaml(&rule).unwrap();

        assert!(yaml.contains("mode: taint"));
        assert!(yaml.contains("pattern-sources:"));
        assert!(yaml.contains("pattern-sinks:"));
        assert!(yaml.contains("pattern-sanitizers:"));
    }
}
