//! Rule loader for loading rules from configuration files
//!
//! Supports:
//! - TOML/JSON native rule format
//! - YAML native rule format
//! - Semgrep-style YAML rules (subset: pattern, patterns, pattern-either, pattern-not)

use crate::domain::{Pattern, Rule, Severity};
use crate::domain::value_objects::Language;
use serde::Deserialize;
use std::path::Path;
use tracing::{debug, warn};

/// Trait for loading rules from various sources
pub trait RuleLoader: Send + Sync {
    fn load_rules(&self) -> Result<Vec<Rule>, RuleLoadError>;
}

/// Error type for rule loading
#[derive(Debug, thiserror::Error)]
pub enum RuleLoadError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),
    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),
    #[error("YAML parse error: {0}")]
    YamlParse(#[from] serde_yml::Error),
    #[error("Invalid rule: {0}")]
    InvalidRule(String),
    #[error("Unsupported Semgrep rule: {0}")]
    UnsupportedSemgrep(String),
}

/// File-based rule loader supporting TOML, JSON, and YAML formats
pub struct FileRuleLoader {
    file_path: std::path::PathBuf,
}

impl FileRuleLoader {
    pub fn new<P: AsRef<Path>>(file_path: P) -> Self {
        Self {
            file_path: file_path.as_ref().to_path_buf(),
        }
    }
}

impl RuleLoader for FileRuleLoader {
    fn load_rules(&self) -> Result<Vec<Rule>, RuleLoadError> {
        let content = std::fs::read_to_string(&self.file_path)?;
        let extension = self
            .file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let rules = match extension.as_str() {
            "json" => {
                debug!(file = %self.file_path.display(), "Loading rules from JSON file");
                let rules_file: RulesFile = serde_json::from_str(&content)?;
                rules_file.rules
            }
            "yaml" | "yml" => {
                debug!(file = %self.file_path.display(), "Loading rules from YAML file");
                load_yaml_rules(&content)?
            }
            _ => {
                debug!(file = %self.file_path.display(), "Loading rules from TOML file");
                let rules_file: RulesFile = toml::from_str(&content)?;
                rules_file.rules
            }
        };

        // Validate rules
        let mut validated_rules = Vec::new();
        for rule in rules {
            match validate_rule(&rule) {
                Ok(_) => validated_rules.push(rule),
                Err(e) => {
                    warn!(rule_id = %rule.id, error = %e, "Skipping invalid rule");
                }
            }
        }

        debug!(rule_count = validated_rules.len(), "Loaded rules from file");
        Ok(validated_rules)
    }
}

/// Rules file structure for TOML/JSON/YAML deserialization (native format)
#[derive(Debug, Deserialize)]
struct RulesFile {
    rules: Vec<Rule>,
}

/// Semgrep rules file structure
#[derive(Debug, Deserialize)]
struct SemgrepRulesFile {
    rules: Vec<SemgrepRule>,
}

/// Semgrep rule (subset supported)
#[derive(Debug, Deserialize)]
struct SemgrepRule {
    id: String,
    message: Option<String>,
    severity: Option<String>,
    languages: Vec<String>,
    #[serde(rename = "pattern")]
    pattern: Option<String>,
    #[serde(rename = "patterns")]
    patterns: Option<Vec<SemgrepPattern>>,
    #[serde(rename = "pattern-either")]
    pattern_either: Option<Vec<SemgrepPattern>>,
    #[serde(rename = "pattern-not")]
    pattern_not: Option<String>,
    #[serde(default)]
    metadata: Option<serde_yml::Value>,
    #[serde(default)]
    fix: Option<String>,
}

/// Semgrep pattern in list contexts (patterns / pattern-either)
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SemgrepPattern {
    String(String),
    Object(SemgrepPatternObject),
}

#[derive(Debug, Deserialize)]
struct SemgrepPatternObject {
    #[serde(rename = "pattern")]
    pattern: Option<String>,
    #[serde(rename = "pattern-not")]
    pattern_not: Option<String>,
    #[serde(rename = "pattern-either")]
    pattern_either: Option<Vec<SemgrepPattern>>,
    #[serde(rename = "patterns")]
    patterns: Option<Vec<SemgrepPattern>>,
}

fn load_yaml_rules(content: &str) -> Result<Vec<Rule>, RuleLoadError> {
    // Try Semgrep first
    let semgrep_attempt: Result<SemgrepRulesFile, serde_yml::Error> = serde_yml::from_str(content);
    if let Ok(semgrep_file) = semgrep_attempt {
        if !semgrep_file.rules.is_empty()
            && semgrep_file
                .rules
                .iter()
                .all(|r| !r.id.is_empty() && !r.languages.is_empty())
        {
            return semgrep_file
                .rules
                .into_iter()
                .map(semgrep_rule_to_rule)
                .collect();
        }
    }

    // Fallback to native YAML rules format
    let rules_file: RulesFile = serde_yml::from_str(content)?;
    Ok(rules_file.rules)
}

fn semgrep_rule_to_rule(rule: SemgrepRule) -> Result<Rule, RuleLoadError> {
    let languages = parse_languages(&rule.languages)?;
    let severity = parse_severity(rule.severity.as_deref());
    let (tags, cwe_ids, owasp_categories) = parse_metadata(rule.metadata.as_ref());

    let base_pattern = resolve_semgrep_pattern(&rule)?;
    let full_pattern = if let Some(neg) = rule.pattern_not {
        let neg_pattern = Pattern::Not(Box::new(Pattern::Metavariable(neg)));
        Pattern::AllOf(vec![base_pattern, neg_pattern])
    } else {
        base_pattern
    };

    Ok(Rule {
        id: rule.id.clone(),
        name: rule.id.clone(),
        description: rule.message.clone().unwrap_or_else(|| rule.id.clone()),
        severity,
        languages,
        pattern: full_pattern,
        options: Default::default(),
        cwe_ids,
        owasp_categories,
        tags,
        message: rule.message,
        fix: rule.fix,
    })
}

fn resolve_semgrep_pattern(rule: &SemgrepRule) -> Result<Pattern, RuleLoadError> {
    if let Some(pattern) = rule.pattern.as_ref() {
        return Ok(Pattern::Metavariable(pattern.clone()));
    }

    if let Some(patterns) = rule.patterns.as_ref() {
        let mut converted = Vec::new();
        for p in patterns {
            converted.push(convert_semgrep_pattern(p)?);
        }
        return Ok(Pattern::AllOf(converted));
    }

    if let Some(patterns) = rule.pattern_either.as_ref() {
        let mut converted = Vec::new();
        for p in patterns {
            converted.push(convert_semgrep_pattern(p)?);
        }
        return Ok(Pattern::AnyOf(converted));
    }

    Err(RuleLoadError::UnsupportedSemgrep(
        "Semgrep rule must include one of: pattern, patterns, pattern-either".to_string(),
    ))
}

fn convert_semgrep_pattern(pattern: &SemgrepPattern) -> Result<Pattern, RuleLoadError> {
    match pattern {
        SemgrepPattern::String(p) => Ok(Pattern::Metavariable(p.clone())),
        SemgrepPattern::Object(obj) => {
            if let Some(pattern) = obj.pattern.as_ref() {
                return Ok(Pattern::Metavariable(pattern.clone()));
            }

            if let Some(patterns) = obj.patterns.as_ref() {
                let mut converted = Vec::new();
                for p in patterns {
                    converted.push(convert_semgrep_pattern(p)?);
                }
                return Ok(Pattern::AllOf(converted));
            }

            if let Some(patterns) = obj.pattern_either.as_ref() {
                let mut converted = Vec::new();
                for p in patterns {
                    converted.push(convert_semgrep_pattern(p)?);
                }
                return Ok(Pattern::AnyOf(converted));
            }

            if let Some(neg) = obj.pattern_not.as_ref() {
                return Ok(Pattern::Not(Box::new(Pattern::Metavariable(neg.clone()))));
            }

            Err(RuleLoadError::UnsupportedSemgrep(
                "Semgrep pattern object missing supported fields".to_string(),
            ))
        }
    }
}

fn parse_languages(languages: &[String]) -> Result<Vec<Language>, RuleLoadError> {
    let mut result = Vec::new();
    for lang in languages {
        let normalized = lang.to_ascii_lowercase();
        let mapped = match normalized.as_str() {
            "python" | "py" => Some(Language::Python),
            "javascript" | "js" | "nodejs" => Some(Language::JavaScript),
            "typescript" | "ts" => Some(Language::TypeScript),
            "rust" | "rs" => Some(Language::Rust),
            "go" | "golang" => Some(Language::Go),
            "c" => Some(Language::C),
            "cpp" | "c++" | "cplusplus" => Some(Language::Cpp),
            _ => None,
        };

        if let Some(lang) = mapped {
            result.push(lang);
        } else {
            return Err(RuleLoadError::InvalidRule(format!(
                "Unsupported language '{}'",
                lang
            )));
        }
    }
    Ok(result)
}

fn parse_severity(sev: Option<&str>) -> Severity {
    match sev.map(|s| s.to_ascii_lowercase()) {
        Some(ref s) if s == "critical" => Severity::Critical,
        Some(ref s) if s == "high" || s == "error" => Severity::High,
        Some(ref s) if s == "medium" || s == "warning" => Severity::Medium,
        Some(ref s) if s == "low" => Severity::Low,
        Some(ref s) if s == "info" => Severity::Info,
        _ => Severity::Medium,
    }
}

fn parse_metadata(metadata: Option<&serde_yml::Value>) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut tags = Vec::new();
    let mut cwe_ids = Vec::new();
    let mut owasp_categories = Vec::new();

    let Some(serde_yml::Value::Mapping(map)) = metadata else {
        return (tags, cwe_ids, owasp_categories);
    };

    for (key, value) in map {
        let key_str = match key.as_str() {
            Some(s) => s,
            None => continue,
        };

        match key_str {
            "tags" => tags.extend(value_to_string_list(value)),
            "cwe" | "cwe_id" | "cwe_ids" => cwe_ids.extend(value_to_string_list(value)),
            "owasp" | "owasp_categories" => owasp_categories.extend(value_to_string_list(value)),
            _ => {}
        }
    }

    (tags, cwe_ids, owasp_categories)
}

fn value_to_string_list(value: &serde_yml::Value) -> Vec<String> {
    match value {
        serde_yml::Value::String(s) => vec![s.clone()],
        serde_yml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        serde_yml::Value::Mapping(map) => map
            .values()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

/// Validate a rule for correctness
fn validate_rule(rule: &Rule) -> Result<(), String> {
    if rule.id.is_empty() {
        return Err("Rule ID cannot be empty".to_string());
    }
    if rule.name.is_empty() {
        return Err("Rule name cannot be empty".to_string());
    }
    if rule.languages.is_empty() {
        return Err("Rule must specify at least one language".to_string());
    }

    // Validate pattern based on type
    match &rule.pattern {
        Pattern::TreeSitterQuery(query) => {
            if query.is_empty() {
                return Err("Tree-sitter query pattern cannot be empty".to_string());
            }
        }
        Pattern::Metavariable(pattern) => {
            if pattern.is_empty() {
                return Err("Metavariable pattern cannot be empty".to_string());
            }
        }
        Pattern::AnyOf(patterns) => {
            if patterns.is_empty() {
                return Err("AnyOf pattern must contain at least one sub-pattern".to_string());
            }
        }
        Pattern::AllOf(patterns) => {
            if patterns.is_empty() {
                return Err("AllOf pattern must contain at least one sub-pattern".to_string());
            }
        }
        Pattern::Not(_) => {
            // Not pattern is always valid if it has a sub-pattern
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Pattern, Severity};
    use crate::domain::value_objects::Language;

    #[test]
    fn test_semgrep_single_pattern_rule() {
        let yaml = r#"
rules:
  - id: test-single
    message: "Use of foo"
    severity: "high"
    languages: ["python"]
    pattern: "$X.foo()"
"#;

        let rules = load_yaml_rules(yaml).expect("Should parse YAML");
        assert_eq!(rules.len(), 1);

        let rule = &rules[0];
        assert_eq!(rule.id, "test-single");
        assert_eq!(rule.severity, Severity::High);
        assert_eq!(rule.languages, vec![Language::Python]);

        match &rule.pattern {
            Pattern::Metavariable(p) => assert_eq!(p, "$X.foo()"),
            other => panic!("Unexpected pattern: {:?}", other),
        }
    }

    #[test]
    fn test_semgrep_patterns_allof() {
        let yaml = r#"
rules:
  - id: test-allof
    languages: ["python"]
    message: "All-of patterns"
    patterns:
      - pattern: "foo($X)"
      - pattern: "bar($Y)"
"#;

        let rules = load_yaml_rules(yaml).expect("Should parse YAML");
        assert_eq!(rules.len(), 1);

        match &rules[0].pattern {
            Pattern::AllOf(patterns) => {
                assert_eq!(patterns.len(), 2);
                assert!(matches!(&patterns[0], Pattern::Metavariable(_)));
                assert!(matches!(&patterns[1], Pattern::Metavariable(_)));
            }
            other => panic!("Unexpected pattern: {:?}", other),
        }
    }

    #[test]
    fn test_semgrep_pattern_either_anyof() {
        let yaml = r#"
rules:
  - id: test-anyof
    languages: ["python"]
    message: "Any-of patterns"
    pattern-either:
      - pattern: "foo($X)"
      - pattern: "bar($Y)"
"#;

        let rules = load_yaml_rules(yaml).expect("Should parse YAML");
        assert_eq!(rules.len(), 1);

        match &rules[0].pattern {
            Pattern::AnyOf(patterns) => {
                assert_eq!(patterns.len(), 2);
                assert!(matches!(&patterns[0], Pattern::Metavariable(_)));
                assert!(matches!(&patterns[1], Pattern::Metavariable(_)));
            }
            other => panic!("Unexpected pattern: {:?}", other),
        }
    }

    #[test]
    fn test_semgrep_pattern_not_wraps_allof() {
        let yaml = r#"
rules:
  - id: test-not
    languages: ["python"]
    message: "Negation"
    pattern: "foo($X)"
    pattern-not: "bar($X)"
"#;

        let rules = load_yaml_rules(yaml).expect("Should parse YAML");
        assert_eq!(rules.len(), 1);

        match &rules[0].pattern {
            Pattern::AllOf(patterns) => {
                assert_eq!(patterns.len(), 2);
                assert!(matches!(&patterns[0], Pattern::Metavariable(_)));
                assert!(matches!(&patterns[1], Pattern::Not(_)));
            }
            other => panic!("Unexpected pattern: {:?}", other),
        }
    }

    #[test]
    fn test_semgrep_metadata_mapping() {
        let yaml = r#"
rules:
  - id: test-meta
    languages: ["python"]
    message: "Metadata mapping"
    pattern: "foo($X)"
    metadata:
      tags: ["web", "injection"]
      cwe: ["CWE-79"]
      owasp: ["A03:2021 - Injection"]
"#;

        let rules = load_yaml_rules(yaml).expect("Should parse YAML");
        assert_eq!(rules.len(), 1);

        let rule = &rules[0];
        assert_eq!(rule.tags, vec!["web".to_string(), "injection".to_string()]);
        assert_eq!(rule.cwe_ids, vec!["CWE-79".to_string()]);
        assert_eq!(
            rule.owasp_categories,
            vec!["A03:2021 - Injection".to_string()]
        );
    }

    #[test]
    fn test_semgrep_pattern_object_not_in_patterns() {
        let yaml = r#"
rules:
  - id: test-not-object
    languages: ["python"]
    message: "Negated object"
    patterns:
      - pattern-not: "foo($X)"
"#;

        let rules = load_yaml_rules(yaml).expect("Should parse YAML");
        assert_eq!(rules.len(), 1);

        match &rules[0].pattern {
            Pattern::AllOf(patterns) => {
                assert_eq!(patterns.len(), 1);
                assert!(matches!(&patterns[0], Pattern::Not(_)));
            }
            other => panic!("Unexpected pattern: {:?}", other),
        }
    }

    #[test]
    fn test_semgrep_missing_pattern_error() {
        let yaml = r#"
rules:
  - id: test-missing
    languages: ["python"]
    message: "Missing pattern"
"#;

        let err = load_yaml_rules(yaml).expect_err("Should fail on missing pattern");
        match err {
            RuleLoadError::UnsupportedSemgrep(_) => {}
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_semgrep_unsupported_language_error() {
        let yaml = r#"
rules:
  - id: test-unsupported-lang
    languages: ["ruby"]
    message: "Unsupported language"
    pattern: "foo($X)"
"#;

        let err = load_yaml_rules(yaml).expect_err("Should fail on unsupported language");
        match err {
            RuleLoadError::InvalidRule(_) => {}
            other => panic!("Unexpected error: {:?}", other),
        }
    }
}
