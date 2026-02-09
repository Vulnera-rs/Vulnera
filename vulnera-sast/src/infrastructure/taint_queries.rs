//! Production-ready taint detection queries
//!
//! Tree-sitter S-expression queries for detecting:
//! - Taint sources (user input, file I/O, environment)
//! - Taint sinks (dangerous functions where tainted data is risky)
//! - Sanitizers (functions that clean/validate tainted data)
//!
//! Supports custom patterns via TaintConfig for framework-specific sources.

use crate::domain::value_objects::Language;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// =============================================================================
// TaintConfig Error Types
// =============================================================================

/// Errors that can occur when loading or processing taint configuration
#[derive(Debug, thiserror::Error)]
pub enum TaintConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),
    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),
    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),
    #[error("Unsupported file format: {0}")]
    UnsupportedFormat(String),
}

// =============================================================================
// TaintConfig - Customizable taint patterns
// =============================================================================

/// Configuration for taint tracking with custom sources/sinks/sanitizers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintConfig {
    /// Custom taint sources per language
    #[serde(default)]
    pub custom_sources: HashMap<String, Vec<TaintPattern>>,
    /// Custom taint sinks per language
    #[serde(default)]
    pub custom_sinks: HashMap<String, Vec<TaintPattern>>,
    /// Custom sanitizers per language
    #[serde(default)]
    pub custom_sanitizers: HashMap<String, Vec<TaintPattern>>,
    /// Whether to include built-in patterns
    #[serde(default = "default_true")]
    pub include_builtin: bool,
    /// Confidence threshold for generic validation (0.0-1.0)
    /// Generic validators reduce confidence instead of clearing taint
    #[serde(default = "default_generic_confidence")]
    pub generic_validation_confidence: f32,
}

fn default_true() -> bool {
    true
}

fn default_generic_confidence() -> f32 {
    0.5
}

impl Default for TaintConfig {
    fn default() -> Self {
        Self {
            custom_sources: HashMap::new(),
            custom_sinks: HashMap::new(),
            custom_sanitizers: HashMap::new(),
            include_builtin: true,
            generic_validation_confidence: 0.5,
        }
    }
}

impl TaintConfig {
    /// Create a new empty taint configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Load taint configuration from a file (TOML or JSON)
    ///
    /// File format is determined by extension:
    /// - `.toml` -> TOML format
    /// - `.json` -> JSON format
    ///
    /// # Example TOML format:
    /// ```toml
    /// include_builtin = true
    /// generic_validation_confidence = 0.6
    ///
    /// [[custom_sources.python]]
    /// query = "(call function: (identifier) @fn (#eq? @fn \"get_user_input\"))"
    /// name = "custom_user_input"
    /// category = "user_input"
    /// labels = ["user_controlled"]
    /// ```
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, TaintConfigError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;

        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|s| s.to_lowercase());

        match extension.as_deref() {
            Some("toml") => {
                let config: TaintConfig = toml::from_str(&content)?;
                config.validate()?;
                Ok(config)
            }
            Some("json") => {
                let config: TaintConfig = serde_json::from_str(&content)?;
                config.validate()?;
                Ok(config)
            }
            Some(ext) => Err(TaintConfigError::UnsupportedFormat(format!(
                "Unsupported extension: .{}",
                ext
            ))),
            None => Err(TaintConfigError::UnsupportedFormat(
                "No file extension provided".to_string(),
            )),
        }
    }

    /// Merge another configuration into this one
    ///
    /// Custom patterns from `other` are appended to existing patterns.
    /// Configuration flags (include_builtin, confidence) are taken from `other`.
    pub fn merge(&mut self, other: TaintConfig) {
        // Merge custom sources
        for (lang, patterns) in other.custom_sources {
            self.custom_sources
                .entry(lang)
                .or_default()
                .extend(patterns);
        }

        // Merge custom sinks
        for (lang, patterns) in other.custom_sinks {
            self.custom_sinks.entry(lang).or_default().extend(patterns);
        }

        // Merge custom sanitizers
        for (lang, patterns) in other.custom_sanitizers {
            self.custom_sanitizers
                .entry(lang)
                .or_default()
                .extend(patterns);
        }

        // Override flags with other's values
        self.include_builtin = other.include_builtin;
        self.generic_validation_confidence = other.generic_validation_confidence;
    }

    /// Validate the configuration
    fn validate(&self) -> Result<(), TaintConfigError> {
        // Validate all patterns have non-empty queries
        for (lang, patterns) in &self.custom_sources {
            for pattern in patterns {
                if pattern.query.trim().is_empty() {
                    return Err(TaintConfigError::InvalidPattern(format!(
                        "Empty query in source pattern '{}' for language '{}'",
                        pattern.name, lang
                    )));
                }
            }
        }

        for (lang, patterns) in &self.custom_sinks {
            for pattern in patterns {
                if pattern.query.trim().is_empty() {
                    return Err(TaintConfigError::InvalidPattern(format!(
                        "Empty query in sink pattern '{}' for language '{}'",
                        pattern.name, lang
                    )));
                }
            }
        }

        for (lang, patterns) in &self.custom_sanitizers {
            for pattern in patterns {
                if pattern.query.trim().is_empty() {
                    return Err(TaintConfigError::InvalidPattern(format!(
                        "Empty query in sanitizer pattern '{}' for language '{}'",
                        pattern.name, lang
                    )));
                }
            }
        }

        // Validate confidence threshold
        if !(0.0..=1.0).contains(&self.generic_validation_confidence) {
            return Err(TaintConfigError::InvalidPattern(format!(
                "generic_validation_confidence must be between 0.0 and 1.0, got {}",
                self.generic_validation_confidence
            )));
        }

        Ok(())
    }

    /// Get all source patterns for a language (built-in + custom)
    pub fn get_sources_for_language(&self, language: &Language) -> Vec<TaintPattern> {
        get_source_queries(language, self)
    }

    /// Get all sink patterns for a language (built-in + custom)
    pub fn get_sinks_for_language(&self, language: &Language) -> Vec<TaintPattern> {
        get_sink_queries(language, self)
    }

    /// Get all sanitizer patterns for a language (built-in + custom)
    pub fn get_sanitizers_for_language(&self, language: &Language) -> Vec<TaintPattern> {
        get_sanitizer_queries(language, self)
    }
}

/// A taint pattern with query and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPattern {
    /// Tree-sitter S-expression query
    pub query: String,
    /// Human-readable name
    pub name: String,
    /// Category (e.g., "user_input", "file_io", "sql", "xss")
    pub category: String,
    /// Whether this is a known/strong pattern (vs generic)
    /// Known sanitizers clear taint; generic ones only reduce confidence
    #[serde(default = "default_true")]
    pub is_known: bool,
    /// Labels that this pattern introduces (for labeled taint tracking)
    #[serde(default)]
    pub labels: Vec<String>,
    /// For sanitizers: which labels this clears (None = all)
    #[serde(default)]
    pub clears_labels: Option<Vec<String>>,
}

impl TaintPattern {
    /// Create a new source pattern
    pub fn source(query: &str, name: &str, category: &str, labels: Vec<&str>) -> Self {
        Self {
            query: query.to_string(),
            name: name.to_string(),
            category: category.to_string(),
            is_known: true,
            labels: labels.into_iter().map(|s| s.to_string()).collect(),
            clears_labels: None,
        }
    }

    /// Create a new sink pattern
    pub fn sink(query: &str, name: &str, category: &str) -> Self {
        Self {
            query: query.to_string(),
            name: name.to_string(),
            category: category.to_string(),
            is_known: true,
            labels: vec![],
            clears_labels: None,
        }
    }

    /// Create a known sanitizer that clears taint
    pub fn sanitizer(query: &str, name: &str, category: &str) -> Self {
        Self {
            query: query.to_string(),
            name: name.to_string(),
            category: category.to_string(),
            is_known: true,
            labels: vec![],
            clears_labels: Some(vec![]), // Empty = clears all labels
        }
    }

    /// Create a generic sanitizer that only reduces confidence
    pub fn generic_sanitizer(query: &str, name: &str, category: &str) -> Self {
        Self {
            query: query.to_string(),
            name: name.to_string(),
            category: category.to_string(),
            is_known: false, // Generic = reduce confidence only
            labels: vec![],
            clears_labels: None, // None = doesn't clear, just reduces confidence
        }
    }
}

// =============================================================================
// Query Result Types
// =============================================================================

/// Result of a taint detection query
#[derive(Debug, Clone)]
pub struct TaintDetection {
    /// Type of detection
    pub detection_type: TaintDetectionType,
    /// Pattern name that matched
    pub pattern_name: String,
    /// Category of the taint
    pub category: String,
    /// Line number (1-indexed)
    pub line: u32,
    /// Column number
    pub column: u32,
    /// End line
    pub end_line: u32,
    /// End column
    pub end_column: u32,
    /// The matched expression/variable
    pub expression: String,
    /// Labels associated with this detection
    pub labels: Vec<String>,
    /// Whether this is a known pattern (vs generic heuristic)
    pub is_known: bool,
    /// For sanitizers: which labels this clears
    pub clears_labels: Option<Vec<String>>,
}

/// Type of taint detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintDetectionType {
    Source,
    Sink,
    Sanitizer,
}

// =============================================================================
// Built-in Taint Patterns (loaded from embedded TOML)
// =============================================================================

/// Embedded taint pattern TOML data (compile-time).
const PYTHON_TAINT_TOML: &str = include_str!("../../taint-patterns/python.toml");
const JAVASCRIPT_TAINT_TOML: &str = include_str!("../../taint-patterns/javascript.toml");
const GO_TAINT_TOML: &str = include_str!("../../taint-patterns/go.toml");
const RUST_TAINT_TOML: &str = include_str!("../../taint-patterns/rust.toml");
const C_CPP_TAINT_TOML: &str = include_str!("../../taint-patterns/c_cpp.toml");

/// Deserialization target for a taint-pattern TOML file.
#[derive(Debug, Deserialize)]
struct BuiltinTaintFile {
    #[serde(default)]
    sources: Vec<TaintPattern>,
    #[serde(default)]
    sinks: Vec<TaintPattern>,
    #[serde(default)]
    sanitizers: Vec<TaintPattern>,
}

fn load_taint_file(toml_str: &str, label: &str) -> BuiltinTaintFile {
    match toml::from_str::<BuiltinTaintFile>(toml_str) {
        Ok(file) => {
            tracing::debug!(
                sources = file.sources.len(),
                sinks = file.sinks.len(),
                sanitizers = file.sanitizers.len(),
                language = label,
                "Loaded taint patterns from embedded TOML"
            );
            file
        }
        Err(e) => {
            tracing::warn!(error = %e, language = label, "Failed to parse embedded taint TOML");
            BuiltinTaintFile {
                sources: Vec::new(),
                sinks: Vec::new(),
                sanitizers: Vec::new(),
            }
        }
    }
}

/// Get built-in source patterns for a language.
pub fn python_source_queries() -> Vec<TaintPattern> {
    load_taint_file(PYTHON_TAINT_TOML, "python").sources
}
pub fn python_sink_queries() -> Vec<TaintPattern> {
    load_taint_file(PYTHON_TAINT_TOML, "python").sinks
}
pub fn python_sanitizer_queries() -> Vec<TaintPattern> {
    load_taint_file(PYTHON_TAINT_TOML, "python").sanitizers
}

pub fn javascript_source_queries() -> Vec<TaintPattern> {
    load_taint_file(JAVASCRIPT_TAINT_TOML, "javascript").sources
}
pub fn javascript_sink_queries() -> Vec<TaintPattern> {
    load_taint_file(JAVASCRIPT_TAINT_TOML, "javascript").sinks
}
pub fn javascript_sanitizer_queries() -> Vec<TaintPattern> {
    load_taint_file(JAVASCRIPT_TAINT_TOML, "javascript").sanitizers
}

pub fn go_source_queries() -> Vec<TaintPattern> {
    load_taint_file(GO_TAINT_TOML, "go").sources
}
pub fn go_sink_queries() -> Vec<TaintPattern> {
    load_taint_file(GO_TAINT_TOML, "go").sinks
}
pub fn go_sanitizer_queries() -> Vec<TaintPattern> {
    load_taint_file(GO_TAINT_TOML, "go").sanitizers
}

pub fn rust_source_queries() -> Vec<TaintPattern> {
    load_taint_file(RUST_TAINT_TOML, "rust").sources
}
pub fn rust_sink_queries() -> Vec<TaintPattern> {
    load_taint_file(RUST_TAINT_TOML, "rust").sinks
}
pub fn rust_sanitizer_queries() -> Vec<TaintPattern> {
    load_taint_file(RUST_TAINT_TOML, "rust").sanitizers
}

pub fn c_source_queries() -> Vec<TaintPattern> {
    load_taint_file(C_CPP_TAINT_TOML, "c_cpp").sources
}
pub fn c_sink_queries() -> Vec<TaintPattern> {
    load_taint_file(C_CPP_TAINT_TOML, "c_cpp").sinks
}
pub fn c_sanitizer_queries() -> Vec<TaintPattern> {
    load_taint_file(C_CPP_TAINT_TOML, "c_cpp").sanitizers
}

// =============================================================================
// Query Provider
// =============================================================================

/// Get all source queries for a language (built-in + custom)
pub fn get_source_queries(language: &Language, config: &TaintConfig) -> Vec<TaintPattern> {
    let mut queries = Vec::new();

    if config.include_builtin {
        queries.extend(match language {
            Language::Python => python_source_queries(),
            Language::JavaScript | Language::TypeScript => javascript_source_queries(),
            Language::Go => go_source_queries(),
            Language::Rust => rust_source_queries(),
            Language::C | Language::Cpp => c_source_queries(),
        });
    }

    // Add custom sources
    let lang_key = format!("{:?}", language).to_lowercase();
    if let Some(custom) = config.custom_sources.get(&lang_key) {
        queries.extend(custom.clone());
    }

    queries
}

/// Get all sink queries for a language (built-in + custom)
pub fn get_sink_queries(language: &Language, config: &TaintConfig) -> Vec<TaintPattern> {
    let mut queries = Vec::new();

    if config.include_builtin {
        queries.extend(match language {
            Language::Python => python_sink_queries(),
            Language::JavaScript | Language::TypeScript => javascript_sink_queries(),
            Language::Go => go_sink_queries(),
            Language::Rust => rust_sink_queries(),
            Language::C | Language::Cpp => c_sink_queries(),
        });
    }

    // Add custom sinks
    let lang_key = format!("{:?}", language).to_lowercase();
    if let Some(custom) = config.custom_sinks.get(&lang_key) {
        queries.extend(custom.clone());
    }

    queries
}

/// Get assignment propagation queries for a language
/// These patterns detect when tainted data is assigned to new variables
pub fn get_propagation_queries(language: &Language) -> Vec<&'static str> {
    match language {
        Language::Python => vec![
            // Variable assignment: x = tainted_expr
            r#"(assignment
              left: (identifier) @target
              right: (_) @source
            )"#,
            // Augmented assignment: x += tainted_expr
            r#"(augmented_assignment
              left: (identifier) @target
              right: (_) @source
            )"#,
        ],
        Language::JavaScript | Language::TypeScript => vec![
            // Variable declaration with initialization: const x = tainted_expr
            r#"(variable_declarator
              name: (identifier) @target
              value: (_) @source
            )"#,
            // Assignment expression: x = tainted_expr
            r#"(assignment_expression
              left: (identifier) @target
              right: (_) @source
            )"#,
        ],
        Language::Go => vec![
            // Short variable declaration: x := tainted_expr
            r#"(short_var_declaration
              left: (expression_list (identifier) @target)
              right: (expression_list (_) @source)
            )"#,
            // Assignment: x = tainted_expr
            r#"(assignment_statement
              left: (expression_list (identifier) @target)
              right: (expression_list (_) @source)
            )"#,
        ],
        Language::Rust => vec![
            // Let binding: let x = tainted_expr
            r#"(let_declaration
              pattern: (identifier) @target
              value: (_) @source
            )"#,
        ],
        Language::C | Language::Cpp => vec![
            // Variable declaration: int x = tainted_expr
            r#"(init_declarator
              declarator: (identifier) @target
              value: (_) @source
            )"#,
            // Assignment: x = tainted_expr
            r#"(assignment_expression
              left: (identifier) @target
              right: (_) @source
            )"#,
        ],
    }
}

/// Get all sanitizer queries for a language (built-in + custom)
pub fn get_sanitizer_queries(language: &Language, config: &TaintConfig) -> Vec<TaintPattern> {
    let mut queries = Vec::new();

    if config.include_builtin {
        queries.extend(match language {
            Language::Python => python_sanitizer_queries(),
            Language::JavaScript | Language::TypeScript => javascript_sanitizer_queries(),
            Language::Go => go_sanitizer_queries(),
            Language::Rust => rust_sanitizer_queries(),
            Language::C | Language::Cpp => c_sanitizer_queries(),
        });
    }

    // Add custom sanitizers
    let lang_key = format!("{:?}", language).to_lowercase();
    if let Some(custom) = config.custom_sanitizers.get(&lang_key) {
        queries.extend(custom.clone());
    }

    queries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TaintConfig::default();
        assert!(config.include_builtin);
        assert!(config.custom_sources.is_empty());
        assert!((config.generic_validation_confidence - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn test_python_sources_not_empty() {
        let sources = python_source_queries();
        assert!(!sources.is_empty());
        assert!(sources.iter().any(|s| s.category == "user_input"));
    }

    #[test]
    fn test_python_sinks_not_empty() {
        let sinks = python_sink_queries();
        assert!(!sinks.is_empty());
        assert!(sinks.iter().any(|s| s.category == "sql_injection"));
    }

    #[test]
    fn test_python_sanitizers_not_empty() {
        let sanitizers = python_sanitizer_queries();
        assert!(!sanitizers.is_empty());
        // Check we have both known and generic sanitizers
        assert!(sanitizers.iter().any(|s| s.is_known));
        assert!(sanitizers.iter().any(|s| !s.is_known));
    }

    #[test]
    fn test_get_queries_with_custom() {
        let mut config = TaintConfig::default();
        config.custom_sources.insert(
            "python".to_string(),
            vec![TaintPattern::source(
                "(identifier) @custom",
                "Custom source",
                "custom",
                vec!["custom"],
            )],
        );

        let sources = get_source_queries(&Language::Python, &config);
        assert!(sources.iter().any(|s| s.name == "Custom source"));
    }

    #[test]
    fn test_sanitizer_types() {
        // Known sanitizer should have clears_labels
        let known = TaintPattern::sanitizer("query", "test", "xss");
        assert!(known.is_known);
        assert!(known.clears_labels.is_some());

        // Generic sanitizer should NOT clear labels
        let generic = TaintPattern::generic_sanitizer("query", "test", "generic");
        assert!(!generic.is_known);
        assert!(generic.clears_labels.is_none());
    }

    #[test]
    fn test_all_languages_have_queries() {
        let config = TaintConfig::default();
        let languages = vec![
            Language::Python,
            Language::JavaScript,
            Language::TypeScript,
            Language::Go,
            Language::Rust,
            Language::C,
            Language::Cpp,
        ];

        for lang in languages {
            let sources = get_source_queries(&lang, &config);
            let sinks = get_sink_queries(&lang, &config);
            let sanitizers = get_sanitizer_queries(&lang, &config);

            assert!(!sources.is_empty(), "No sources for {:?}", lang);
            assert!(!sinks.is_empty(), "No sinks for {:?}", lang);
            assert!(!sanitizers.is_empty(), "No sanitizers for {:?}", lang);
        }
    }
}
