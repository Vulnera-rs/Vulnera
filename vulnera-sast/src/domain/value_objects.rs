//! SAST value objects

use serde::{Deserialize, Serialize};
use std::fmt;

/// Programming language
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Language {
    Python,
    JavaScript,
    Rust,
    Go,
    C,
    Cpp,
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Language::Python => write!(f, "python"),
            Language::JavaScript => write!(f, "javascript"),
            Language::Rust => write!(f, "rust"),
            Language::Go => write!(f, "go"),
            Language::C => write!(f, "c"),
            Language::Cpp => write!(f, "cpp"),
        }
    }
}

impl Language {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "py" => Some(Language::Python),
            "js" | "jsx" | "ts" | "tsx" => Some(Language::JavaScript),
            "rs" => Some(Language::Rust),
            "go" => Some(Language::Go),
            "c" | "h" => Some(Language::C),
            "cpp" | "hpp" | "cc" | "cxx" => Some(Language::Cpp),
            _ => None,
        }
    }

    pub fn from_filename(filename: &str) -> Option<Self> {
        std::path::Path::new(filename)
            .extension()
            .and_then(|ext| ext.to_str())
            .and_then(Self::from_extension)
    }

    /// Convert to Semgrep language identifier
    pub fn to_semgrep_id(&self) -> &'static str {
        match self {
            Language::Python => "python",
            Language::JavaScript => "javascript",
            Language::Rust => "rust",
            Language::Go => "go",
            Language::C => "c",
            Language::Cpp => "cpp",
        }
    }

    /// Convert to tree-sitter language name
    pub fn to_tree_sitter_name(&self) -> &'static str {
        match self {
            Language::Python => "python",
            Language::JavaScript => "javascript",
            Language::Rust => "rust",
            Language::Go => "go",
            Language::C => "c",
            Language::Cpp => "cpp",
        }
    }
}

/// Confidence level for findings
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Analysis engine selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnalysisEngine {
    /// Tree-sitter native query engine (fast pattern matching)
    TreeSitter,
    /// Semgrep OSS engine (taint tracking, complex patterns)
    Semgrep,
    /// Hybrid: use tree-sitter first, Semgrep for taint rules
    Hybrid,
}

impl Default for AnalysisEngine {
    fn default() -> Self {
        Self::Hybrid
    }
}

/// Rule source indicating where rules are loaded from
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleSource {
    /// Built-in default rules
    Default,
    /// Loaded from PostgreSQL database
    Database,
    /// Loaded from file (TOML/JSON/YAML)
    File(String),
}
