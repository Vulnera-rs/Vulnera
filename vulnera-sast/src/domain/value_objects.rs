//! SAST value objects

use serde::{Deserialize, Serialize};
use std::fmt;

/// Programming language
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Language {
    Python,
    JavaScript,
    TypeScript,
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
            Language::TypeScript => write!(f, "typescript"),
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
            "js" | "mjs" | "cjs" => Some(Language::JavaScript),
            "ts" | "mts" | "cts" => Some(Language::TypeScript),
            "rs" => Some(Language::Rust),
            "go" => Some(Language::Go),
            "c" | "h" => Some(Language::C),
            "cpp" | "hpp" | "cc" | "cxx" | "hxx" => Some(Language::Cpp),
            _ => None,
        }
    }

    pub fn from_filename(filename: &str) -> Option<Self> {
        std::path::Path::new(filename)
            .extension()
            .and_then(|ext| ext.to_str())
            .and_then(Self::from_extension)
    }

    /// Convert to tree-sitter language name
    pub fn to_tree_sitter_name(&self) -> &'static str {
        match self {
            Language::Python => "python",
            Language::JavaScript => "javascript",
            Language::TypeScript => "typescript",
            Language::Rust => "rust",
            Language::Go => "go",
            Language::C => "c",
            Language::Cpp => "cpp",
        }
    }

    /// Get the tree-sitter grammar for this language
    pub fn grammar(&self) -> tree_sitter::Language {
        match self {
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Language::Rust => tree_sitter_rust::LANGUAGE.into(),
            Language::Go => tree_sitter_go::LANGUAGE.into(),
            Language::C => tree_sitter_c::LANGUAGE.into(),
            Language::Cpp => tree_sitter_cpp::LANGUAGE.into(),
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
