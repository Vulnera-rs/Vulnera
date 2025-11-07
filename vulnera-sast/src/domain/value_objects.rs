//! SAST value objects

use serde::{Deserialize, Serialize};

/// Programming language
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Language {
    Python,
    JavaScript,
    Rust,
}

impl Language {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "py" => Some(Language::Python),
            "js" | "jsx" | "ts" | "tsx" => Some(Language::JavaScript),
            "rs" => Some(Language::Rust),
            _ => None,
        }
    }

    pub fn from_filename(filename: &str) -> Option<Self> {
        std::path::Path::new(filename)
            .extension()
            .and_then(|ext| ext.to_str())
            .and_then(|ext| Self::from_extension(ext))
    }
}

/// Confidence level for findings
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    High,
    Medium,
    Low,
}


