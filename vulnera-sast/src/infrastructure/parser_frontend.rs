use serde::{Deserialize, Serialize};

use crate::domain::value_objects::Language;

/// Preferred JS/TS parser frontend strategy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum JavaScriptFrontend {
    /// Use tree-sitter for JavaScript/TypeScript parsing and analysis.
    #[default]
    TreeSitter,
    /// Prefer OXC for JavaScript/TypeScript when available.
    ///
    /// Current runtime keeps tree-sitter as execution backend and uses this
    /// as routing intent for progressive rollout.
    OxcPreferred,
}

/// Effective parser frontend selected for a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParserFrontend {
    TreeSitter,
    Oxc,
}

/// Routing selector from language + config to parser frontend.
#[derive(Debug, Clone, Copy)]
pub struct ParserFrontendSelector {
    js_ts_frontend: JavaScriptFrontend,
}

impl ParserFrontendSelector {
    pub fn new(js_ts_frontend: JavaScriptFrontend) -> Self {
        Self { js_ts_frontend }
    }

    pub fn select(&self, language: Language) -> ParserFrontend {
        match language {
            Language::JavaScript | Language::TypeScript => match self.js_ts_frontend {
                JavaScriptFrontend::TreeSitter => ParserFrontend::TreeSitter,
                JavaScriptFrontend::OxcPreferred => ParserFrontend::Oxc,
            },
            _ => ParserFrontend::TreeSitter,
        }
    }
}
