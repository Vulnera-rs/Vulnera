use std::path::Path;

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;

use crate::domain::value_objects::Language;

/// OXC-powered parser frontend for JavaScript/TypeScript family files.
#[derive(Debug, Default, Clone, Copy)]
pub struct OxcFrontend;

impl OxcFrontend {
    /// Returns whether this frontend supports the given language.
    pub fn supports(language: Language) -> bool {
        matches!(language, Language::JavaScript | Language::TypeScript)
    }

    /// Performs syntax parsing with OXC and returns detailed parse errors.
    pub fn parse_file(&self, file_path: &Path, source: &str) -> Result<(), String> {
        let source_type = SourceType::from_path(file_path).map_err(|err| {
            format!(
                "Unsupported JS/TS source type for '{}': {}",
                file_path.display(),
                err
            )
        })?;

        let allocator = Allocator::default();
        let parser_return = Parser::new(&allocator, source, source_type).parse();

        if parser_return.panicked {
            return Err(format!(
                "OXC parser panicked for '{}'",
                file_path.display()
            ));
        }

        if parser_return.errors.is_empty() {
            return Ok(());
        }

        let error_summary = parser_return
            .errors
            .iter()
            .take(5)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" | ");

        Err(format!(
            "OXC parse errors in '{}': {}",
            file_path.display(),
            error_summary
        ))
    }
}
