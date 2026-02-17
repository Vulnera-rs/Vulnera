//! Source location tracking for IDE integration
//!
//! This module provides precise file location tracking (path, line, column)
//! to enable IDE features like code actions, jump to definition, and quick fixes.

use serde::{Deserialize, Serialize};

/// Precise source location within a file
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceLocation {
    /// File path relative to project root
    pub path: String,
    /// Starting line number (1-indexed)
    pub line: u32,
    /// Starting column number (1-indexed, UTF-8 character offset)
    pub column: u32,
    /// Ending line number (1-indexed, inclusive)
    pub end_line: Option<u32>,
    /// Ending column number (1-indexed, inclusive, UTF-8 character offset)
    pub end_column: Option<u32>,
}

impl SourceLocation {
    /// Create a new source location
    pub fn new(path: String, line: u32, column: u32) -> Self {
        Self {
            path,
            line,
            column,
            end_line: None,
            end_column: None,
        }
    }

    /// Create a source location with end position
    pub fn with_end(path: String, line: u32, column: u32, end_line: u32, end_column: u32) -> Self {
        Self {
            path,
            line,
            column,
            end_line: Some(end_line),
            end_column: Some(end_column),
        }
    }

    /// Create a source location spanning multiple lines
    pub fn span(
        path: String,
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
    ) -> Self {
        Self {
            path,
            line: start_line,
            column: start_column,
            end_line: Some(end_line),
            end_column: Some(end_column),
        }
    }

    /// Check if this location contains a point (line, column)
    pub fn contains(&self, line: u32, column: u32) -> bool {
        if line < self.line {
            return false;
        }
        if let Some(end_line) = self.end_line {
            if line > end_line {
                return false;
            }
            if line == self.line && column < self.column {
                return false;
            }
            if line == end_line
                && let Some(end_column) = self.end_column
            {
                return column <= end_column;
            }
        } else {
            // Single line location - must be on the same line
            if line != self.line {
                return false;
            }
            if column < self.column {
                return false;
            }
        }
        true
    }

    /// Get a display string for this location
    pub fn to_display_string(&self) -> String {
        if let (Some(end_line), Some(end_column)) = (self.end_line, self.end_column) {
            if end_line == self.line {
                format!("{}:{}:{}-{}", self.path, self.line, self.column, end_column)
            } else {
                format!(
                    "{}:{}:{}-{}:{}",
                    self.path, self.line, self.column, end_line, end_column
                )
            }
        } else {
            format!("{}:{}:{}", self.path, self.line, self.column)
        }
    }
}

impl Default for SourceLocation {
    fn default() -> Self {
        Self {
            path: String::new(),
            line: 1,
            column: 1,
            end_line: None,
            end_column: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_location_new() {
        let loc = SourceLocation::new("test.py".to_string(), 10, 5);
        assert_eq!(loc.path, "test.py");
        assert_eq!(loc.line, 10);
        assert_eq!(loc.column, 5);
        assert_eq!(loc.end_line, None);
        assert_eq!(loc.end_column, None);
    }

    #[test]
    fn test_source_location_with_end() {
        let loc = SourceLocation::with_end("test.py".to_string(), 10, 5, 10, 15);
        assert_eq!(loc.path, "test.py");
        assert_eq!(loc.line, 10);
        assert_eq!(loc.column, 5);
        assert_eq!(loc.end_line, Some(10));
        assert_eq!(loc.end_column, Some(15));
    }

    #[test]
    fn test_source_location_span() {
        let loc = SourceLocation::span("test.py".to_string(), 10, 5, 12, 20);
        assert_eq!(loc.path, "test.py");
        assert_eq!(loc.line, 10);
        assert_eq!(loc.column, 5);
        assert_eq!(loc.end_line, Some(12));
        assert_eq!(loc.end_column, Some(20));
    }

    #[test]
    fn test_contains() {
        let loc = SourceLocation::new("test.py".to_string(), 10, 5);
        assert!(loc.contains(10, 5));
        assert!(loc.contains(10, 10));
        assert!(!loc.contains(10, 4));
        assert!(!loc.contains(9, 5));
        assert!(!loc.contains(11, 5));

        let loc_span = SourceLocation::span("test.py".to_string(), 10, 5, 12, 20);
        assert!(loc_span.contains(10, 5));
        assert!(loc_span.contains(11, 1));
        assert!(loc_span.contains(12, 20));
        assert!(!loc_span.contains(10, 4));
        assert!(!loc_span.contains(12, 21));
        assert!(!loc_span.contains(13, 1));
    }

    #[test]
    fn test_to_display_string() {
        let loc = SourceLocation::new("test.py".to_string(), 10, 5);
        assert_eq!(loc.to_display_string(), "test.py:10:5");

        let loc_span = SourceLocation::span("test.py".to_string(), 10, 5, 10, 15);
        assert_eq!(loc_span.to_display_string(), "test.py:10:5-15");

        let loc_multiline = SourceLocation::span("test.py".to_string(), 10, 5, 12, 20);
        assert_eq!(loc_multiline.to_display_string(), "test.py:10:5-12:20");
    }
}
