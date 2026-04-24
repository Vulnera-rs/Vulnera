//! Tree-sitter based parsers for dependency files
//!
//! This module provides parsers using tree-sitter for better error recovery,
//! incremental parsing, and precise source location tracking.
//!

pub mod go;
pub mod json;
pub mod traits;

pub use go::*;
pub use json::*;
pub use traits::*;
