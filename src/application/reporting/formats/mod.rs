//! Report format implementations
//!
//! This module contains format-specific report generators.

pub mod html;
pub mod json;

pub use html::*;
pub use json::*;

