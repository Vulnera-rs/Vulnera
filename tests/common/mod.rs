//! Common test utilities and shared functionality for all Vulnera tests
//!
//! This module provides:
//! - Test data factories
//! - Mock implementations
//! - Custom assertions
//! - Test helpers and utilities

pub mod factories;
pub mod mocks;
pub mod assertions;
pub mod test_helpers;
pub mod extensions;

// Re-export commonly used items
pub use factories::*;
pub use mocks::*;
pub use assertions::*;
pub use test_helpers::*;
pub use extensions::*;