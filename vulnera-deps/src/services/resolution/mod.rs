//! Dependency resolution services
//!
//! This module provides various strategies for resolving dependency trees,
//! including recursive resolution for projects without lockfiles.

pub mod recursive_resolver;

pub use recursive_resolver::{RecursiveResolutionResult, RecursiveResolver};
