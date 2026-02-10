//! SAST infrastructure layer
//!
//! This module provides the core infrastructure for static analysis:
//! - Query Engine: Tree-sitter query execution with composite patterns
//! - Data Flow: Taint tracking and data flow analysis
//! - Call Graph: Inter-procedural function call analysis
//! - Rules: Rule loading, validation, and management
//! - AST Cache: Cached AST for incremental analysis
//! - Incremental: Content hash-based change detection

pub mod ast_cache;
pub mod call_graph;
pub mod call_graph_queries;
pub mod data_flow;
pub mod incremental;
pub mod metavar_patterns;
pub mod parsers;
pub mod query_engine;
pub mod regex_cache;
pub mod rules;
pub mod sarif;
pub mod sast_engine;
pub mod scanner;
pub mod symbol_table;
pub mod taint_queries;

pub use ast_cache::*;
pub use call_graph::*;
pub use data_flow::*;
pub use incremental::*;
pub use query_engine::*;
pub use rules::RuleRepository;
pub use sast_engine::*;
pub use scanner::*;
pub use symbol_table::*;
pub use taint_queries::*;
