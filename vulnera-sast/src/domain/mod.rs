//! SAST domain layer
//!
//! Domain-driven design layer containing:
//! - Entities: core business objects (findings, rules)
//! - Value objects: immutable types (Language, Confidence)

pub mod call_graph;
pub mod finding;
pub mod pattern_types;
pub mod rule;
pub mod suppression;
pub mod taint_types;
pub mod value_objects;

// Re-exports for backward compatibility
pub use call_graph::*;
pub use finding::*;
pub use pattern_types::*;
pub use rule::*;
pub use suppression::*;
pub use taint_types::*;
pub use value_objects::*;
