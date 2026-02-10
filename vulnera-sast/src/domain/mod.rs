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
