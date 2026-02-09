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

// Re-exports for backward compatibility (to be removed in future)
pub use finding::{
    DataFlowFinding, DataFlowNode, DataFlowPath, Finding, FlowStep, FlowStepKind,
    Location, Severity, TaintLabel, TaintState,
};
pub use pattern_types::{Pattern, PatternRule as Rule};
pub use suppression::FileSuppressions;
pub use rule::{
    RuleMetadata, RuleSet, SastRule, SarifArtifactChange, SarifArtifactLocation,
    SarifCodeFlow, SarifDefaultConfiguration, SarifFix, SarifInsertedContent,
    SarifInvocation, SarifLevel, SarifLocation, SarifMessage, SarifPhysicalLocation,
    SarifRegion, SarifReplacement, SarifReport, SarifResult, SarifRule,
    SarifRuleProperties, SarifRun, SarifSnippet, SarifThreadFlow,
    SarifThreadFlowLocation, SarifTool, SarifToolDriver,
};
pub use call_graph::{CallGraphNode, CallSite, FunctionSignature, ParameterInfo};
pub use taint_types::{DataFlowRule, TaintPropagator, TaintSanitizer, TaintSink, TaintSource};
