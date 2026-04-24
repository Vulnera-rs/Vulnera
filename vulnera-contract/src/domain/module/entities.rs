//! Module plugin entities

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::value_objects::ModuleType;

/// Result from a single analysis module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleResult {
    /// Job identifier this result belongs to
    pub job_id: Uuid,
    /// Type of module that produced this result
    pub module_type: ModuleType,
    /// Findings discovered by the module
    pub findings: Vec<Finding>,
    /// Execution metadata
    pub metadata: ModuleResultMetadata,
    /// Error message if execution failed
    pub error: Option<String>,
}

/// LLM-generated enrichment data for a finding
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Default)]
pub struct FindingEnrichment {
    /// LLM-generated explanation of the vulnerability
    #[schema(
        example = "This SQL injection vulnerability allows attackers to execute arbitrary SQL commands..."
    )]
    pub explanation: Option<String>,
    /// LLM-generated remediation suggestion
    #[schema(
        example = "Use parameterized queries or prepared statements instead of string concatenation..."
    )]
    pub remediation_suggestion: Option<String>,
    /// Risk assessment summary
    #[schema(
        example = "High risk: This vulnerability could lead to data breach and unauthorized access."
    )]
    pub risk_summary: Option<String>,
    /// Whether enrichment was successful
    pub enrichment_successful: bool,
    /// Error message if enrichment failed
    pub error: Option<String>,
    /// Timestamp when enrichment was performed
    pub enriched_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Finding from a module (unified format)
///
/// All analysis modules produce findings in this unified format, allowing
/// the orchestrator to aggregate results from different module types.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Finding {
    /// Unique finding identifier
    pub id: String,
    /// Type of finding
    pub r#type: FindingType,
    /// Rule identifier that triggered this finding (if applicable)
    pub rule_id: Option<String>,
    /// Location of the finding in the source code
    pub location: Location,
    /// Severity of the finding
    pub severity: FindingSeverity,
    /// Confidence level of the finding
    pub confidence: FindingConfidence,
    /// Human-readable description
    pub description: String,
    /// Recommended remediation (if available)
    pub recommendation: Option<String>,
    /// Secret-specific metadata (populated only for secret findings)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_metadata: Option<SecretFindingMetadata>,
    /// Vulnerability-specific metadata (populated by vulnerability analyzers such as SAST)
    pub vulnerability_metadata: VulnerabilityFindingMetadata,
    /// LLM-generated enrichment data (populated on-demand via enrichment endpoint)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrichment: Option<FindingEnrichment>,
}

/// Vulnerability-specific metadata attached to vulnerability findings
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Default)]
pub struct VulnerabilityFindingMetadata {
    /// Code snippet at the finding location
    pub snippet: Option<String>,
    /// Rule metavariable bindings captured during matching
    pub bindings: Option<std::collections::HashMap<String, String>>,
    /// Optional semantic trace for taint/dataflow findings
    pub semantic_path: Option<VulnerabilitySemanticPath>,
}

/// Semantic path showing source-to-sink propagation
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VulnerabilitySemanticPath {
    /// Source location where taint originated
    pub source: VulnerabilitySemanticNode,
    /// Intermediate propagation steps
    pub steps: Vec<VulnerabilitySemanticNode>,
    /// Sink location where taint is consumed
    pub sink: VulnerabilitySemanticNode,
}

/// Semantic node metadata for vulnerability traces
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VulnerabilitySemanticNode {
    /// Location in source code
    pub location: Location,
    /// Description of the node operation
    pub description: String,
    /// Expression tracked at this node
    pub expression: String,
}

/// Secret-specific metadata attached to secret findings
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SecretFindingMetadata {
    /// Secret detector identifier
    pub detector_id: String,
    /// Verification state returned by the verifier subsystem
    pub verification_state: SecretVerificationState,
    /// Redacted secret snippet (safe for display)
    pub redacted_secret: String,
    /// Optional entropy value when entropy detector contributed to the finding
    pub entropy: Option<f64>,
    /// Optional evidence notes used during scoring and triage
    pub evidence: Vec<String>,
}

/// Verification state for detected secrets
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum SecretVerificationState {
    /// Secret was successfully verified against provider/API
    Verified,
    /// Secret was checked and determined invalid
    Invalid,
    /// Verification attempted but result is indeterminate (timeouts/network/provider errors)
    Unknown,
    /// Verification available but not attempted for this finding
    Unverified,
    /// No verifier exists for this secret type
    NotSupported,
}

/// Finding type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum FindingType {
    /// Security vulnerability
    Vulnerability,
    /// Exposed secret or credential
    Secret,
    /// License compliance issue
    LicenseViolation,
    /// Configuration misconfiguration
    Misconfiguration,
}

/// Finding severity
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub enum FindingSeverity {
    /// Critical severity
    Critical,
    /// High severity
    High,
    /// Medium severity
    Medium,
    /// Low severity
    Low,
    /// Informational
    Info,
}

/// Finding confidence level
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub enum FindingConfidence {
    /// High confidence
    High,
    /// Medium confidence
    Medium,
    /// Low confidence
    Low,
}

/// Location of a finding
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Location {
    /// File path or resource identifier
    pub path: String,
    /// Starting line number (1-indexed)
    pub line: Option<u32>,
    /// Starting column number (1-indexed)
    pub column: Option<u32>,
    /// Ending line number (1-indexed)
    pub end_line: Option<u32>,
    /// Ending column number (1-indexed)
    pub end_column: Option<u32>,
}

/// Module result metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModuleResultMetadata {
    /// Number of files scanned
    pub files_scanned: usize,
    /// Execution duration in milliseconds
    pub duration_ms: u64,
    /// Additional module-specific information
    pub additional_info: std::collections::HashMap<String, String>,
}
