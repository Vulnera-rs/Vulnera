//! Module plugin entities

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::value_objects::ModuleType;

/// Result from a single analysis module
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
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

impl ModuleResult {
    /// Create a successful module result.
    pub fn success(
        job_id: Uuid,
        module_type: ModuleType,
        findings: Vec<Finding>,
        metadata: ModuleResultMetadata,
    ) -> Self {
        Self {
            job_id,
            module_type,
            findings,
            metadata,
            error: None,
        }
    }

    /// Create a failed module result.
    pub fn failure(job_id: Uuid, module_type: ModuleType, error: impl Into<String>) -> Self {
        Self {
            job_id,
            module_type,
            findings: Vec::new(),
            metadata: ModuleResultMetadata::default(),
            error: Some(error.into()),
        }
    }
}

/// LLM-generated enrichment data for a finding
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub struct FindingEnrichment {
    /// LLM-generated explanation of the vulnerability
    pub explanation: Option<String>,
    /// LLM-generated remediation suggestion
    pub remediation_suggestion: Option<String>,
    /// Risk assessment summary
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
///
/// Use [`Finding::builder()`] to construct findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
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

impl Finding {
    /// Create a finding builder with required fields.
    pub fn builder(
        id: impl Into<String>,
        r#type: FindingType,
        location: Location,
        severity: FindingSeverity,
        confidence: FindingConfidence,
        description: impl Into<String>,
    ) -> FindingBuilder {
        FindingBuilder {
            id: id.into(),
            r#type,
            location,
            severity,
            confidence,
            description: description.into(),
            rule_id: None,
            recommendation: None,
            secret_metadata: None,
            vulnerability_metadata: VulnerabilityFindingMetadata::default(),
            enrichment: None,
        }
    }
}

/// Builder for [`Finding`].
///
/// ```rust,ignore
/// let finding = Finding::builder("id", FindingType::Vulnerability, loc, FindingSeverity::High, FindingConfidence::High, "desc")
///     .rule_id("rule-1")
///     .recommendation("Fix it")
///     .build();
/// ```
pub struct FindingBuilder {
    id: String,
    r#type: FindingType,
    location: Location,
    severity: FindingSeverity,
    confidence: FindingConfidence,
    description: String,
    rule_id: Option<String>,
    recommendation: Option<String>,
    secret_metadata: Option<SecretFindingMetadata>,
    vulnerability_metadata: VulnerabilityFindingMetadata,
    enrichment: Option<FindingEnrichment>,
}

impl FindingBuilder {
    /// Set the rule identifier.
    pub fn rule_id(mut self, id: impl Into<String>) -> Self {
        self.rule_id = Some(id.into());
        self
    }

    /// Set the recommendation.
    pub fn recommendation(mut self, rec: impl Into<String>) -> Self {
        self.recommendation = Some(rec.into());
        self
    }

    /// Set secret metadata.
    pub fn secret_metadata(mut self, meta: SecretFindingMetadata) -> Self {
        self.secret_metadata = Some(meta);
        self
    }

    /// Set vulnerability metadata.
    pub fn vulnerability_metadata(mut self, meta: VulnerabilityFindingMetadata) -> Self {
        self.vulnerability_metadata = meta;
        self
    }

    /// Set enrichment data.
    pub fn enrichment(mut self, enr: FindingEnrichment) -> Self {
        self.enrichment = Some(enr);
        self
    }

    /// Build the finding.
    pub fn build(self) -> Finding {
        Finding {
            id: self.id,
            r#type: self.r#type,
            rule_id: self.rule_id,
            location: self.location,
            severity: self.severity,
            confidence: self.confidence,
            description: self.description,
            recommendation: self.recommendation,
            secret_metadata: self.secret_metadata,
            vulnerability_metadata: self.vulnerability_metadata,
            enrichment: self.enrichment,
        }
    }
}

/// Vulnerability-specific metadata attached to vulnerability findings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub struct VulnerabilityFindingMetadata {
    /// Code snippet at the finding location
    pub snippet: Option<String>,
    /// Rule metavariable bindings captured during matching
    pub bindings: Option<std::collections::HashMap<String, String>>,
    /// Optional semantic trace for taint/dataflow findings
    pub semantic_path: Option<VulnerabilitySemanticPath>,
}

/// Semantic path showing source-to-sink propagation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VulnerabilitySemanticPath {
    /// Source location where taint originated
    pub source: VulnerabilitySemanticNode,
    /// Intermediate propagation steps
    pub steps: Vec<VulnerabilitySemanticNode>,
    /// Sink location where taint is consumed
    pub sink: VulnerabilitySemanticNode,
}

impl VulnerabilitySemanticPath {
    /// Create a new semantic path.
    pub fn new(
        source: VulnerabilitySemanticNode,
        steps: Vec<VulnerabilitySemanticNode>,
        sink: VulnerabilitySemanticNode,
    ) -> Self {
        Self {
            source,
            steps,
            sink,
        }
    }
}

/// Semantic node metadata for vulnerability traces
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VulnerabilitySemanticNode {
    /// Location in source code
    pub location: Location,
    /// Description of the node operation
    pub description: String,
    /// Expression tracked at this node
    pub expression: String,
}

impl VulnerabilitySemanticNode {
    /// Create a new semantic node.
    pub fn new(
        location: Location,
        description: impl Into<String>,
        expression: impl Into<String>,
    ) -> Self {
        Self {
            location,
            description: description.into(),
            expression: expression.into(),
        }
    }
}

/// Secret-specific metadata attached to secret findings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
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

impl SecretFindingMetadata {
    /// Create new secret metadata.
    pub fn new(
        detector_id: impl Into<String>,
        verification_state: SecretVerificationState,
        redacted_secret: impl Into<String>,
    ) -> Self {
        Self {
            detector_id: detector_id.into(),
            verification_state,
            redacted_secret: redacted_secret.into(),
            entropy: None,
            evidence: Vec::new(),
        }
    }

    /// Set the entropy value.
    pub fn with_entropy(mut self, entropy: f64) -> Self {
        self.entropy = Some(entropy);
        self
    }

    /// Set evidence notes.
    pub fn with_evidence(mut self, evidence: Vec<String>) -> Self {
        self.evidence = evidence;
        self
    }
}

/// Verification state for detected secrets
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FindingConfidence {
    /// High confidence
    High,
    /// Medium confidence
    Medium,
    /// Low confidence
    Low,
}

/// Location of a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
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

impl Location {
    /// Create a new location with required field.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            line: None,
            column: None,
            end_line: None,
            end_column: None,
        }
    }

    /// Set the line number.
    pub fn with_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }

    /// Set the column number.
    pub fn with_column(mut self, column: u32) -> Self {
        self.column = Some(column);
        self
    }

    /// Set the end line number.
    pub fn with_end_line(mut self, end_line: u32) -> Self {
        self.end_line = Some(end_line);
        self
    }

    /// Set the end column number.
    pub fn with_end_column(mut self, end_column: u32) -> Self {
        self.end_column = Some(end_column);
        self
    }
}

/// Module result metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub struct ModuleResultMetadata {
    /// Number of files scanned
    pub files_scanned: usize,
    /// Execution duration in milliseconds
    pub duration_ms: u64,
    /// Additional module-specific information
    pub additional_info: std::collections::HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FindingConfidence, FindingSeverity, FindingType, ModuleType, SecretVerificationState,
    };
    use chrono::Utc;

    fn test_location() -> Location {
        Location::new("src/main.rs")
            .with_line(42)
            .with_column(10)
            .with_end_line(42)
            .with_end_column(20)
    }

    fn test_job_id() -> uuid::Uuid {
        uuid::Uuid::parse_str("b16b4e16-a5c6-4168-96cc-d4f414bf974c").unwrap()
    }

    // --- ModuleResult ---

    #[test]
    fn module_result_success_has_no_error() {
        let job_id = test_job_id();
        let result = ModuleResult::success(
            job_id,
            ModuleType::SAST,
            vec![],
            ModuleResultMetadata::default(),
        );
        assert_eq!(result.job_id, job_id);
        assert_eq!(result.module_type, ModuleType::SAST);
        assert!(result.error.is_none());
        assert!(result.findings.is_empty());
    }

    #[test]
    fn module_result_failure_has_error_and_empty_findings() {
        let job_id = test_job_id();
        let result = ModuleResult::failure(job_id, ModuleType::SecretDetection, "sandbox timeout");
        assert_eq!(result.job_id, job_id);
        assert_eq!(result.module_type, ModuleType::SecretDetection);
        assert_eq!(result.error.as_deref(), Some("sandbox timeout"));
        assert!(result.findings.is_empty());
        assert_eq!(result.metadata.files_scanned, 0);
    }

    // --- FindingBuilder ---

    #[test]
    fn finding_builder_produces_correct_fields() {
        let id = "b16b4e16-a5c6-4168-96cc-d4f414bf974c";
        let loc = test_location();
        let finding = Finding::builder(
            id,
            FindingType::Secret,
            loc.clone(),
            FindingSeverity::High,
            FindingConfidence::High,
            "AWS key found in source",
        )
        .rule_id("sec-aws-001")
        .recommendation("Rotate the key")
        .build();

        assert_eq!(finding.id, id);
        assert_eq!(finding.r#type, FindingType::Secret);
        assert_eq!(finding.location.path, loc.path);
        assert_eq!(finding.severity, FindingSeverity::High);
        assert_eq!(finding.confidence, FindingConfidence::High);
        assert_eq!(finding.description, "AWS key found in source");
        assert_eq!(finding.rule_id.as_deref(), Some("sec-aws-001"));
        assert_eq!(finding.recommendation.as_deref(), Some("Rotate the key"));
    }

    #[test]
    fn finding_builder_default_optional_fields_are_empty() {
        let finding = Finding::builder(
            "id-1",
            FindingType::Vulnerability,
            test_location(),
            FindingSeverity::Critical,
            FindingConfidence::Medium,
            "SQL injection",
        )
        .build();

        assert!(finding.rule_id.is_none());
        assert!(finding.recommendation.is_none());
        assert!(finding.secret_metadata.is_none());
        assert!(finding.enrichment.is_none());
    }

    #[test]
    fn finding_builder_with_secret_metadata() {
        let secret = SecretFindingMetadata::new(
            "aws-access-key",
            SecretVerificationState::Verified,
            "AKIA****REDACTED",
        )
        .with_entropy(4.7);

        let finding = Finding::builder(
            "id-2",
            FindingType::Secret,
            test_location(),
            FindingSeverity::Critical,
            FindingConfidence::High,
            "AWS key exposed",
        )
        .secret_metadata(secret)
        .build();

        let meta = finding.secret_metadata.as_ref().unwrap();
        assert_eq!(meta.detector_id, "aws-access-key");
        assert_eq!(meta.verification_state, SecretVerificationState::Verified);
        assert_eq!(meta.entropy, Some(4.7));
    }

    #[test]
    fn finding_builder_with_vulnerability_metadata() {
        let loc = test_location();
        let source = VulnerabilitySemanticNode::new(loc.clone(), "taint source", "request.body");
        let sink = VulnerabilitySemanticNode::new(loc, "raw SQL", "db.query(sql)");
        let path = VulnerabilitySemanticPath::new(source, vec![], sink);
        let vuln_meta = VulnerabilityFindingMetadata {
            snippet: Some("db.query(user)".into()),
            semantic_path: Some(path),
            ..Default::default()
        };

        let finding = Finding::builder(
            "id-3",
            FindingType::Vulnerability,
            test_location(),
            FindingSeverity::Critical,
            FindingConfidence::High,
            "SQL injection in login",
        )
        .vulnerability_metadata(vuln_meta)
        .build();

        assert!(finding.vulnerability_metadata.snippet.is_some());
        assert!(finding.vulnerability_metadata.semantic_path.is_some());
    }

    #[test]
    fn finding_builder_with_enrichment() {
        let enrichment = FindingEnrichment {
            explanation: Some("Detailed exploit scenario".into()),
            remediation_suggestion: Some("Use parameterized queries".into()),
            enrichment_successful: true,
            enriched_at: Some(Utc::now()),
            ..Default::default()
        };

        let finding = Finding::builder(
            "id-4",
            FindingType::Vulnerability,
            test_location(),
            FindingSeverity::High,
            FindingConfidence::High,
            "XSS in template",
        )
        .enrichment(enrichment)
        .build();

        let enr = finding.enrichment.as_ref().unwrap();
        assert!(enr.explanation.is_some());
        assert!(enr.enrichment_successful);
    }

    // --- Location ---

    #[test]
    fn location_default_fields_are_none() {
        let loc = Location::new("src/lib.rs");
        assert_eq!(loc.path, "src/lib.rs");
        assert!(loc.line.is_none());
        assert!(loc.column.is_none());
        assert!(loc.end_line.is_none());
        assert!(loc.end_column.is_none());
    }

    #[test]
    fn location_builder_sets_all_fields() {
        let loc = Location::new("src/main.rs")
            .with_line(10)
            .with_column(5)
            .with_end_line(12)
            .with_end_column(8);
        assert_eq!(loc.line, Some(10));
        assert_eq!(loc.column, Some(5));
        assert_eq!(loc.end_line, Some(12));
        assert_eq!(loc.end_column, Some(8));
    }

    // --- SecretFindingMetadata ---

    #[test]
    fn secret_metadata_new_sets_required_fields() {
        let meta = SecretFindingMetadata::new(
            "github-pat",
            SecretVerificationState::Invalid,
            "ghp_****REDACTED",
        );
        assert_eq!(meta.detector_id, "github-pat");
        assert_eq!(meta.verification_state, SecretVerificationState::Invalid);
        assert_eq!(meta.redacted_secret, "ghp_****REDACTED");
        assert!(meta.entropy.is_none());
        assert!(meta.evidence.is_empty());
    }

    #[test]
    fn secret_metadata_with_entropy_and_evidence() {
        let meta = SecretFindingMetadata::new(
            "generic-api-key",
            SecretVerificationState::Unknown,
            "***REDACTED",
        )
        .with_entropy(5.2)
        .with_evidence(vec![
            "Found in .env file".into(),
            "Matches known pattern".into(),
        ]);
        assert_eq!(meta.entropy, Some(5.2));
        assert_eq!(meta.evidence.len(), 2);
    }

    // --- VulnerabilitySemanticNode ---

    #[test]
    fn semantic_node_new_stores_fields() {
        let loc = test_location();
        let node = VulnerabilitySemanticNode::new(
            loc.clone(),
            "user input enters application",
            "req.query.name",
        );
        assert_eq!(node.location.path, loc.path);
        assert_eq!(node.description, "user input enters application");
        assert_eq!(node.expression, "req.query.name");
    }

    // --- VulnerabilitySemanticPath ---

    #[test]
    fn semantic_path_new_stores_source_steps_sink() {
        let source = VulnerabilitySemanticNode::new(
            test_location(),
            "HTTP request parameter",
            "req.body.user",
        );
        let step = VulnerabilitySemanticNode::new(
            Location::new("src/controller.rs").with_line(25),
            "pass-through to database",
            "user",
        );
        let sink = VulnerabilitySemanticNode::new(
            Location::new("src/db.rs").with_line(80),
            "raw SQL query",
            "db.query(sql)",
        );
        let path = VulnerabilitySemanticPath::new(source.clone(), vec![step.clone()], sink.clone());
        assert_eq!(path.source.description, source.description);
        assert_eq!(path.steps.len(), 1);
        assert_eq!(path.sink.expression, sink.expression);
    }

    // --- Default implementations ---

    #[test]
    fn finding_enrichment_default_fields() {
        let fe = FindingEnrichment::default();
        assert!(fe.explanation.is_none());
        assert!(fe.remediation_suggestion.is_none());
        assert!(!fe.enrichment_successful);
        assert!(fe.enriched_at.is_none());
    }

    #[test]
    fn module_result_metadata_default_is_zeroed() {
        let m = ModuleResultMetadata::default();
        assert_eq!(m.files_scanned, 0);
        assert_eq!(m.duration_ms, 0);
        assert!(m.additional_info.is_empty());
    }

    // --- Finding JSON round-trip ---

    #[test]
    fn finding_json_roundtrip_minimal() {
        let finding = Finding::builder(
            "id-json-1",
            FindingType::Vulnerability,
            Location::new("src/auth.rs").with_line(10),
            FindingSeverity::Critical,
            FindingConfidence::High,
            "Hardcoded JWT secret",
        )
        .rule_id("sast-jwt-001")
        .build();

        let json = serde_json::to_string(&finding).unwrap();
        let parsed: Finding = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, finding.id);
        assert_eq!(parsed.r#type, finding.r#type);
        assert_eq!(parsed.severity, finding.severity);
        assert_eq!(parsed.location.path, finding.location.path);
        assert_eq!(parsed.location.line, finding.location.line);
        assert_eq!(parsed.rule_id, finding.rule_id);
    }

    #[test]
    fn finding_json_roundtrip_with_all_optional_fields() {
        let secret = SecretFindingMetadata::new(
            "aws-access-key",
            SecretVerificationState::Verified,
            "AKIA****REDACTED",
        )
        .with_entropy(4.7);
        let enrichment = FindingEnrichment {
            explanation: Some("Found in public repo".into()),
            remediation_suggestion: Some("Rotate immediately".into()),
            enrichment_successful: true,
            enriched_at: Some(Utc::now()),
            ..Default::default()
        };

        let finding = Finding::builder(
            "id-json-2",
            FindingType::Secret,
            test_location(),
            FindingSeverity::High,
            FindingConfidence::High,
            "Secret found",
        )
        .rule_id("sec-001")
        .recommendation("Rotate immediately")
        .secret_metadata(secret)
        .enrichment(enrichment)
        .build();

        let json = serde_json::to_string(&finding).unwrap();
        let parsed: Finding = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.rule_id.as_deref(), Some("sec-001"));
        assert!(parsed.secret_metadata.is_some());
        assert!(parsed.enrichment.is_some());
        assert_eq!(
            parsed.secret_metadata.as_ref().unwrap().detector_id,
            "aws-access-key"
        );
    }

    #[test]
    fn finding_json_deserialization_required_fields() {
        let json = r#"{
            "id": "id-deser-1",
            "type": "Vulnerability",
            "location": { "path": "main.go", "line": 1 },
            "severity": "High",
            "confidence": "Medium",
            "description": "empty password check",
            "vulnerability_metadata": {}
        }"#;

        let finding: Finding = serde_json::from_str(json).unwrap();
        assert!(finding.rule_id.is_none());
        assert!(finding.recommendation.is_none());
        assert!(finding.secret_metadata.is_none());
        assert!(finding.enrichment.is_none());
    }

    // --- Enum JSON round-trips ---

    #[test]
    fn secret_verification_state_json_roundtrip_all_variants() {
        for state in [
            SecretVerificationState::Verified,
            SecretVerificationState::Invalid,
            SecretVerificationState::Unknown,
            SecretVerificationState::Unverified,
            SecretVerificationState::NotSupported,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let parsed: SecretVerificationState = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, state, "round-trip failed for {:?}", state);
        }
    }

    #[test]
    fn finding_type_json_roundtrip_all_variants() {
        for ft in [
            FindingType::Vulnerability,
            FindingType::Secret,
            FindingType::LicenseViolation,
            FindingType::Misconfiguration,
        ] {
            let json = serde_json::to_string(&ft).unwrap();
            let parsed: FindingType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, ft);
        }
    }

    #[test]
    fn finding_severity_json_roundtrip_all_variants() {
        for s in [
            FindingSeverity::Critical,
            FindingSeverity::High,
            FindingSeverity::Medium,
            FindingSeverity::Low,
            FindingSeverity::Info,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let parsed: FindingSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, s);
        }
    }

    #[test]
    fn finding_confidence_json_roundtrip_all_variants() {
        for c in [
            FindingConfidence::High,
            FindingConfidence::Medium,
            FindingConfidence::Low,
        ] {
            let json = serde_json::to_string(&c).unwrap();
            let parsed: FindingConfidence = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, c);
        }
    }

    // --- ModuleResult JSON ---

    #[test]
    fn module_result_json_roundtrip_success() {
        let job_id = test_job_id();
        let mut info = std::collections::HashMap::new();
        info.insert("lang".into(), "rust".into());
        let result = ModuleResult::success(
            job_id,
            ModuleType::SAST,
            vec![],
            ModuleResultMetadata {
                files_scanned: 42,
                duration_ms: 1500,
                additional_info: info,
            },
        );
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ModuleResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.job_id, job_id);
        assert_eq!(parsed.module_type, ModuleType::SAST);
        assert!(parsed.error.is_none());
        assert_eq!(parsed.metadata.files_scanned, 42);
    }

    #[test]
    fn module_result_json_roundtrip_failure() {
        let job_id = test_job_id();
        let result = ModuleResult::failure(job_id, ModuleType::DependencyAnalyzer, "network error");
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ModuleResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.error.as_deref(), Some("network error"));
        assert!(parsed.findings.is_empty());
    }

    // --- Location JSON ---

    #[test]
    fn location_json_roundtrip_full() {
        let loc = Location::new("lib/parser.py")
            .with_line(100)
            .with_column(4)
            .with_end_line(105)
            .with_end_column(12);
        let json = serde_json::to_string(&loc).unwrap();
        let parsed: Location = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.path, loc.path);
        assert_eq!(parsed.line, Some(100));
        assert_eq!(parsed.end_column, Some(12));
    }

    #[test]
    fn location_json_missing_optional_defaults_to_none() {
        let json = r#"{"path": "src/main.rs"}"#;
        let parsed: Location = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.path, "src/main.rs");
        assert!(parsed.line.is_none());
    }

    // --- FindingEnrichment JSON ---

    #[test]
    fn finding_enrichment_json_roundtrip() {
        let now = Utc::now();
        let fe = FindingEnrichment {
            explanation: Some("SQL injection in login form".into()),
            remediation_suggestion: Some("Use parameterized queries".into()),
            enrichment_successful: true,
            error: None,
            enriched_at: Some(now),
            ..Default::default()
        };
        let json = serde_json::to_string(&fe).unwrap();
        let parsed: FindingEnrichment = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.explanation, fe.explanation);
        assert!(parsed.enrichment_successful);
    }
}
