//! GitHub Security Advisories API client implementation

use super::traits::{RawVulnerability, VulnerabilityApiClient};
use crate::application::errors::{ApiError, VulnerabilityError};
use crate::domain::vulnerability::entities::Package;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// Task-local request-scoped GHSA token.
// Middleware or handlers can scope a token for the lifetime of a request using
// `with_request_ghsa_token(token, async { ... }).await;`
tokio::task_local! {
    static GHSA_REQ_TOKEN: String;
}

/// Scope a request-scoped GHSA token for the duration of the provided future.
/// Any GHSA client calls within this future (and not crossing a task boundary)
/// will pick up the token via task-local storage.
pub async fn with_request_ghsa_token<F, T>(token: String, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    GHSA_REQ_TOKEN.scope(token, fut).await
}

/// GraphQL query request structure
#[derive(Debug, Serialize)]
struct GraphQLRequest {
    query: String,
    variables: serde_json::Value,
}

/// GraphQL response structure
#[derive(Debug, Deserialize)]
struct GraphQLResponse<T> {
    data: Option<T>,
    errors: Option<Vec<GraphQLError>>,
}

#[derive(Debug, Clone, serde::Deserialize, PartialEq)]
struct GraphQLError {
    message: String,
    #[serde(default)]
    locations: Vec<GraphQLLocation>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct GraphQLLocation {
    line: u32,
    column: u32,
}

#[derive(Debug, Deserialize)]
pub struct SecurityAdvisoriesConnection {
    nodes: Vec<SecurityAdvisory>,
    #[serde(rename = "pageInfo")]
    page_info: PageInfo,
}

#[derive(Debug, Deserialize)]
struct PageInfo {
    #[serde(rename = "hasNextPage")]
    has_next_page: bool,
    #[serde(rename = "endCursor")]
    end_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SecurityAdvisory {
    #[serde(rename = "ghsaId")]
    ghsa_id: String,
    summary: String,
    description: String,
    severity: String,
    #[serde(rename = "publishedAt")]
    published_at: String,
    references: Vec<Reference>,
    #[allow(dead_code)]
    vulnerabilities: SecurityAdvisoryVulnerabilities, // Future: Enhanced vulnerability analysis
}

#[derive(Debug, Deserialize)]
struct Reference {
    url: String,
}

#[derive(Debug, Deserialize)]
struct SecurityAdvisoryVulnerabilities {
    nodes: Vec<Vulnerability>, // Future: vulnerability nodes processing
}

#[derive(Debug, Deserialize, Clone)]
struct Vulnerability {
    package: VulnerabilityPackage, // Future: package-specific vulnerability details
    #[serde(rename = "vulnerableVersionRange")]
    vulnerable_version_range: Option<String>, // Future: version range analysis
    #[serde(rename = "firstPatchedVersion")]
    first_patched_version: Option<FirstPatchedVersion>, // Future: patch version tracking
}

#[derive(Debug, Deserialize, Clone)]
struct VulnerabilityPackage {
    name: String, // Future: package name processing

    ecosystem: String, // Future: ecosystem-specific logic
}

#[derive(Debug, Deserialize, Clone)]
struct FirstPatchedVersion {
    identifier: String, // Future: patch version identifier processing
}

/// Client for GitHub Security Advisories GraphQL API
pub struct GhsaClient {
    client: Client,
    token: String,
    graphql_url: String,
}

/// Comprehensive error analysis structure for enhanced reporting
#[derive(Debug, Clone)]
pub struct GraphQLErrorAnalysis {
    pub error_count: usize,
    pub error_type: String,
    pub locations: Vec<(u32, u32)>,
    pub has_location_info: bool,
    pub primary_message: Option<String>,
    pub query_context: Option<String>,
    pub detailed_errors: Vec<DetailedGraphQLError>,
}

/// Detailed error information for individual GraphQL errors
#[derive(Debug, Clone)]
pub struct DetailedGraphQLError {
    pub message: String,
    pub locations: Vec<(u32, u32)>,
}

impl GraphQLError {
    /// Format error with location context for enhanced reporting
    fn format_with_context(&self, query_context: Option<&str>) -> String {
        let mut error_msg = format!("GraphQL Error: {}", self.message);

        if !self.locations.is_empty() {
            let locations: Vec<String> = self
                .locations
                .iter()
                .map(|loc| loc.format_location())
                .collect();
            error_msg.push_str(&format!(" (at {})", locations.join(", ")));
        }

        if let Some(context) = query_context {
            error_msg.push_str(&format!(" | Query context: {}", context));
        }

        error_msg
    }

    /// Get the primary location (first location if multiple exist)
    fn primary_location(&self) -> Option<&GraphQLLocation> {
        self.locations.first()
    }

    /// Check if this error has location information
    fn has_location_info(&self) -> bool {
        !self.locations.is_empty()
    }
}

impl GraphQLLocation {
    /// Format location as "line:column"
    fn format_location(&self) -> String {
        format!("line {}:column {}", self.line, self.column)
    }

    /// Get a tuple of (line, column) for programmatic use
    fn as_tuple(&self) -> (u32, u32) {
        (self.line, self.column)
    }
}

impl GhsaClient {
    /// Create a new GHSA client with the given token and GraphQL URL
    pub fn new(token: String, graphql_url: String) -> Result<Self, VulnerabilityError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("vulnera-rust/0.1.0")
            .build()
            .map_err(VulnerabilityError::Network)?;

        Ok(Self {
            client,
            token,
            graphql_url,
        })
    }

    /// Create a new GHSA client with default configuration
    pub fn default(token: String) -> Result<Self, VulnerabilityError> {
        Self::new(token, "https://api.github.com/graphql".to_string())
    }

    /// Convert domain ecosystem to GHSA ecosystem string
    fn ecosystem_to_ghsa_string(
        ecosystem: &crate::domain::vulnerability::value_objects::Ecosystem,
    ) -> &'static str {
        match ecosystem {
            crate::domain::vulnerability::value_objects::Ecosystem::Npm => "NPM",
            crate::domain::vulnerability::value_objects::Ecosystem::PyPI => "PIP",
            crate::domain::vulnerability::value_objects::Ecosystem::Maven => "MAVEN",
            crate::domain::vulnerability::value_objects::Ecosystem::Cargo => "RUST",
            crate::domain::vulnerability::value_objects::Ecosystem::Go => "GO",
            crate::domain::vulnerability::value_objects::Ecosystem::Packagist => "COMPOSER",
            crate::domain::vulnerability::value_objects::Ecosystem::RubyGems => "RUBYGEMS",
            crate::domain::vulnerability::value_objects::Ecosystem::NuGet => "NUGET",
        }
    }

    /// Execute a GraphQL query
    async fn execute_query<T>(
        &self,
        query: &str,
        variables: serde_json::Value,
    ) -> Result<T, VulnerabilityError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let request_body = GraphQLRequest {
            query: query.to_string(),
            variables,
        };

        // Determine token from environment at request time, falling back to configured token
        let token_opt = GHSA_REQ_TOKEN
            .try_with(|t| t.clone())
            .ok()
            .filter(|t| !t.is_empty())
            .or_else(|| {
                if !self.token.is_empty() {
                    Some(self.token.clone())
                } else {
                    None
                }
            });

        // Build request and add Authorization header only if token present
        let mut req = self
            .client
            .post(&self.graphql_url)
            .header("Content-Type", "application/json")
            .json(&request_body);

        if let Some(tok) = token_opt {
            req = req.header("Authorization", format!("Bearer {}", tok));
        } else {
            return Err(VulnerabilityError::Api(ApiError::Http {
                status: 401,
                message: "Missing GitHub token for GHSA lookups; set VULNERA__APIS__GHSA__TOKEN or provide Authorization/X-GHSA-Token".to_string(),
            }));
        }

        let response = req.send().await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let error_text = response.text().await.unwrap_or_default();
            return Err(VulnerabilityError::Api(ApiError::Http {
                status,
                message: format!("GitHub GraphQL API error: {}", error_text),
            }));
        }

        let graphql_response: GraphQLResponse<T> = response.json().await?;

        if let Some(errors) = graphql_response.errors {
            // Enhanced error reporting with comprehensive analysis
            let analysis = Self::analyze_graphql_errors(&errors, query);
            let error_summary = Self::create_error_summary(&errors);
            let error_count = errors.len();

            // Log comprehensive error analysis
            tracing::error!(
                error_count = analysis.error_count,
                error_type = %analysis.error_type,
                error_summary = %error_summary,
                has_locations = analysis.has_location_info,
                location_count = analysis.locations.len(),
                query_context = ?analysis.query_context,
                primary_message = ?analysis.primary_message,
                "GraphQL request failed with enhanced error analysis"
            );

            // Log individual errors with full context
            for (index, error) in errors.iter().enumerate() {
                if let Some(primary_loc) = error.primary_location() {
                    tracing::warn!(
                        error_index = index,
                        message = %error.message,
                        line = primary_loc.line,
                        column = primary_loc.column,
                        location_count = error.locations.len(),
                        query_context = ?analysis.query_context,
                        "GraphQL error with location information"
                    );
                } else {
                    tracing::warn!(
                        error_index = index,
                        message = %error.message,
                        query_context = ?analysis.query_context,
                        "GraphQL error without location information"
                    );
                }
            }

            // Create enhanced error messages for user-facing errors
            let detailed_messages: Vec<String> = errors
                .iter()
                .enumerate()
                .map(|(i, e)| {
                    let base_msg = e.format_with_context(analysis.query_context.as_deref());
                    if error_count > 1 {
                        format!("[{}] {}", i + 1, base_msg)
                    } else {
                        base_msg
                    }
                })
                .collect();

            return Err(VulnerabilityError::Api(ApiError::Http {
                status: 400,
                message: format!(
                    "GraphQL request failed [{}]: {} - Details: {}",
                    analysis.error_type,
                    error_summary,
                    detailed_messages.join(" | ")
                ),
            }));
        }

        graphql_response.data.ok_or_else(|| {
            VulnerabilityError::Api(ApiError::Http {
                status: 500,
                message: "No data in GraphQL response".to_string(),
            })
        })
    }

    /// Extract a brief context from the GraphQL query for error reporting
    fn extract_query_context(query: &str) -> Option<String> {
        // Extract the first line of the query (usually contains the operation name)
        let first_line = query.lines().next()?.trim();

        // If it's empty or just whitespace, try the next non-empty line
        if first_line.is_empty() {
            for line in query.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    return Some(format!("Operation: {}", trimmed));
                }
            }
        } else {
            return Some(format!("Operation: {}", first_line));
        }

        None
    }

    /// Create a detailed error summary for multiple GraphQL errors
    fn create_error_summary(errors: &[GraphQLError]) -> String {
        if errors.is_empty() {
            return "No errors".to_string();
        }

        if errors.len() == 1 {
            let error = &errors[0];
            return format!(
                "GraphQL error: {} {}",
                error.message,
                if let Some(loc) = error.primary_location() {
                    format!("at {}", loc.format_location())
                } else {
                    "(no location info)".to_string()
                }
            );
        }

        // Multiple errors - provide summary
        let with_locations = errors.iter().filter(|e| e.has_location_info()).count();
        format!(
            "{} GraphQL errors (locations available for {}/{})",
            errors.len(),
            with_locations,
            errors.len()
        )
    }

    /// Get the most relevant error from a collection (prioritizes errors with location info)
    fn get_primary_error(errors: &[GraphQLError]) -> Option<&GraphQLError> {
        if errors.is_empty() {
            return None;
        }

        // Prefer errors with location information
        errors
            .iter()
            .find(|e| e.has_location_info())
            .or_else(|| errors.first())
    }

    /// Extract all unique error locations from a set of errors
    fn extract_error_locations(errors: &[GraphQLError]) -> Vec<(u32, u32)> {
        let mut locations = Vec::new();
        for error in errors {
            for location in &error.locations {
                let tuple = location.as_tuple();
                if !locations.contains(&tuple) {
                    locations.push(tuple);
                }
            }
        }
        locations.sort();
        locations
    }

    /// Check if errors indicate a query syntax issue vs data/permission issue
    fn classify_error_type(errors: &[GraphQLError]) -> &'static str {
        for error in errors {
            let msg = error.message.to_lowercase();
            if msg.contains("syntax") || msg.contains("parse") || error.has_location_info() {
                return "syntax";
            } else if msg.contains("permission")
                || msg.contains("unauthorized")
                || msg.contains("forbidden")
            {
                return "authorization";
            } else if msg.contains("not found") || msg.contains("does not exist") {
                return "not_found";
            }
        }
        "unknown"
    }

    /// Provide comprehensive error analysis for debugging and monitoring
    fn analyze_graphql_errors(errors: &[GraphQLError], query: &str) -> GraphQLErrorAnalysis {
        let error_type = Self::classify_error_type(errors);
        let locations = Self::extract_error_locations(errors);
        let primary_error = Self::get_primary_error(errors);
        let query_context = Self::extract_query_context(query);

        GraphQLErrorAnalysis {
            error_count: errors.len(),
            error_type: error_type.to_string(),
            locations,
            has_location_info: errors.iter().any(|e| e.has_location_info()),
            primary_message: primary_error.map(|e| e.message.clone()),
            query_context,
            detailed_errors: errors
                .iter()
                .map(|e| DetailedGraphQLError {
                    message: e.message.clone(),
                    locations: e.locations.iter().map(|l| (l.line, l.column)).collect(),
                })
                .collect(),
        }
    }

    /// Query security advisories for a specific package
    pub async fn security_advisories(
        &self,
        package_name: &str,
        ecosystem: &str,
        first: u32,
        after: Option<&str>,
    ) -> Result<SecurityAdvisoriesConnection, VulnerabilityError> {
        let query = r#"
            query SecurityAdvisories($packageName: String!, $ecosystem: SecurityAdvisoryEcosystem!, $first: Int!, $after: String) {
                securityAdvisories: securityVulnerabilities(
                    first: $first
                    after: $after
                    orderBy: { field: UPDATED_AT, direction: DESC }
                    package: $packageName
                    ecosystem: $ecosystem
                ) {
                    nodes {
                        advisory {
                            ghsaId
                            summary
                            description
                            severity
                            publishedAt
                            references { url }
                        }
                        package { name ecosystem }
                        vulnerableVersionRange
                        firstPatchedVersion { identifier }
                    }
                    pageInfo { hasNextPage endCursor }
                }
            }
        "#;

        let mut variables = serde_json::json!({
            "packageName": package_name,
            "ecosystem": ecosystem,
            "first": first
        });

        if let Some(cursor) = after {
            variables["after"] = serde_json::Value::String(cursor.to_string());
        }

        // Fetch as raw JSON and adapt to our existing advisory-shaped model; we will group later.
        let raw: serde_json::Value = self.execute_query(query, variables).await?;

        let page_info: PageInfo =
            serde_json::from_value(raw["securityAdvisories"]["pageInfo"].clone()).map_err(|e| {
                tracing::error!(
                    error = %e,
                    package_name = %package_name,
                    ecosystem = %ecosystem,
                    "Failed to parse GHSA pageInfo structure"
                );
                VulnerabilityError::Api(ApiError::Http {
                    status: 500,
                    message: format!(
                        "Invalid GHSA pageInfo shape for {}/{}: {}",
                        ecosystem, package_name, e
                    ),
                })
            })?;

        let mut nodes: Vec<SecurityAdvisory> = Vec::new();
        if let Some(items) = raw["securityAdvisories"]["nodes"].as_array() {
            for item in items {
                let advisory = &item["advisory"];
                let ghsa_id = advisory["ghsaId"].as_str().unwrap_or_default().to_string();
                let summary = advisory["summary"].as_str().unwrap_or_default().to_string();
                let description = advisory["description"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let severity = advisory["severity"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let published_at = advisory["publishedAt"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();

                let references: Vec<Reference> = advisory["references"]
                    .as_array()
                    .unwrap_or(&Vec::new())
                    .iter()
                    .filter_map(|r| r.get("url").and_then(|u| u.as_str()))
                    .map(|url| Reference {
                        url: url.to_string(),
                    })
                    .collect();

                let package = VulnerabilityPackage {
                    name: item["package"]["name"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    ecosystem: item["package"]["ecosystem"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                };
                let vulnerable_version_range = item["vulnerableVersionRange"]
                    .as_str()
                    .map(|s| s.to_string());
                let first_patched_version =
                    item["firstPatchedVersion"]["identifier"]
                        .as_str()
                        .map(|id| FirstPatchedVersion {
                            identifier: id.to_string(),
                        });

                let vuln = Vulnerability {
                    package,
                    vulnerable_version_range,
                    first_patched_version,
                };

                nodes.push(SecurityAdvisory {
                    ghsa_id,
                    summary,
                    description,
                    severity,
                    published_at,
                    references,
                    vulnerabilities: SecurityAdvisoryVulnerabilities { nodes: vec![vuln] },
                });
            }
        }

        Ok(SecurityAdvisoriesConnection { nodes, page_info })
    }

    /// Convert GHSA security advisory to RawVulnerability
    fn convert_ghsa_advisory(advisory: SecurityAdvisory) -> RawVulnerability {
        use super::traits::{AffectedPackageData, PackageInfo, VersionEventData, VersionRangeData};

        let references = advisory.references.into_iter().map(|r| r.url).collect();

        let published_at = chrono::DateTime::parse_from_rfc3339(&advisory.published_at)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc));

        // Map GHSA vulnerabilities to affected package data with fixed events
        let affected = advisory
            .vulnerabilities
            .nodes
            .into_iter()
            .map(|v| {
                // Map GHSA ecosystem values to strings understood by our aggregator
                // NPM -> "npm", PIP -> "PyPI", MAVEN -> "Maven", RUST -> "crates.io",
                // GO -> "Go", COMPOSER -> "Packagist", RUBYGEMS -> "RubyGems", NUGET -> "NuGet"
                let ecosystem = match v.package.ecosystem.as_str() {
                    "NPM" => "npm".to_string(),
                    "PIP" => "PyPI".to_string(),
                    "MAVEN" => "Maven".to_string(),
                    "RUST" => "crates.io".to_string(),
                    "GO" => "Go".to_string(),
                    "COMPOSER" => "Packagist".to_string(),
                    "RUBYGEMS" => "RubyGems".to_string(),
                    "NUGET" => "NuGet".to_string(),
                    other => other.to_string(),
                };

                // Build precise events from GHSA vulnerable_version_range and firstPatchedVersion.
                // Supports OR segments (||) and comma-separated constraints within each segment.
                let mut ranges: Option<Vec<VersionRangeData>> = None;
                if let Some(range_str) = v.vulnerable_version_range.as_ref() {
                    let mut out: Vec<VersionRangeData> = Vec::new();

                    for or_part in range_str.split("||") {
                        let mut introduced: Option<String> = None;
                        let mut fixed: Option<String> = None;
                        let mut last_affected: Option<String> = None;

                        for token in or_part.split(',') {
                            let t = token.trim();
                            if let Some(rest) = t.strip_prefix(">=") {
                                introduced = Some(rest.trim().to_string());
                            } else if let Some(rest) = t.strip_prefix('>') {
                                // Approximate strict lower bound as introduced at this version
                                introduced = Some(rest.trim().to_string());
                            } else if let Some(rest) = t.strip_prefix("<=") {
                                last_affected = Some(rest.trim().to_string());
                            } else if let Some(rest) = t.strip_prefix('<') {
                                fixed = Some(rest.trim().to_string());
                            } else if let Some(rest) = t.strip_prefix('=') {
                                // Exact version: introduced == last_affected == that version
                                let vstr = rest.trim().to_string();
                                introduced = Some(vstr.clone());
                                last_affected = Some(vstr);
                            }
                        }

                        // Prefer explicit first patched version if present
                        if fixed.is_none() {
                            if let Some(fp) = v.first_patched_version.as_ref() {
                                fixed = Some(fp.identifier.clone());
                            }
                        }

                        let mut events: Vec<VersionEventData> = Vec::new();
                        let has_upper = fixed.is_some() || last_affected.is_some();
                        if introduced.is_none() && has_upper {
                            introduced = Some("0".to_string());
                        }

                        if let Some(intro) = introduced {
                            events.push(VersionEventData {
                                event_type: "introduced".to_string(),
                                value: intro,
                            });
                        }
                        if let Some(f) = fixed {
                            events.push(VersionEventData {
                                event_type: "fixed".to_string(),
                                value: f,
                            });
                        } else if let Some(la) = last_affected {
                            events.push(VersionEventData {
                                event_type: "last_affected".to_string(),
                                value: la,
                            });
                        }

                        if !events.is_empty() {
                            out.push(VersionRangeData {
                                range_type: "SEMVER".to_string(),
                                repo: None,
                                events,
                            });
                        }
                    }

                    if !out.is_empty() {
                        ranges = Some(out);
                    }
                } else if let Some(fp) = v.first_patched_version.as_ref() {
                    // If only firstPatchedVersion exists, assume 0..fixed
                    let events = vec![
                        VersionEventData {
                            event_type: "introduced".to_string(),
                            value: "0".to_string(),
                        },
                        VersionEventData {
                            event_type: "fixed".to_string(),
                            value: fp.identifier.clone(),
                        },
                    ];
                    ranges = Some(vec![VersionRangeData {
                        range_type: "SEMVER".to_string(),
                        repo: None,
                        events,
                    }]);
                }

                AffectedPackageData {
                    package: PackageInfo {
                        name: v.package.name,
                        ecosystem,
                        purl: None,
                    },
                    ranges,
                    versions: None,
                }
            })
            .collect();

        RawVulnerability {
            id: advisory.ghsa_id,
            summary: advisory.summary,
            description: advisory.description,
            severity: Some(advisory.severity),
            references,
            published_at,
            affected,
        }
    }

    /// Get all security advisories for a package with pagination
    async fn get_all_advisories_for_package(
        &self,
        package: &Package,
    ) -> Result<Vec<SecurityAdvisory>, VulnerabilityError> {
        let ecosystem = Self::ecosystem_to_ghsa_string(&package.ecosystem);
        let mut all_advisories = Vec::new();
        let mut cursor: Option<String> = None;
        let page_size = 50; // GitHub's maximum

        loop {
            let connection = self
                .security_advisories(&package.name, ecosystem, page_size, cursor.as_deref())
                .await?;

            all_advisories.extend(connection.nodes);

            if !connection.page_info.has_next_page {
                break;
            }

            cursor = connection.page_info.end_cursor;
        }

        // Group by GHSA ID to merge vulnerability nodes belonging to the same advisory
        let mut by_id: std::collections::HashMap<String, SecurityAdvisory> =
            std::collections::HashMap::new();
        for adv in all_advisories {
            by_id
                .entry(adv.ghsa_id.clone())
                .and_modify(|existing| {
                    existing
                        .vulnerabilities
                        .nodes
                        .extend(adv.vulnerabilities.nodes.clone());
                })
                .or_insert(adv);
        }

        Ok(by_id.into_values().collect())
    }
}

#[async_trait]
impl VulnerabilityApiClient for GhsaClient {
    async fn query_vulnerabilities(
        &self,
        package: &Package,
    ) -> Result<Vec<RawVulnerability>, VulnerabilityError> {
        let advisories = self.get_all_advisories_for_package(package).await?;

        let vulnerabilities = advisories
            .into_iter()
            .map(Self::convert_ghsa_advisory)
            .collect();

        Ok(vulnerabilities)
    }

    async fn get_vulnerability_details(
        &self,
        id: &str,
    ) -> Result<Option<RawVulnerability>, VulnerabilityError> {
        // GHSA IDs are in format GHSA-xxxx-xxxx-xxxx
        if !id.starts_with("GHSA-") {
            return Ok(None);
        }

        let query = r#"
            query SecurityAdvisory($ghsaId: String!) {
                securityAdvisory(ghsaId: $ghsaId) {
                    ghsaId
                    summary
                    description
                    severity
                    publishedAt
                    references {
                        url
                    }
                    vulnerabilities(first: 10) {
                        nodes {
                            package {
                                name
                                ecosystem
                            }
                            vulnerableVersionRange
                            firstPatchedVersion {
                                identifier
                            }
                        }
                    }
                }
            }
        "#;

        let variables = serde_json::json!({
            "ghsaId": id
        });

        #[derive(Debug, Deserialize)]
        struct SecurityAdvisoryResponse {
            #[serde(rename = "securityAdvisory")]
            security_advisory: Option<SecurityAdvisory>,
        }

        let response: SecurityAdvisoryResponse = self.execute_query(query, variables).await?;

        if let Some(advisory) = response.security_advisory {
            let vulnerability = Self::convert_ghsa_advisory(advisory);
            Ok(Some(vulnerability))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vulnerability::value_objects::{Ecosystem, Version};
    use mockito::Server;
    use serde_json::json;

    fn create_test_package() -> Package {
        Package::new(
            "express".to_string(),
            Version::parse("4.17.1").unwrap(),
            Ecosystem::Npm,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_security_advisories_success() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "data": {
                "securityAdvisories": {
                    "nodes": [
                        {
                            "advisory": {
                                "ghsaId": "GHSA-xxxx-xxxx-xxxx",
                                "summary": "Test vulnerability",
                                "description": "A test vulnerability for unit testing",
                                "severity": "HIGH",
                                "publishedAt": "2022-01-01T00:00:00Z",
                                "references": [
                                    {
                                        "url": "https://example.com/advisory"
                                    }
                                ]
                            },
                            "package": {
                                "name": "express",
                                "ecosystem": "NPM"
                            },
                            "vulnerableVersionRange": "< 4.18.0",
                            "firstPatchedVersion": {
                                "identifier": "4.18.0"
                            }
                        }
                    ],
                    "pageInfo": {
                        "hasNextPage": false,
                        "endCursor": null
                    }
                }
            }
        });

        let mock = server
            .mock("POST", "/graphql")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = GhsaClient::new(
            "test-token".to_string(),
            format!("{}/graphql", server.url()),
        )
        .expect("Failed to create test client");

        let result = client.security_advisories("express", "NPM", 50, None).await;

        mock.assert_async().await;
        assert!(result.is_ok());

        let connection = result.unwrap();
        assert_eq!(connection.nodes.len(), 1);

        let advisory = &connection.nodes[0];
        assert_eq!(advisory.ghsa_id, "GHSA-xxxx-xxxx-xxxx");
        assert_eq!(advisory.summary, "Test vulnerability");
        assert_eq!(advisory.severity, "HIGH");
        assert!(!connection.page_info.has_next_page);
    }

    #[tokio::test]
    async fn test_query_vulnerabilities_success() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "data": {
                "securityAdvisories": {
                    "nodes": [
                        {
                            "advisory": {
                                "ghsaId": "GHSA-xxxx-xxxx-xxxx",
                                "summary": "Test vulnerability",
                                "description": "A test vulnerability for unit testing",
                                "severity": "HIGH",
                                "publishedAt": "2022-01-01T00:00:00Z",
                                "references": [
                                    {
                                        "url": "https://example.com/advisory"
                                    }
                                ]
                            },
                            "package": {
                                "name": "express",
                                "ecosystem": "NPM"
                            },
                            "vulnerableVersionRange": "< 4.18.0",
                            "firstPatchedVersion": {
                                "identifier": "4.18.0"
                            }
                        }
                    ],
                    "pageInfo": {
                        "hasNextPage": false,
                        "endCursor": null
                    }
                }
            }
        });

        let mock = server
            .mock("POST", "/graphql")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = GhsaClient::new(
            "test-token".to_string(),
            format!("{}/graphql", server.url()),
        )
        .expect("Failed to create test client");
        let package = create_test_package();

        let result = client.query_vulnerabilities(&package).await;

        mock.assert_async().await;
        assert!(result.is_ok());

        let vulnerabilities = result.unwrap();
        assert_eq!(vulnerabilities.len(), 1);

        let vuln = &vulnerabilities[0];
        assert_eq!(vuln.id, "GHSA-xxxx-xxxx-xxxx");
        assert_eq!(vuln.summary, "Test vulnerability");
        assert_eq!(vuln.severity, Some("HIGH".to_string()));
        assert_eq!(vuln.references.len(), 1);
        assert!(vuln.published_at.is_some());
    }

    #[tokio::test]
    async fn test_get_vulnerability_details_success() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "data": {
                "securityAdvisory": {
                    "ghsaId": "GHSA-xxxx-xxxx-xxxx",
                    "summary": "Test vulnerability",
                    "description": "A test vulnerability for unit testing",
                    "severity": "HIGH",
                    "publishedAt": "2022-01-01T00:00:00Z",
                    "references": [
                        {
                            "url": "https://example.com/advisory"
                        }
                    ],
                    "vulnerabilities": {
                        "nodes": []
                    }
                }
            }
        });

        let mock = server
            .mock("POST", "/graphql")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = GhsaClient::new(
            "test-token".to_string(),
            format!("{}/graphql", server.url()),
        )
        .expect("Failed to create test client");

        let result = client
            .get_vulnerability_details("GHSA-xxxx-xxxx-xxxx")
            .await;

        mock.assert_async().await;
        assert!(result.is_ok());

        let vulnerability = result.unwrap();
        assert!(vulnerability.is_some());

        let vuln = vulnerability.unwrap();
        assert_eq!(vuln.id, "GHSA-xxxx-xxxx-xxxx");
        assert_eq!(vuln.summary, "Test vulnerability");
        assert_eq!(vuln.severity, Some("HIGH".to_string()));
    }

    #[tokio::test]
    async fn test_get_vulnerability_details_not_found() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "data": {
                "securityAdvisory": null
            }
        });

        let mock = server
            .mock("POST", "/graphql")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = GhsaClient::new(
            "test-token".to_string(),
            format!("{}/graphql", server.url()),
        )
        .expect("Failed to create test client");

        let result = client
            .get_vulnerability_details("GHSA-nonexistent-xxxx")
            .await;

        mock.assert_async().await;
        assert!(result.is_ok());

        let vulnerability = result.unwrap();
        assert!(vulnerability.is_none());
    }

    #[tokio::test]
    async fn test_get_vulnerability_details_invalid_id() {
        let client = GhsaClient::new(
            "test-token".to_string(),
            "https://api.github.com/graphql".to_string(),
        )
        .expect("Failed to create test client");

        let result = client.get_vulnerability_details("CVE-2022-24999").await;

        assert!(result.is_ok());
        let vulnerability = result.unwrap();
        assert!(vulnerability.is_none());
    }

    #[tokio::test]
    async fn test_security_advisories_requires_token() {
        let server = Server::new_async().await;

        // Minimal GraphQL error response isn't needed; client returns 401 before calling server
        let client = GhsaClient::new("".to_string(), format!("{}/graphql", server.url()))
            .expect("Failed to create test client");

        let result = client.security_advisories("express", "NPM", 1, None).await;

        // Expect a 401 error due to missing token
        assert!(result.is_err());
        match result.unwrap_err() {
            VulnerabilityError::Api(ApiError::Http { status, message }) => {
                assert_eq!(status, 401);
                assert!(
                    message.contains("Missing GitHub token"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_with_request_scoped_token_applies_authorization_header() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "data": {
                "securityAdvisories": {
                    "nodes": [],
                    "pageInfo": {
                        "hasNextPage": false,
                        "endCursor": null
                    }
                }
            }
        });

        let mock = server
            .mock("POST", "/graphql")
            .match_header("authorization", "Bearer scoped-token-123")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = GhsaClient::new("".to_string(), format!("{}/graphql", server.url()))
            .expect("Failed to create test client");

        let result = crate::infrastructure::api_clients::ghsa::with_request_ghsa_token(
            "scoped-token-123".to_string(),
            async { client.security_advisories("express", "NPM", 1, None).await },
        )
        .await;

        mock.assert_async().await;
        assert!(result.is_ok());
        let connection = result.unwrap();
        assert_eq!(connection.nodes.len(), 0);
        assert!(!connection.page_info.has_next_page);
    }

    #[tokio::test]
    async fn test_graphql_error_handling() {
        let mut server = Server::new_async().await;

        let mock_response = json!({
            "errors": [
                {
                    "message": "Field 'invalidField' doesn't exist on type 'Query'",
                    "locations": [
                        {
                            "line": 2,
                            "column": 3
                        }
                    ]
                }
            ]
        });

        let mock = server
            .mock("POST", "/graphql")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .expect(1)
            .create_async()
            .await;

        let client = GhsaClient::new(
            "test-token".to_string(),
            format!("{}/graphql", server.url()),
        )
        .expect("Failed to create test client");

        let result = client.security_advisories("express", "NPM", 50, None).await;

        mock.assert_async().await;
        assert!(result.is_err());

        match result.unwrap_err() {
            VulnerabilityError::Api(ApiError::Http { message, .. }) => {
                assert!(message.contains("GraphQL request failed"));
                assert!(message.contains("Field 'invalidField' doesn't exist"));
                assert!(message.contains("line 2:column 3"));
            }
            _ => panic!("Expected GraphQL error"),
        }
    }

    #[test]
    fn test_ecosystem_conversion() {
        assert_eq!(GhsaClient::ecosystem_to_ghsa_string(&Ecosystem::Npm), "NPM");
        assert_eq!(
            GhsaClient::ecosystem_to_ghsa_string(&Ecosystem::PyPI),
            "PIP"
        );
        assert_eq!(
            GhsaClient::ecosystem_to_ghsa_string(&Ecosystem::Maven),
            "MAVEN"
        );
        assert_eq!(
            GhsaClient::ecosystem_to_ghsa_string(&Ecosystem::Cargo),
            "RUST"
        );
        assert_eq!(GhsaClient::ecosystem_to_ghsa_string(&Ecosystem::Go), "GO");
        assert_eq!(
            GhsaClient::ecosystem_to_ghsa_string(&Ecosystem::Packagist),
            "COMPOSER"
        );
        assert_eq!(
            GhsaClient::ecosystem_to_ghsa_string(&Ecosystem::RubyGems),
            "RUBYGEMS"
        );
        assert_eq!(
            GhsaClient::ecosystem_to_ghsa_string(&Ecosystem::NuGet),
            "NUGET"
        );
    }

    #[test]
    fn test_convert_ghsa_advisory() {
        let advisory = SecurityAdvisory {
            ghsa_id: "GHSA-xxxx-xxxx-xxxx".to_string(),
            summary: "Test vulnerability".to_string(),
            description: "A test vulnerability for unit testing".to_string(),
            severity: "HIGH".to_string(),
            published_at: "2022-01-01T00:00:00Z".to_string(),
            references: vec![Reference {
                url: "https://example.com".to_string(),
            }],
            vulnerabilities: SecurityAdvisoryVulnerabilities { nodes: vec![] },
        };

        let raw_vuln = GhsaClient::convert_ghsa_advisory(advisory);

        assert_eq!(raw_vuln.id, "GHSA-xxxx-xxxx-xxxx");
        assert_eq!(raw_vuln.summary, "Test vulnerability");
        assert_eq!(
            raw_vuln.description,
            "A test vulnerability for unit testing"
        );
        assert_eq!(raw_vuln.severity, Some("HIGH".to_string()));
        assert_eq!(raw_vuln.references.len(), 1);
        assert!(raw_vuln.published_at.is_some());
    }

    // Enhanced Error Reporting Tests
    #[test]
    fn test_graphql_location_formatting() {
        let location = GraphQLLocation {
            line: 10,
            column: 25,
        };
        assert_eq!(location.format_location(), "line 10:column 25");
        assert_eq!(location.as_tuple(), (10, 25));
    }

    #[test]
    fn test_graphql_error_without_location() {
        let error = GraphQLError {
            message: "Field 'invalid' not found".to_string(),
            locations: vec![],
        };

        assert!(!error.has_location_info());
        assert_eq!(error.primary_location(), None);

        let formatted = error.format_with_context(Some("query getPackage"));
        assert!(formatted.contains("Field 'invalid' not found"));
        assert!(formatted.contains("Query context: query getPackage"));
    }

    #[test]
    fn test_graphql_error_with_location() {
        let error = GraphQLError {
            message: "Syntax error".to_string(),
            locations: vec![
                GraphQLLocation {
                    line: 5,
                    column: 12,
                },
                GraphQLLocation { line: 8, column: 3 },
            ],
        };

        assert!(error.has_location_info());
        assert_eq!(error.primary_location().unwrap().line, 5);

        let formatted = error.format_with_context(None);
        assert!(formatted.contains("Syntax error"));
        assert!(formatted.contains("line 5:column 12"));
        assert!(formatted.contains("line 8:column 3"));
    }

    #[test]
    fn test_query_context_extraction() {
        let query1 =
            "query getSecurityAdvisories($packageName: String!) {\n  securityAdvisories\n}";
        let context1 = GhsaClient::extract_query_context(query1);
        assert_eq!(
            context1,
            Some("Operation: query getSecurityAdvisories($packageName: String!) {".to_string())
        );

        let query2 = "\n\n  # Comment\n  mutation updatePackage {\n    update\n  }";
        let context2 = GhsaClient::extract_query_context(query2);
        assert_eq!(
            context2,
            Some("Operation: mutation updatePackage {".to_string())
        );

        let empty_query = "";
        let context3 = GhsaClient::extract_query_context(empty_query);
        assert_eq!(context3, None);
    }

    #[test]
    fn test_error_type_classification() {
        let syntax_errors = vec![GraphQLError {
            message: "Syntax error in query".to_string(),
            locations: vec![GraphQLLocation { line: 1, column: 1 }],
        }];
        assert_eq!(GhsaClient::classify_error_type(&syntax_errors), "syntax");

        let auth_errors = vec![GraphQLError {
            message: "Unauthorized access".to_string(),
            locations: vec![],
        }];
        assert_eq!(
            GhsaClient::classify_error_type(&auth_errors),
            "authorization"
        );

        let not_found_errors = vec![GraphQLError {
            message: "Package not found".to_string(),
            locations: vec![],
        }];
        assert_eq!(
            GhsaClient::classify_error_type(&not_found_errors),
            "not_found"
        );

        let unknown_errors = vec![GraphQLError {
            message: "Something went wrong".to_string(),
            locations: vec![],
        }];
        assert_eq!(GhsaClient::classify_error_type(&unknown_errors), "unknown");
    }

    #[test]
    fn test_error_locations_extraction() {
        let errors = vec![
            GraphQLError {
                message: "Error 1".to_string(),
                locations: vec![
                    GraphQLLocation {
                        line: 5,
                        column: 10,
                    },
                    GraphQLLocation { line: 3, column: 2 },
                ],
            },
            GraphQLError {
                message: "Error 2".to_string(),
                locations: vec![
                    GraphQLLocation {
                        line: 5,
                        column: 10,
                    }, // Duplicate
                    GraphQLLocation {
                        line: 7,
                        column: 15,
                    },
                ],
            },
        ];

        let locations = GhsaClient::extract_error_locations(&errors);
        assert_eq!(locations, vec![(3, 2), (5, 10), (7, 15)]); // Sorted and deduplicated
    }

    #[test]
    fn test_comprehensive_error_analysis() {
        let errors = vec![
            GraphQLError {
                message: "Parse error at position".to_string(),
                locations: vec![GraphQLLocation { line: 3, column: 5 }],
            },
            GraphQLError {
                message: "Type mismatch".to_string(),
                locations: vec![],
            },
        ];

        let query = "query test { field }";
        let analysis = GhsaClient::analyze_graphql_errors(&errors, query);

        assert_eq!(analysis.error_count, 2);
        assert_eq!(analysis.error_type, "syntax");
        assert!(analysis.has_location_info);
        assert_eq!(analysis.locations, vec![(3, 5)]);
        assert_eq!(
            analysis.primary_message,
            Some("Parse error at position".to_string())
        );
        assert!(analysis.query_context.is_some());
        assert_eq!(analysis.detailed_errors.len(), 2);
    }

    #[test]
    fn test_error_summary_creation() {
        let no_errors: Vec<GraphQLError> = vec![];
        assert_eq!(GhsaClient::create_error_summary(&no_errors), "No errors");

        let single_error = vec![GraphQLError {
            message: "Single error".to_string(),
            locations: vec![GraphQLLocation { line: 1, column: 1 }],
        }];
        let summary = GhsaClient::create_error_summary(&single_error);
        assert!(summary.contains("Single error"));
        assert!(summary.contains("line 1:column 1"));

        let multiple_errors = vec![
            GraphQLError {
                message: "Error 1".to_string(),
                locations: vec![GraphQLLocation { line: 1, column: 1 }],
            },
            GraphQLError {
                message: "Error 2".to_string(),
                locations: vec![],
            },
        ];
        let summary = GhsaClient::create_error_summary(&multiple_errors);
        assert!(summary.contains("2 GraphQL errors"));
        assert!(summary.contains("locations available for 1/2"));
    }
}
