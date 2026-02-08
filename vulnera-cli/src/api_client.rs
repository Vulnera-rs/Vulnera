//! API Client - HTTP client for Vulnera server communication
//!
//! This module provides a client for interacting with the Vulnera server API
//! for features that require server connectivity:
//! - Dependency vulnerability analysis
//! - API key verification
//! - Quota synchronization

use anyhow::{Context, Result};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::constants::{DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_TIMEOUT_SECS, USER_AGENT};

/// API client for Vulnera server
#[derive(Clone)]
pub struct VulneraClient {
    client: Client,
    base_url: String,
    api_key: Option<String>,
}

/// Individual dependency file for analysis
#[derive(Debug, Serialize)]
pub struct DependencyFileRequest {
    pub filename: String,
    pub file_content: String,
    pub ecosystem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_path: Option<String>,
}

/// Batch dependency analysis request matching server API
#[derive(Debug, Serialize)]
pub struct BatchDependencyAnalysisRequest {
    pub files: Vec<DependencyFileRequest>,
    #[serde(default)]
    pub enable_cache: bool,
    #[serde(default)]
    pub compact_mode: bool,
}

/// Response from dependency analysis
#[derive(Debug, Deserialize)]
pub struct DependencyAnalysisResponse {
    pub results: Vec<FileAnalysisResult>,
    pub metadata: BatchAnalysisMetadata,
}

/// Analysis result for a single file
#[derive(Debug, Deserialize)]
pub struct FileAnalysisResult {
    pub filename: String,
    pub ecosystem: String,
    pub vulnerabilities: Vec<VulnerabilityDto>,
    pub packages: Vec<PackageDto>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Vulnerability information from server
#[derive(Debug, Clone, Deserialize)]
pub struct VulnerabilityDto {
    pub id: String,
    pub severity: String,
    pub description: String,
    #[serde(default)]
    pub cvss_score: Option<f32>,
    #[serde(default)]
    pub fixed_version: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

/// Package information from server
#[derive(Debug, Clone, Deserialize)]
pub struct PackageDto {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub is_direct: bool,
    #[serde(default)]
    pub vulnerabilities: Vec<String>,
}

/// Batch analysis metadata
#[derive(Debug, Deserialize)]
pub struct BatchAnalysisMetadata {
    pub total_files: usize,
    pub successful: usize,
    pub failed: usize,
    pub duration_ms: u64,
}

/// API key verification response
#[derive(Debug, Deserialize)]
pub struct VerifyApiKeyResponse {
    pub valid: bool,
    pub user_id: Option<String>,
    pub tier: Option<String>,
    pub daily_limit: Option<u32>,
}

/// Quota status response
#[derive(Debug, Deserialize)]
pub struct QuotaStatusResponse {
    pub used: u32,
    pub limit: u32,
    pub remaining: u32,
    pub resets_at: String,
}

/// Request for the server's LLM code fix endpoint (`POST /api/v1/llm/fix`)
#[derive(Debug, Serialize)]
pub struct LlmFixRequest {
    pub vulnerability_id: String,
    pub vulnerable_code: String,
    pub language: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

/// Response from the server's LLM code fix endpoint
#[derive(Debug, Deserialize)]
pub struct LlmFixResponse {
    pub fixed_code: String,
    pub explanation: String,
    pub confidence: Option<f64>,
}

/// Error response from server
#[derive(Debug, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(default)]
    pub details: Option<String>,
}

/// Simplified dependency analysis response for CLI
#[derive(Debug, Deserialize)]
pub struct SimpleDepsResponse {
    pub vulnerabilities: Vec<SimpleVulnerability>,
    pub dependencies: Vec<SimpleDependency>,
}

/// Simplified vulnerability for CLI
#[derive(Debug, Clone, Deserialize)]
pub struct SimpleVulnerability {
    pub id: String,
    pub severity: String,
    pub package: String,
    pub version: String,
    pub description: String,
    pub cve: Option<String>,
    pub cvss_score: Option<f32>,
    pub fixed_version: Option<String>,
    pub references: Option<Vec<String>>,
}

/// Simplified dependency for CLI
#[derive(Debug, Clone, Deserialize)]
pub struct SimpleDependency {
    pub name: String,
    pub version: String,
    pub is_direct: bool,
    pub is_dev: bool,
    pub latest_version: Option<String>,
    pub is_outdated: bool,
}

impl VulneraClient {
    /// Create a new API client
    pub fn new(host: String, port: u16, api_key: Option<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
            .user_agent(USER_AGENT)
            .build()
            .context("Failed to create HTTP client")?;

        // Construct base URL from host and port
        let base_url = if host.starts_with("http://") || host.starts_with("https://") {
            if port == 443 || port == 80 {
                host
            } else {
                format!("{}:{}", host.trim_end_matches('/'), port)
            }
        } else if port == 443 {
            format!("https://{}", host)
        } else {
            format!("http://{}:{}", host, port)
        };

        Ok(Self {
            client,
            base_url,
            api_key,
        })
    }

    /// Create with a full URL (for testing)
    pub fn with_url(base_url: String, api_key: Option<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
            .user_agent(USER_AGENT)
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            client,
            base_url,
            api_key,
        })
    }

    /// Set the API key for authenticated requests
    pub fn with_api_key(mut self, api_key: String) -> Self {
        self.api_key = Some(api_key);
        self
    }

    /// Analyze dependencies from a project path
    pub async fn analyze_dependencies(
        &self,
        path: &std::path::Path,
        package_manager: Option<&str>,
        _include_transitive: bool,
    ) -> Result<SimpleDepsResponse> {
        // Find and read dependency files
        let files = self.collect_dependency_files(path, package_manager)?;
        if files.is_empty() {
            return Ok(SimpleDepsResponse {
                vulnerabilities: Vec::new(),
                dependencies: Vec::new(),
            });
        }

        let response = self.analyze_dependencies_raw(files).await?;

        // Convert to simplified response
        let mut vulnerabilities = Vec::new();
        let mut dependencies = Vec::new();

        for result in response.results {
            for vuln in result.vulnerabilities {
                vulnerabilities.push(SimpleVulnerability {
                    id: vuln.id,
                    severity: vuln.severity,
                    package: String::new(), // Will be filled from packages
                    version: String::new(),
                    description: vuln.description,
                    cve: None,
                    cvss_score: vuln.cvss_score,
                    fixed_version: vuln.fixed_version,
                    references: Some(vuln.references),
                });
            }

            for pkg in result.packages {
                dependencies.push(SimpleDependency {
                    name: pkg.name.clone(),
                    version: pkg.version.clone(),
                    is_direct: pkg.is_direct,
                    is_dev: false,
                    latest_version: None,
                    is_outdated: false,
                });

                // Fill in vulnerability package info
                for vuln_id in &pkg.vulnerabilities {
                    if let Some(vuln) = vulnerabilities.iter_mut().find(|v| &v.id == vuln_id) {
                        vuln.package = pkg.name.clone();
                        vuln.version = pkg.version.clone();
                    }
                }
            }
        }

        Ok(SimpleDepsResponse {
            vulnerabilities,
            dependencies,
        })
    }

    /// Collect dependency files from a path
    fn collect_dependency_files(
        &self,
        path: &std::path::Path,
        package_manager: Option<&str>,
    ) -> Result<Vec<DependencyFileRequest>> {
        let mut files = Vec::new();

        let manifest_names: Vec<&str> = match package_manager {
            Some("npm") | Some("yarn") | Some("pnpm") => vec!["package.json", "package-lock.json"],
            Some("cargo") => vec!["Cargo.toml", "Cargo.lock"],
            Some("pip") | Some("pipenv") | Some("poetry") => {
                vec!["requirements.txt", "Pipfile", "pyproject.toml"]
            }
            Some("maven") => vec!["pom.xml"],
            Some("gradle") => vec!["build.gradle", "build.gradle.kts"],
            Some("go") => vec!["go.mod", "go.sum"],
            _ => vec![
                "package.json",
                "Cargo.toml",
                "requirements.txt",
                "pom.xml",
                "go.mod",
            ],
        };

        for name in manifest_names {
            let file_path = path.join(name);
            if file_path.exists() {
                if let Ok(file_content) = std::fs::read_to_string(&file_path) {
                    let ecosystem = match name {
                        "package.json" | "package-lock.json" => "npm".to_string(),
                        "Cargo.toml" | "Cargo.lock" => "cargo".to_string(),
                        "requirements.txt" => "pypi".to_string(),
                        "Pipfile" | "pyproject.toml" => "pypi".to_string(),
                        "pom.xml" => "maven".to_string(),
                        "build.gradle" | "build.gradle.kts" => "gradle".to_string(),
                        "go.mod" | "go.sum" => "go".to_string(),
                        _ => "unknown".to_string(),
                    };
                    files.push(DependencyFileRequest {
                        filename: name.to_string(),
                        file_content,
                        ecosystem,
                        workspace_path: Some(path.to_string_lossy().to_string()),
                    });
                }
            }
        }

        Ok(files)
    }

    /// Analyze dependencies via server API (raw)
    pub async fn analyze_dependencies_raw(
        &self,
        files: Vec<DependencyFileRequest>,
    ) -> Result<DependencyAnalysisResponse> {
        let url = format!(
            "{}/api/v1/dependencies/analyze",
            self.base_url.trim_end_matches('/')
        );

        let request = BatchDependencyAnalysisRequest {
            files,
            enable_cache: true,
            compact_mode: false,
        };

        let mut req = self.client.post(&url).json(&request);

        if let Some(api_key) = &self.api_key {
            req = req.header("X-API-Key", api_key);
        }

        let response = req.send().await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to send request to server at {}: {} (is_connect: {}, is_timeout: {})",
                url,
                e,
                e.is_connect(),
                e.is_timeout()
            )
        })?;

        let status = response.status();
        if !status.is_success() {
            return Err(self.handle_error_response(status, response).await);
        }

        response
            .json::<DependencyAnalysisResponse>()
            .await
            .context("Failed to parse server response")
    }

    /// Verify the client's API key with the server
    pub async fn verify_api_key(&self) -> Result<bool> {
        let api_key = match &self.api_key {
            Some(k) => k.clone(),
            None => return Ok(false),
        };

        let result = self.verify_api_key_raw(&api_key).await?;
        Ok(result.valid)
    }

    /// Verify an API key with the server (raw response)
    /// Uses the /api/v1/dependencies/analyze endpoint with a minimal request
    pub async fn verify_api_key_raw(&self, api_key: &str) -> Result<VerifyApiKeyResponse> {
        let url = format!(
            "{}/api/v1/dependencies/analyze",
            self.base_url.trim_end_matches('/')
        );

        // Create a minimal dependency file request to verify the API key
        let verify_request = BatchDependencyAnalysisRequest {
            files: vec![DependencyFileRequest {
                filename: "package.json".to_string(),
                file_content: "{}".to_string(),
                ecosystem: "npm".to_string(),
                workspace_path: None,
            }],
            enable_cache: false,
            compact_mode: true,
        };

        let response = self
            .client
            .post(&url)
            .header("X-API-Key", api_key)
            .json(&verify_request)
            .send()
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to connect to server at {}: {} (is_connect: {}, is_timeout: {})",
                    url,
                    e,
                    e.is_connect(),
                    e.is_timeout()
                )
            })?;

        let status = response.status();
        if !status.is_success() {
            if status == StatusCode::UNAUTHORIZED {
                return Ok(VerifyApiKeyResponse {
                    valid: false,
                    user_id: None,
                    tier: None,
                    daily_limit: None,
                });
            }
            return Err(self.handle_error_response(status, response).await);
        }

        // If we got a successful response, the API key is valid
        Ok(VerifyApiKeyResponse {
            valid: true,
            user_id: None,
            tier: None,
            daily_limit: None,
        })
    }

    /// Get quota status from server
    pub async fn get_quota(&self) -> Result<QuotaStatusResponse> {
        let url = format!("{}/api/v1/quota", self.base_url.trim_end_matches('/'));

        let mut req = self.client.get(&url);

        if let Some(api_key) = &self.api_key {
            req = req.header("X-API-Key", api_key);
        }

        let response = req.send().await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to connect to server at {}: {} (is_connect: {}, is_timeout: {})",
                url,
                e,
                e.is_connect(),
                e.is_timeout()
            )
        })?;

        let status = response.status();
        if !status.is_success() {
            return Err(self.handle_error_response(status, response).await);
        }

        response
            .json::<QuotaStatusResponse>()
            .await
            .context("Failed to parse quota response")
    }

    /// Check if server is reachable
    pub async fn health_check(&self) -> Result<bool> {
        let url = format!("{}/health", self.base_url.trim_end_matches('/'));

        match self.client.get(&url).send().await {
            Ok(response) => Ok(response.status().is_success()),
            Err(_) => Ok(false),
        }
    }

    /// Generate a code fix using the server's LLM endpoint
    pub async fn generate_code_fix(
        &self,
        request: &LlmFixRequest,
    ) -> Result<LlmFixResponse> {
        let url = format!(
            "{}/api/v1/llm/fix",
            self.base_url.trim_end_matches('/')
        );

        let mut req = self.client.post(&url).json(request);

        if let Some(api_key) = &self.api_key {
            req = req.header("X-API-Key", api_key);
        }

        let response = req.send().await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to send LLM fix request to {}: {} (is_connect: {}, is_timeout: {})",
                url,
                e,
                e.is_connect(),
                e.is_timeout()
            )
        })?;

        let status = response.status();
        if !status.is_success() {
            return Err(self.handle_error_response(status, response).await);
        }

        response
            .json::<LlmFixResponse>()
            .await
            .context("Failed to parse LLM fix response")
    }

    /// Handle error response from server
    async fn handle_error_response(
        &self,
        status: StatusCode,
        response: reqwest::Response,
    ) -> anyhow::Error {
        let error_msg = match response.json::<ErrorResponse>().await {
            Ok(err) => {
                if let Some(details) = err.details {
                    format!("{}: {}", err.error, details)
                } else {
                    err.error
                }
            }
            Err(_) => format!("Server returned status {}", status),
        };

        match status {
            StatusCode::UNAUTHORIZED => anyhow::anyhow!("Authentication failed: {}", error_msg),
            StatusCode::FORBIDDEN => anyhow::anyhow!("Access denied: {}", error_msg),
            StatusCode::TOO_MANY_REQUESTS => anyhow::anyhow!("Rate limit exceeded: {}", error_msg),
            StatusCode::BAD_REQUEST => anyhow::anyhow!("Invalid request: {}", error_msg),
            StatusCode::NOT_FOUND => anyhow::anyhow!("Endpoint not found: {}", error_msg),
            StatusCode::INTERNAL_SERVER_ERROR => anyhow::anyhow!("Server error: {}", error_msg),
            _ => anyhow::anyhow!("Request failed ({}): {}", status, error_msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = VulneraClient::new("localhost".to_string(), 8080, None);
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_with_custom_url() {
        let client = VulneraClient::with_url("http://localhost:8080".to_string(), None).unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn test_client_with_api_key() {
        let client = VulneraClient::new("localhost".to_string(), 8080, None)
            .unwrap()
            .with_api_key("test-key".to_string());
        assert_eq!(client.api_key, Some("test-key".to_string()));
    }
}
