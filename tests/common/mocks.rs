//! Shared mock implementations for testing
//!
//! This module provides consistent mock implementations that can be used
//! across different test modules to avoid duplication.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use vulnera_rust::application::errors::VulnerabilityError;
use vulnera_rust::domain::entities::{Package, Vulnerability};
use vulnera_rust::infrastructure::api_clients::traits::VulnerabilityApiClient;
use vulnera_rust::infrastructure::parsers::traits::PackageFileParser;
use vulnera_rust::infrastructure::repository_source::{FetchedFileContent, RepositoryFile, RepositorySourceClient, RepositorySourceError};
use vulnera_rust::infrastructure::VulnerabilityRepository;

/// Mock vulnerability repository for testing
#[derive(Debug, Clone)]
pub struct MockVulnerabilityRepository {
    vulnerabilities: Vec<Vulnerability>,
    should_fail: bool,
    failure_type: Option<VulnerabilityError>,
}

impl MockVulnerabilityRepository {
    /// Create a new mock repository with given vulnerabilities
    pub fn new(vulnerabilities: Vec<Vulnerability>) -> Self {
        Self {
            vulnerabilities,
            should_fail: false,
            failure_type: None,
        }
    }

    /// Create a mock repository that always fails
    pub fn failing() -> Self {
        Self {
            vulnerabilities: vec![],
            should_fail: true,
            failure_type: Some(VulnerabilityError::RateLimit {
                api: "mock".to_string(),
            }),
        }
    }

    /// Create a mock repository that fails with a specific error
    pub fn with_error(error: VulnerabilityError) -> Self {
        Self {
            vulnerabilities: vec![],
            should_fail: true,
            failure_type: Some(error),
        }
    }

    /// Add a vulnerability to the repository
    pub fn add_vulnerability(&mut self, vulnerability: Vulnerability) {
        self.vulnerabilities.push(vulnerability);
    }

    /// Get the number of vulnerabilities in the repository
    pub fn vulnerability_count(&self) -> usize {
        self.vulnerabilities.len()
    }
}

#[async_trait]
impl VulnerabilityRepository for MockVulnerabilityRepository {
    async fn find_vulnerabilities(
        &self,
        package: &Package,
    ) -> Result<Vec<Vulnerability>, VulnerabilityError> {
        if self.should_fail {
            return Err(self.failure_type.clone().unwrap_or_else(|| VulnerabilityError::RateLimit {
                api: "mock".to_string(),
            }));
        }

        Ok(self
            .vulnerabilities
            .iter()
            .filter(|vuln| vuln.affects_package(package))
            .cloned()
            .collect())
    }

    async fn get_vulnerability_by_id(
        &self,
        id: &vulnera_rust::domain::value_objects::VulnerabilityId,
    ) -> Result<Option<Vulnerability>, VulnerabilityError> {
        if self.should_fail {
            return Err(self.failure_type.clone().unwrap_or_else(|| VulnerabilityError::RateLimit {
                api: "mock".to_string(),
            }));
        }

        Ok(self
            .vulnerabilities
            .iter()
            .find(|vuln| vuln.id.as_str() == id.as_str())
            .cloned())
    }
}

/// Mock repository source client for testing
#[derive(Debug, Clone)]
pub struct MockRepositorySourceClient {
    files: Vec<RepositoryFile>,
    contents: Vec<FetchedFileContent>,
    should_fail: bool,
}

impl MockRepositorySourceClient {
    /// Create a new mock with given files and contents
    pub fn new(files: Vec<RepositoryFile>, contents: Vec<FetchedFileContent>) -> Self {
        Self {
            files,
            contents,
            should_fail: false,
        }
    }

    /// Create a mock that always fails
    pub fn failing() -> Self {
        Self {
            files: vec![],
            contents: vec![],
            should_fail: true,
        }
    }

    /// Create a mock for a single file
    pub fn single_file(path: &str, content: &str) -> Self {
        let file = RepositoryFile {
            path: path.to_string(),
            size: content.len() as u64,
            is_text: true,
        };

        let content = FetchedFileContent {
            path: path.to_string(),
            content: content.to_string(),
        };

        Self::new(vec![file], vec![content])
    }

    /// Create a mock for multiple files
    pub fn multiple_files(files_contents: HashMap<&str, &str>) -> Self {
        let files: Vec<RepositoryFile> = files_contents
            .iter()
            .map(|(path, content)| RepositoryFile {
                path: path.to_string(),
                size: content.len() as u64,
                is_text: true,
            })
            .collect();

        let contents: Vec<FetchedFileContent> = files_contents
            .iter()
            .map(|(path, content)| FetchedFileContent {
                path: path.to_string(),
                content: content.to_string(),
            })
            .collect();

        Self::new(files, contents)
    }
}

#[async_trait]
impl RepositorySourceClient for MockRepositorySourceClient {
    async fn list_repository_files(
        &self,
        _owner: &str,
        _repo: &str,
        _ref: Option<&str>,
        _max_files: u32,
        _max_bytes: u64,
    ) -> Result<Vec<RepositoryFile>, RepositorySourceError> {
        if self.should_fail {
            return Err(RepositorySourceError::RateLimit {
                source: "mock".to_string(),
            });
        }

        Ok(self.files.clone())
    }

    async fn fetch_file_contents(
        &self,
        _owner: &str,
        _repo: &str,
        files: &[RepositoryFile],
        _ref: Option<&str>,
        _single_file_max_bytes: u64,
        _concurrent_limit: usize,
    ) -> Result<Vec<FetchedFileContent>, RepositorySourceError> {
        if self.should_fail {
            return Err(RepositorySourceError::RateLimit {
                source: "mock".to_string(),
            });
        }

        // Return contents for matching files
        let requested_paths: std::collections::HashSet<String> = files
            .iter()
            .map(|f| f.path.clone())
            .collect();

        Ok(self
            .contents
            .iter()
            .filter(|content| requested_paths.contains(&content.path))
            .cloned()
            .collect())
    }
}

/// Mock API client for testing vulnerability APIs
#[derive(Debug, Clone)]
pub struct MockApiClient {
    responses: HashMap<String, Vec<Vulnerability>>,
    should_fail: bool,
    failure_reason: String,
}

impl MockApiClient {
    /// Create a new mock with predefined responses
    pub fn new(responses: HashMap<String, Vec<Vulnerability>>) -> Self {
        Self {
            responses,
            should_fail: false,
            failure_reason: String::new(),
        }
    }

    /// Create a mock that always fails
    pub fn failing(reason: &str) -> Self {
        Self {
            responses: HashMap::new(),
            should_fail: true,
            failure_reason: reason.to_string(),
        }
    }

    /// Create a mock that returns no vulnerabilities
    pub fn empty() -> Self {
        Self::new(HashMap::new())
    }

    /// Add a response for a specific package
    pub fn add_response(&mut self, package_key: String, vulnerabilities: Vec<Vulnerability>) {
        self.responses.insert(package_key, vulnerabilities);
    }

    /// Create a package key for the responses map
    pub fn package_key(package: &Package) -> String {
        format!("{}:{}:{}", package.ecosystem, package.name, package.version)
    }
}

#[async_trait]
impl VulnerabilityApiClient for MockApiClient {
    async fn find_vulnerabilities(&self, packages: &[Package]) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
        if self.should_fail {
            return Err(format!("Mock API client failure: {}", self.failure_reason).into());
        }

        let mut all_vulnerabilities = Vec::new();

        for package in packages {
            let key = Self::package_key(package);
            if let Some(vulnerabilities) = self.responses.get(&key) {
                all_vulnerabilities.extend(vulnerabilities.clone());
            }
        }

        Ok(all_vulnerabilities)
    }
}

/// Mock package file parser for testing
#[derive(Debug, Clone)]
pub struct MockPackageFileParser {
    ecosystem: vulnera_rust::domain::value_objects::Ecosystem,
    result: Result<Vec<Package>, vulnera_rust::infrastructure::parsers::traits::ParsingError>,
}

impl MockPackageFileParser {
    /// Create a mock that returns success with given packages
    pub fn success(ecosystem: vulnera_rust::domain::value_objects::Ecosystem, packages: Vec<Package>) -> Self {
        Self {
            ecosystem,
            result: Ok(packages),
        }
    }

    /// Create a mock that returns an error
    pub fn error(
        ecosystem: vulnera_rust::domain::value_objects::Ecosystem,
        error: vulnera_rust::infrastructure::parsers::traits::ParsingError,
    ) -> Self {
        Self {
            ecosystem,
            result: Err(error),
        }
    }

    /// Create a mock that returns no packages
    pub fn empty(ecosystem: vulnera_rust::domain::value_objects::Ecosystem) -> Self {
        Self::success(ecosystem, vec![])
    }
}

impl PackageFileParser for MockPackageFileParser {
    fn ecosystem(&self) -> vulnera_rust::domain::value_objects::Ecosystem {
        self.ecosystem
    }

    fn parse_file(&self, _content: &str) -> Result<Vec<Package>, vulnera_rust::infrastructure::parsers::traits::ParsingError> {
        self.result.clone()
    }

    fn supported_extensions(&self) -> Vec<&'static str> {
        match self.ecosystem {
            vulnera_rust::domain::value_objects::Ecosystem::Npm => vec!["json"],
            vulnera_rust::domain::value_objects::Ecosystem::Cargo => vec!["toml"],
            vulnera_rust::domain::value_objects::Ecosystem::PyPI => vec!["txt", "toml"],
            vulnera_rust::domain::value_objects::Ecosystem::Maven => vec!["xml"],
            vulnera_rust::domain::value_objects::Ecosystem::Go => vec!["mod"],
            vulnera_rust::domain::value_objects::Ecosystem::Packagist => vec!["json"],
            vulnera_rust::domain::value_objects::Ecosystem::RubyGems => vec!["gemspec"],
            vulnera_rust::domain::value_objects::Ecosystem::NuGet => vec!["csproj", "config"],
        }
    }
}

/// Builder for creating complex mock scenarios
pub struct MockScenarioBuilder {
    vulnerability_repository: Option<MockVulnerabilityRepository>,
    repository_source: Option<MockRepositorySourceClient>,
    api_client: Option<MockApiClient>,
}

impl MockScenarioBuilder {
    /// Create a new scenario builder
    pub fn new() -> Self {
        Self {
            vulnerability_repository: None,
            repository_source: None,
            api_client: None,
        }
    }

    /// Add a vulnerability repository
    pub fn with_vulnerability_repository(mut self, repo: MockVulnerabilityRepository) -> Self {
        self.vulnerability_repository = Some(repo);
        self
    }

    /// Add a repository source
    pub fn with_repository_source(mut self, source: MockRepositorySourceClient) -> Self {
        self.repository_source = Some(source);
        self
    }

    /// Add an API client
    pub fn with_api_client(mut self, client: MockApiClient) -> Self {
        self.api_client = Some(client);
        self
    }

    /// Build the scenario
    pub fn build(self) -> MockScenario {
        MockScenario {
            vulnerability_repository: self.vulnerability_repository.unwrap_or_else(|| MockVulnerabilityRepository::new(vec![])),
            repository_source: self.repository_source.unwrap_or_else(|| MockRepositorySourceClient::new(vec![], vec![])),
            api_client: self.api_client.unwrap_or_else(|| MockApiClient::empty()),
        }
    }
}

/// A complete mock scenario for testing
pub struct MockScenario {
    pub vulnerability_repository: MockVulnerabilityRepository,
    pub repository_source: MockRepositorySourceClient,
    pub api_client: MockApiClient,
}

impl MockScenario {
    /// Create a scenario builder
    pub fn builder() -> MockScenarioBuilder {
        MockScenarioBuilder::new()
    }

    /// Create a scenario with a simple successful analysis
    pub fn simple_success() -> Self {
        use crate::common::factories::*;

        let pkg = PackageFactory::npm("express", "4.17.1");
        let vuln = VulnerabilityFactory::high_severity("TEST-001", pkg.clone());

        Self::builder()
            .with_vulnerability_repository(MockVulnerabilityRepository::new(vec![vuln]))
            .with_repository_source(MockRepositorySourceClient::single_file(
                "package.json",
                &FileContentFactory::package_json([("express", "4.17.1")].into()),
            ))
            .with_api_client(MockApiClient::empty())
            .build()
    }

    /// Create a scenario that simulates API failures
    pub fn api_failure() -> Self {
        Self::builder()
            .with_vulnerability_repository(MockVulnerabilityRepository::failing())
            .with_api_client(MockApiClient::failing("Rate limit exceeded"))
            .build()
    }

    /// Create a scenario with no vulnerabilities
    pub fn clean() -> Self {
        Self::builder()
            .with_vulnerability_repository(MockVulnerabilityRepository::new(vec![]))
            .with_api_client(MockApiClient::empty())
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::factories::*;

    #[test]
    fn test_mock_vulnerability_repository() {
        let pkg = PackageFactory::npm("express", "4.17.1");
        let vuln = VulnerabilityFactory::high_severity("TEST-001", pkg.clone());

        let repo = MockVulnerabilityRepository::new(vec![vuln.clone()]);
        assert_eq!(repo.vulnerability_count(), 1);

        let mut failing_repo = MockVulnerabilityRepository::failing();
        failing_repo.add_vulnerability(vuln);
        assert_eq!(failing_repo.vulnerability_count(), 1);
    }

    #[test]
    fn test_mock_repository_source_client() {
        let client = MockRepositorySourceClient::single_file("package.json", "{}");
        assert!(!client.should_fail);

        let failing_client = MockRepositorySourceClient::failing();
        assert!(failing_client.should_fail);
    }

    #[test]
    fn test_mock_scenario_builder() {
        let scenario = MockScenario::simple_success();
        assert_eq!(scenario.vulnerability_repository.vulnerability_count(), 1);
        assert!(!scenario.repository_source.should_fail);

        let failure_scenario = MockScenario::api_failure();
        assert!(failure_scenario.vulnerability_repository.should_fail);
    }

    #[test]
    fn test_mock_api_client_package_key() {
        let pkg = PackageFactory::npm("express", "4.17.1");
        let key = MockApiClient::package_key(&pkg);
        assert_eq!(key, "npm:express:4.17.1");
    }
}