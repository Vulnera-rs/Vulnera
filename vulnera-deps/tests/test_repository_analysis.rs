use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use async_trait::async_trait;
use vulnera_core::Config;
use vulnera_core::application::errors::{ApplicationError, VulnerabilityError};
use vulnera_core::domain::vulnerability::entities::{Package, Vulnerability};
use vulnera_core::domain::vulnerability::repositories::IVulnerabilityRepository;
use vulnera_core::domain::vulnerability::value_objects::VulnerabilityId;
use vulnera_core::infrastructure::parsers::ParserFactory;
use vulnera_core::infrastructure::repository_source::{
    FetchedFileContent, RepositoryFile, RepositorySourceClient, RepositorySourceResult, RepositorySourceError
};
use vulnera_deps::services::repository_analysis::{
    RepositoryAnalysisInput, RepositoryAnalysisService, RepositoryAnalysisServiceImpl
};

// --- Mocks ---

#[derive(Clone)]
struct MockRepositorySourceClient {
    files: Arc<Mutex<HashMap<String, Vec<RepositoryFile>>>>,
    contents: Arc<Mutex<HashMap<String, String>>>,
    rate_limit_trigger: Arc<Mutex<bool>>,
}

impl MockRepositorySourceClient {
    fn new() -> Self {
        Self {
            files: Arc::new(Mutex::new(HashMap::new())),
            contents: Arc::new(Mutex::new(HashMap::new())),
            rate_limit_trigger: Arc::new(Mutex::new(false)),
        }
    }

    fn add_repo(&self, owner: &str, repo: &str, files: Vec<RepositoryFile>) {
        let key = format!("{}/{}", owner, repo);
        self.files.lock().unwrap().insert(key, files);
    }

    fn add_content(&self, path: &str, content: &str) {
        self.contents.lock().unwrap().insert(path.to_string(), content.to_string());
    }

    fn set_rate_limit(&self, active: bool) {
        *self.rate_limit_trigger.lock().unwrap() = active;
    }
}

#[async_trait]
impl RepositorySourceClient for MockRepositorySourceClient {
    async fn list_repository_files(
        &self,
        owner: &str,
        repo: &str,
        _ref: Option<&str>,
        max_files: u32,
        _max_bytes: u64,
    ) -> RepositorySourceResult<Vec<RepositoryFile>> {
        if *self.rate_limit_trigger.lock().unwrap() {
            return Err(RepositorySourceError::RateLimited {
                retry_after: Some(60),
                message: "Rate limit exceeded".to_string(),
            });
        }

        let key = format!("{}/{}", owner, repo);
        let files = self.files.lock().unwrap().get(&key).cloned().unwrap_or_default();
        
        if files.len() > max_files as usize {
             // Simulate truncation logic if needed, but usually the client handles it or returns partial
             // For this mock, let's just return what we have, or slice it
             return Ok(files.into_iter().take(max_files as usize).collect());
        }

        Ok(files)
    }

    async fn fetch_file_contents(
        &self,
        _owner: &str,
        _repo: &str,
        files: &[RepositoryFile],
        _ref: Option<&str>,
        single_file_max_bytes: u64,
        _concurrent_limit: usize,
    ) -> RepositorySourceResult<Vec<FetchedFileContent>> {
        if *self.rate_limit_trigger.lock().unwrap() {
            return Err(RepositorySourceError::RateLimited {
                retry_after: Some(60),
                message: "Rate limit exceeded".to_string(),
            });
        }

        let mut results = Vec::new();
        let contents = self.contents.lock().unwrap();

        for file in files {
            if file.size > single_file_max_bytes {
                // Skip or error? The real client might skip or error. 
                // The service logic filters before calling this, but let's be safe.
                continue;
            }

            if let Some(content) = contents.get(&file.path) {
                results.push(FetchedFileContent {
                    path: file.path.clone(),
                    content: content.clone(),
                });
            }
        }

        Ok(results)
    }
}

struct MockVulnerabilityRepository;

#[async_trait]
impl IVulnerabilityRepository for MockVulnerabilityRepository {
    async fn find_vulnerabilities(
        &self,
        _package: &Package,
    ) -> Result<Vec<Vulnerability>, VulnerabilityError> {
        Ok(Vec::new()) // Return empty for now, can be extended if needed
    }

    async fn get_vulnerability_by_id(
        &self,
        _id: &VulnerabilityId,
    ) -> Result<Option<Vulnerability>, VulnerabilityError> {
        Ok(None)
    }
}

// --- Tests ---

#[tokio::test]
async fn test_analyze_repository_success() {
    let mock_client = MockRepositorySourceClient::new();
    let mock_vuln_repo = Arc::new(MockVulnerabilityRepository);
    let config = Arc::new(Config::default());
    let parser_factory = Arc::new(ParserFactory::default());

    // Setup repo data
    let owner = "test-owner";
    let repo = "test-repo";
    
    mock_client.add_repo(owner, repo, vec![
        RepositoryFile { path: "Cargo.toml".to_string(), size: 100, is_text: true },
        RepositoryFile { path: "src/main.rs".to_string(), size: 500, is_text: true }, // Should be ignored by parsers
    ]);

    mock_client.add_content("Cargo.toml", r#"
        [package]
        name = "test-pkg"
        version = "0.1.0"
        
        [dependencies]
        serde = "1.0"
    "#);

    let service = RepositoryAnalysisServiceImpl::new(
        Arc::new(mock_client),
        mock_vuln_repo,
        parser_factory,
        config,
    );

    let input = RepositoryAnalysisInput {
        owner: owner.to_string(),
        repo: repo.to_string(),
        requested_ref: None,
        include_paths: None,
        exclude_paths: None,
        max_files: 100,
        include_lockfiles: true,
        return_packages: true,
    };

    let result = service.analyze_repository(input).await.expect("Analysis failed");

    assert_eq!(result.owner, owner);
    assert_eq!(result.repo, repo);
    assert_eq!(result.analyzed_files, 1); // Only Cargo.toml
    assert_eq!(result.files.len(), 1);
    assert_eq!(result.files[0].path, "Cargo.toml");
    assert!(!result.files[0].packages.is_empty());
    assert_eq!(result.files[0].packages[0].name, "serde");
}

#[tokio::test]
async fn test_analyze_repository_rate_limit() {
    let mock_client = MockRepositorySourceClient::new();
    mock_client.set_rate_limit(true);
    
    let mock_vuln_repo = Arc::new(MockVulnerabilityRepository);
    let config = Arc::new(Config::default());
    let parser_factory = Arc::new(ParserFactory::default());

    let service = RepositoryAnalysisServiceImpl::new(
        Arc::new(mock_client),
        mock_vuln_repo,
        parser_factory,
        config,
    );

    let input = RepositoryAnalysisInput {
        owner: "owner".to_string(),
        repo: "repo".to_string(),
        requested_ref: None,
        include_paths: None,
        exclude_paths: None,
        max_files: 100,
        include_lockfiles: true,
        return_packages: true,
    };

    let result = service.analyze_repository(input).await;
    
    match result {
        Err(ApplicationError::RateLimited { .. }) => (), // Expected
        _ => panic!("Expected RateLimited error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_analyze_repository_file_size_limit() {
    let mock_client = MockRepositorySourceClient::new();
    let mock_vuln_repo = Arc::new(MockVulnerabilityRepository);
    let mut config = Config::default();
    // Set a small file size limit
    config.apis.github.max_single_file_bytes = 50; 
    
    let parser_factory = Arc::new(ParserFactory::default());

    let owner = "test-owner";
    let repo = "test-repo";
    
    mock_client.add_repo(owner, repo, vec![
        RepositoryFile { path: "Cargo.toml".to_string(), size: 100, is_text: true }, // Too big
    ]);

    let service = RepositoryAnalysisServiceImpl::new(
        Arc::new(mock_client),
        mock_vuln_repo,
        parser_factory,
        Arc::new(config),
    );

    let input = RepositoryAnalysisInput {
        owner: owner.to_string(),
        repo: repo.to_string(),
        requested_ref: None,
        include_paths: None,
        exclude_paths: None,
        max_files: 100,
        include_lockfiles: true,
        return_packages: true,
    };

    let result = service.analyze_repository(input).await.expect("Analysis failed");

    // Should be skipped because of size
    assert_eq!(result.analyzed_files, 0);
    assert_eq!(result.files.len(), 0);
}

#[tokio::test]
async fn test_analyze_repository_max_files_truncation() {
    let mock_client = MockRepositorySourceClient::new();
    let mock_vuln_repo = Arc::new(MockVulnerabilityRepository);
    let config = Arc::new(Config::default());
    let parser_factory = Arc::new(ParserFactory::default());

    let owner = "test-owner";
    let repo = "test-repo";
    
    // Add 5 files
    let files: Vec<RepositoryFile> = (0..5)
        .map(|i| RepositoryFile { 
            path: format!("package{}.json", i), 
            size: 10, 
            is_text: true 
        })
        .collect();
    
    mock_client.add_repo(owner, repo, files);

    let service = RepositoryAnalysisServiceImpl::new(
        Arc::new(mock_client),
        mock_vuln_repo,
        parser_factory,
        config,
    );

    let input = RepositoryAnalysisInput {
        owner: owner.to_string(),
        repo: repo.to_string(),
        requested_ref: None,
        include_paths: None,
        exclude_paths: None,
        max_files: 3, // Limit to 3
        include_lockfiles: true,
        return_packages: true,
    };

    let result = service.analyze_repository(input).await.expect("Analysis failed");

    // The service asks the client for `max_files`. 
    // Our mock respects that and returns 3 files.
    // The service then processes those 3.
    // The `truncated` flag in result depends on logic: 
    // `truncated: (filtered.len() as u32) >= max_files`
    
    assert_eq!(result.total_files_scanned, 3);
    assert!(result.truncated);
}
