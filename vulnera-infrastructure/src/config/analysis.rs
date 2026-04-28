use serde::Deserialize;

/// Analysis orchestrator configuration
#[derive(Debug, Clone, Deserialize)]
pub struct AnalysisConfig {
    /// Maximum concurrent packages analyzed per job
    pub max_concurrent_packages: usize,
    /// Maximum concurrent registry HTTP queries
    pub max_concurrent_registry_queries: usize,
    /// Maximum concurrent external API calls
    pub max_concurrent_api_calls: usize,
    /// Job queue ring-buffer capacity
    pub job_queue_capacity: usize,
    /// Number of background job worker tasks
    pub max_job_workers: usize,
    /// Max files per batch for extension requests
    pub extension_batch_size_limit: usize,
    /// Enable gzip compression for responses
    pub enable_response_compression: bool,
    /// Cache extension results for repeated analysis
    pub cache_extension_results: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_concurrent_packages: 8,
            max_concurrent_registry_queries: 10,
            max_concurrent_api_calls: 12,
            job_queue_capacity: 64,
            max_job_workers: 8,
            extension_batch_size_limit: 25,
            enable_response_compression: true,
            cache_extension_results: true,
        }
    }
}
