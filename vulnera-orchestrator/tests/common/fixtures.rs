//! Test data fixtures for vulnera-orchestrator

use vulnera_orchestrator::domain::value_objects::{AnalysisDepth, SourceType};

/// Create a test analysis job request
pub fn test_analysis_request() -> (SourceType, String, AnalysisDepth) {
    (
        SourceType::Git,
        "https://github.com/example/repo".to_string(),
        AnalysisDepth::Standard,
    )
}

