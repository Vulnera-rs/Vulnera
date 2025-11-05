//! JSON report format implementation

use crate::application::errors::ApplicationError;
use crate::domain::vulnerability::entities::AnalysisReport;

/// Generate JSON-based analysis report for API consumption
pub fn generate_json_report(analysis: &AnalysisReport) -> Result<String, ApplicationError> {
    serde_json::to_string_pretty(analysis).map_err(ApplicationError::Json)
}
