//! HTML report format implementation
//!
//! Note: Currently returns JSON format for HTML reports.
//! Future enhancement: Generate actual HTML markup.

use crate::application::errors::ApplicationError;
use crate::application::reporting::formats::json;
use crate::domain::vulnerability::entities::AnalysisReport;

/// Generate HTML report
/// Currently returns JSON format, but can be enhanced to generate actual HTML markup
pub fn generate_html_report(analysis: &AnalysisReport) -> Result<String, ApplicationError> {
    // For now, we return JSON format
    // Future: Generate actual HTML markup with proper styling
    // TODO: Implement actual HTML markup generation
    json::generate_json_report(analysis)
}
