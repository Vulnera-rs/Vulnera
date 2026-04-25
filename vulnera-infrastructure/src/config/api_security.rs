use serde::Deserialize;

/// API security analysis configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ApiSecurityConfig {
    /// Enable authentication analyzer
    pub enable_authentication_analyzer: bool,
    /// Enable authorization analyzer
    pub enable_authorization_analyzer: bool,
    /// Enable data exposure analyzer
    pub enable_data_exposure_analyzer: bool,
    /// Enable design analyzer
    pub enable_design_analyzer: bool,
    /// Enable input validation analyzer
    pub enable_input_validation_analyzer: bool,
    /// Enable OAuth analyzer
    pub enable_oauth_analyzer: bool,
    /// Enable resource restriction analyzer
    pub enable_resource_restriction_analyzer: bool,
    /// Enable security headers analyzer
    pub enable_security_headers_analyzer: bool,
    /// Enable security misconfiguration analyzer
    pub enable_security_misconfig_analyzer: bool,
    /// Minimum finding severity to report
    pub min_finding_severity: String,
}

impl Default for ApiSecurityConfig {
    fn default() -> Self {
        Self {
            enable_authentication_analyzer: true,
            enable_authorization_analyzer: true,
            enable_data_exposure_analyzer: true,
            enable_design_analyzer: true,
            enable_input_validation_analyzer: true,
            enable_oauth_analyzer: true,
            enable_resource_restriction_analyzer: true,
            enable_security_headers_analyzer: true,
            enable_security_misconfig_analyzer: true,
            min_finding_severity: "info".into(),
        }
    }
}
