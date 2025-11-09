//! API security domain entities

use serde::{Deserialize, Serialize};

use super::value_objects::ApiVulnerabilityType;

/// API security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiFinding {
    pub id: String,
    pub vulnerability_type: ApiVulnerabilityType,
    pub location: ApiLocation,
    pub severity: FindingSeverity,
    pub description: String,
    pub recommendation: String,
    pub path: Option<String>,
    pub method: Option<String>,
}

/// Location in API specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiLocation {
    pub file_path: String,
    pub line: Option<u32>,
    pub path: Option<String>,
    pub operation: Option<String>,
}

/// Finding severity
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}
