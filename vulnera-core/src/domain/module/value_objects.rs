//! Module plugin value objects

use serde::{Deserialize, Serialize};

/// Module licensing tier
///
/// Determines whether a module is available in the open-source community edition
/// or requires an enterprise license.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModuleTier {
    /// Free and open-source — available to all users
    Community,
    /// Requires an active enterprise license
    Enterprise,
}

impl std::fmt::Display for ModuleTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Community => write!(f, "community"),
            Self::Enterprise => write!(f, "enterprise"),
        }
    }
}

/// Module type identifier
///
/// Each analysis module type has a unique identifier that is used for registration,
/// selection, and routing within the orchestrator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModuleType {
    /// Dependency analyzer module (Community)
    DependencyAnalyzer,
    /// SAST module (Community)
    SAST,
    /// Secret detection module (Community)
    SecretDetection,
    /// API security module (Community)
    ApiSecurity,
    /// Malicious package detection module (Enterprise)
    MaliciousPackageDetection,
    /// License compliance module (Enterprise)
    LicenseCompliance,
    /// SBOM generation module (Enterprise)
    SBOM,
    /// DAST module (Enterprise)
    DAST,
    /// Fuzz testing module (Enterprise)
    FuzzTesting,
    /// IaC/Container security module (Enterprise)
    IaC,
    /// CSPM module (Enterprise)
    CSPM,
}

impl ModuleType {
    /// Returns the licensing tier for this module type.
    ///
    /// Community modules are open-source and always available.
    /// Enterprise modules require a valid license key.
    pub fn tier(&self) -> ModuleTier {
        match self {
            Self::DependencyAnalyzer
            | Self::SAST
            | Self::SecretDetection
            | Self::ApiSecurity => ModuleTier::Community,

            Self::MaliciousPackageDetection
            | Self::LicenseCompliance
            | Self::SBOM
            | Self::DAST
            | Self::FuzzTesting
            | Self::IaC
            | Self::CSPM => ModuleTier::Enterprise,
        }
    }

    /// Returns true if this module is part of the community (open-source) tier.
    pub fn is_community(&self) -> bool {
        self.tier() == ModuleTier::Community
    }

    /// Returns true if this module requires an enterprise license.
    pub fn is_enterprise(&self) -> bool {
        self.tier() == ModuleTier::Enterprise
    }
}

/// Configuration for module execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    /// Unique job identifier
    pub job_id: uuid::Uuid,
    /// Project identifier
    pub project_id: String,
    /// Source URI (file path, git URL, etc.)
    pub source_uri: String,
    /// Module-specific configuration parameters
    pub config: std::collections::HashMap<String, serde_json::Value>,
}

/// Module execution error
#[derive(Debug, thiserror::Error)]
pub enum ModuleExecutionError {
    #[error("Module execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Other error: {0}")]
    Other(String),
}
