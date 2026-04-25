//! Module plugin value objects

use serde::{Deserialize, Serialize};

/// Module licensing tier
///
/// Determines whether a module is available in the open-source community edition
/// or requires an enterprise license.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ModuleTier {
    /// Free and open-source - available to all users
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
#[non_exhaustive]
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
            Self::DependencyAnalyzer | Self::SAST | Self::SecretDetection | Self::ApiSecurity => {
                ModuleTier::Community
            }

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
    Io(String),

    #[error("Other error: {0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- ModuleTier ---

    #[test]
    fn module_tier_display() {
        assert_eq!(ModuleTier::Community.to_string(), "community");
        assert_eq!(ModuleTier::Enterprise.to_string(), "enterprise");
    }

    #[test]
    fn module_tier_json_roundtrip() {
        for tier in [ModuleTier::Community, ModuleTier::Enterprise] {
            let json = serde_json::to_string(&tier).unwrap();
            let parsed: ModuleTier = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, tier);
        }
    }

    // --- ModuleType ---

    #[test]
    fn community_module_types_have_community_tier() {
        let community_modules = [
            ModuleType::DependencyAnalyzer,
            ModuleType::SAST,
            ModuleType::SecretDetection,
            ModuleType::ApiSecurity,
        ];
        for mt in community_modules {
            assert_eq!(mt.tier(), ModuleTier::Community, "{:?} should be Community", mt);
            assert!(mt.is_community());
            assert!(!mt.is_enterprise());
        }
    }

    #[test]
    fn enterprise_module_types_have_enterprise_tier() {
        let enterprise_modules = [
            ModuleType::MaliciousPackageDetection,
            ModuleType::LicenseCompliance,
            ModuleType::SBOM,
            ModuleType::DAST,
            ModuleType::FuzzTesting,
            ModuleType::IaC,
            ModuleType::CSPM,
        ];
        for mt in enterprise_modules {
            assert_eq!(mt.tier(), ModuleTier::Enterprise, "{:?} should be Enterprise", mt);
            assert!(!mt.is_community());
            assert!(mt.is_enterprise());
        }
    }

    #[test]
    fn module_type_json_roundtrip() {
        let types = [
            ModuleType::DependencyAnalyzer,
            ModuleType::SAST,
            ModuleType::SecretDetection,
            ModuleType::ApiSecurity,
            ModuleType::MaliciousPackageDetection,
            ModuleType::LicenseCompliance,
            ModuleType::SBOM,
            ModuleType::DAST,
            ModuleType::FuzzTesting,
            ModuleType::IaC,
            ModuleType::CSPM,
        ];
        for mt in types {
            let json = serde_json::to_string(&mt).unwrap();
            let parsed: ModuleType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, mt);
        }
    }

    // --- ModuleConfig ---

    #[test]
    fn module_config_default() {
        let cfg = ModuleConfig {
            job_id: uuid::Uuid::parse_str("b16b4e16-a5c6-4168-96cc-d4f414bf974c").unwrap(),
            project_id: "project-1".into(),
            source_uri: "/tmp/repo".into(),
            config: std::collections::HashMap::new(),
        };
        assert_eq!(cfg.project_id, "project-1");
        assert_eq!(cfg.source_uri, "/tmp/repo");
        assert!(cfg.config.is_empty());
    }

    #[test]
    fn module_config_json_roundtrip() {
        use serde_json::json;
        let mut config = std::collections::HashMap::new();
        config.insert("depth".into(), json!("full"));
        config.insert("paths".into(), json!(["src/", "tests/"]));
        let cfg = ModuleConfig {
            job_id: uuid::Uuid::parse_str("b16b4e16-a5c6-4168-96cc-d4f414bf974c").unwrap(),
            project_id: "test-project".into(),
            source_uri: "/tmp/repo".into(),
            config,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: ModuleConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.project_id, "test-project");
        assert_eq!(parsed.source_uri, "/tmp/repo");
        assert_eq!(
            parsed.config.get("depth").and_then(|v| v.as_str()),
            Some("full")
        );
    }

    // --- ModuleExecutionError ---

    #[test]
    fn module_execution_error_display() {
        let err = ModuleExecutionError::ExecutionFailed("sandbox OOM".into());
        assert_eq!(
            err.to_string(),
            "Module execution failed: sandbox OOM"
        );
    }

    #[test]
    fn module_execution_error_invalid_config_display() {
        let err = ModuleExecutionError::InvalidConfig("missing 'source_path'".into());
        assert!(err.to_string().contains("missing 'source_path'"));
    }

    #[test]
    fn module_execution_error_io_display() {
        let err = ModuleExecutionError::Io("permission denied: /etc/shadow".into());
        assert!(err.to_string().contains("permission denied"));
        assert!(err.to_string().contains("IO error"));
    }

    #[test]
    fn module_execution_error_other_display() {
        let err = ModuleExecutionError::Other("unknown tool exited code 137".into());
        assert!(err.to_string().contains("unknown tool exited code 137"));
    }

    // --- ModuleType Discriminant stability ---

    #[test]
    fn module_type_equality_is_by_variant() {
        assert_eq!(ModuleType::SAST, ModuleType::SAST);
        assert_ne!(ModuleType::SAST, ModuleType::SecretDetection);
        assert_ne!(ModuleType::DependencyAnalyzer, ModuleType::DAST);
    }
}
