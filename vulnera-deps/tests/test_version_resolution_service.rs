//! Integration tests for VersionResolutionService

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use vulnera_core::domain::vulnerability::entities::{AffectedPackage, Package, Vulnerability};
use vulnera_core::domain::vulnerability::value_objects::{
    Ecosystem, Severity, Version, VersionRange, VulnerabilityId, VulnerabilitySource,
};
use vulnera_core::infrastructure::registries::{PackageRegistryClient, RegistryError, VersionInfo};
use vulnera_deps::services::version_resolution::VersionResolutionServiceImpl;
use vulnera_deps::types::VersionResolutionService;

// Mock Registry Client
struct MockRegistryClient {
    versions: Mutex<HashMap<(Ecosystem, String), Result<Vec<VersionInfo>, RegistryError>>>,
}

impl MockRegistryClient {
    fn new() -> Self {
        Self {
            versions: Mutex::new(HashMap::new()),
        }
    }

    fn add_versions(&self, ecosystem: Ecosystem, name: &str, versions: Vec<&str>) {
        let version_infos = versions
            .into_iter()
            .map(|v| {
                let version = Version::parse(v).unwrap();
                VersionInfo::new(version, false, Some(Utc::now()))
            })
            .collect();

        self.versions
            .lock()
            .unwrap()
            .insert((ecosystem, name.to_string()), Ok(version_infos));
    }

    fn add_prerelease_versions(&self, ecosystem: Ecosystem, name: &str, versions: Vec<&str>) {
        let version_infos = versions
            .into_iter()
            .map(|v| {
                let version = Version::parse(v).unwrap();
                // VersionInfo::new infers prerelease from version string
                VersionInfo::new(version, false, Some(Utc::now()))
            })
            .collect();

        self.versions
            .lock()
            .unwrap()
            .insert((ecosystem, name.to_string()), Ok(version_infos));
    }

    fn set_error(&self, ecosystem: Ecosystem, name: &str, error: RegistryError) {
        self.versions
            .lock()
            .unwrap()
            .insert((ecosystem, name.to_string()), Err(error));
    }
}

#[async_trait]
impl PackageRegistryClient for MockRegistryClient {
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<VersionInfo>, RegistryError> {
        let key = (ecosystem.clone(), name.to_string());
        let guard = self.versions.lock().unwrap();

        if let Some(result) = guard.get(&key) {
            match result {
                Ok(versions) => Ok(versions.clone()),
                Err(e) => match e {
                    RegistryError::NotFound => Err(RegistryError::NotFound),
                    RegistryError::Http { message, status } => Err(RegistryError::Http {
                        message: message.clone(),
                        status: *status,
                    }),
                    _ => Err(RegistryError::Other("Mock error".to_string())),
                },
            }
        } else {
            Err(RegistryError::NotFound)
        }
    }
}

fn create_vulnerability(
    id: &str,
    pkg_name: &str,
    vulnerable_range: &str,
    fixed_versions: Vec<&str>,
) -> Vulnerability {
    let pkg = Package::new(
        pkg_name.to_string(),
        Version::parse("0.0.0").unwrap(), // Dummy version
        Ecosystem::Npm,
    )
    .unwrap();

    let range = VersionRange::parse(vulnerable_range).unwrap();
    let fixed = fixed_versions
        .into_iter()
        .map(|v| Version::parse(v).unwrap())
        .collect();

    let affected = AffectedPackage::new(pkg, vec![range], fixed);

    Vulnerability::new(
        VulnerabilityId::new(id.to_string()).unwrap(),
        "Test Vuln".to_string(),
        "Description".to_string(),
        Severity::High,
        vec![affected],
        vec![],
        Utc::now(),
        vec![VulnerabilitySource::OSV],
    )
    .unwrap()
}

#[tokio::test]
async fn test_recommend_latest_stable() {
    let registry = Arc::new(MockRegistryClient::new());
    registry.add_versions(
        Ecosystem::Npm,
        "express",
        vec!["4.17.1", "4.17.2", "4.18.0", "4.18.1"],
    );

    let service = VersionResolutionServiceImpl::new(registry);

    let recommendation = service
        .recommend(
            Ecosystem::Npm,
            "express",
            Some(Version::parse("4.17.1").unwrap()),
            &[], // No vulnerabilities
        )
        .await
        .unwrap();

    assert_eq!(
        recommendation.most_up_to_date_safe,
        Some(Version::parse("4.18.1").unwrap())
    );
    assert_eq!(
        recommendation.nearest_safe_above_current,
        Some(Version::parse("4.17.1").unwrap())
    ); // Current is safe
}

#[tokio::test]
async fn test_recommend_avoid_vulnerable() {
    let registry = Arc::new(MockRegistryClient::new());
    registry.add_versions(
        Ecosystem::Npm,
        "express",
        vec!["4.17.1", "4.17.2", "4.18.0", "4.18.1"],
    );

    let vuln = create_vulnerability("CVE-2022-1234", "express", "<4.18.0", vec!["4.18.0"]);

    let service = VersionResolutionServiceImpl::new(registry);

    let recommendation = service
        .recommend(
            Ecosystem::Npm,
            "express",
            Some(Version::parse("4.17.1").unwrap()),
            &[vuln],
        )
        .await
        .unwrap();

    // 4.17.1, 4.17.2 are vulnerable. 4.18.0, 4.18.1 are safe.
    assert_eq!(
        recommendation.most_up_to_date_safe,
        Some(Version::parse("4.18.1").unwrap())
    );
    assert_eq!(
        recommendation.nearest_safe_above_current,
        Some(Version::parse("4.18.0").unwrap())
    );
}

#[tokio::test]
async fn test_recommend_prerelease_exclusion() {
    let registry = Arc::new(MockRegistryClient::new());
    registry.add_prerelease_versions(Ecosystem::Npm, "express", vec!["4.17.1", "5.0.0-alpha.1"]);

    let mut service = VersionResolutionServiceImpl::new(registry);
    service.set_exclude_prereleases(true);

    let recommendation = service
        .recommend(
            Ecosystem::Npm,
            "express",
            Some(Version::parse("4.17.1").unwrap()),
            &[],
        )
        .await
        .unwrap();

    // Should ignore 5.0.0-alpha.1
    assert_eq!(
        recommendation.most_up_to_date_safe,
        Some(Version::parse("4.17.1").unwrap())
    );
}

#[tokio::test]
async fn test_recommend_registry_unavailable_fallback() {
    let registry = Arc::new(MockRegistryClient::new());
    registry.set_error(
        Ecosystem::Npm,
        "express",
        RegistryError::Http {
            message: "Timeout".to_string(),
            status: Some(504),
        },
    );

    let vuln = create_vulnerability(
        "CVE-2022-1234",
        "express",
        "<4.18.0",
        vec!["4.18.0", "4.18.1"], // Fixed versions known from vuln DB
    );

    let service = VersionResolutionServiceImpl::new(registry);

    let recommendation = service
        .recommend(
            Ecosystem::Npm,
            "express",
            Some(Version::parse("4.17.1").unwrap()),
            &[vuln],
        )
        .await
        .unwrap();

    // Should fall back to fixed versions from vulnerability
    // nearest_safe_above_current should be 4.18.0
    assert_eq!(
        recommendation.nearest_safe_above_current,
        Some(Version::parse("4.18.0").unwrap())
    );
    // most_up_to_date_safe is None because we can't know the latest version from registry
    assert_eq!(recommendation.most_up_to_date_safe, None);
    assert!(
        recommendation
            .notes
            .iter()
            .any(|n| n.contains("registry unavailable"))
    );
}

#[tokio::test]
async fn test_recommend_all_vulnerable() {
    let registry = Arc::new(MockRegistryClient::new());
    registry.add_versions(Ecosystem::Npm, "express", vec!["4.17.1", "4.17.2"]);

    let vuln = create_vulnerability(
        "CVE-2022-1234",
        "express",
        "*",    // All versions vulnerable
        vec![], // No fix
    );

    let service = VersionResolutionServiceImpl::new(registry);

    let recommendation = service
        .recommend(
            Ecosystem::Npm,
            "express",
            Some(Version::parse("4.17.1").unwrap()),
            &[vuln],
        )
        .await
        .unwrap();

    assert_eq!(recommendation.most_up_to_date_safe, None);
    assert_eq!(recommendation.nearest_safe_above_current, None);
    assert!(
        recommendation
            .notes
            .iter()
            .any(|n| n.contains("no known safe version"))
    );
}
