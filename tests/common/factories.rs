//! Test data factories for creating consistent test data across all test modules
//!
//! These factories provide a standardized way to create test data objects
//! with sensible defaults while allowing customization as needed.

use chrono::Utc;
use std::collections::HashMap;
use vulnera_rust::domain::vulnerability::{
    entities::{AffectedPackage, AnalysisReport, Package, Vulnerability},
    value_objects::{Ecosystem, Severity, Version, VersionRange, VulnerabilityId, VulnerabilitySource},
};

/// Factory for creating Package instances
pub struct PackageFactory;

impl PackageFactory {
    /// Create a standard npm package
    pub fn npm(name: &str, version: &str) -> Package {
        Package::new(
            name.to_string(),
            Version::parse(version).expect("Invalid version"),
            Ecosystem::Npm,
        ).expect("Failed to create package")
    }

    /// Create a standard cargo package
    pub fn cargo(name: &str, version: &str) -> Package {
        Package::new(
            name.to_string(),
            Version::parse(version).expect("Invalid version"),
            Ecosystem::Cargo,
        ).expect("Failed to create package")
    }

    /// Create a standard Python package
    pub fn python(name: &str, version: &str) -> Package {
        Package::new(
            name.to_string(),
            Version::parse(version).expect("Invalid version"),
            Ecosystem::PyPI,
        ).expect("Failed to create package")
    }

    /// Create a standard Maven package
    pub fn maven(name: &str, version: &str) -> Package {
        Package::new(
            name.to_string(),
            Version::parse(version).expect("Invalid version"),
            Ecosystem::Maven,
        ).expect("Failed to create package")
    }

    /// Create a package for any ecosystem
    pub fn for_ecosystem(name: &str, version: &str, ecosystem: Ecosystem) -> Package {
        Package::new(
            name.to_string(),
            Version::parse(version).expect("Invalid version"),
            ecosystem,
        ).expect("Failed to create package")
    }

    /// Create a package with common vulnerabilities for testing
    pub fn vulnerable_npm(name: &str, version: &str) -> Package {
        let common_vulns = vec![
            "express", "lodash", "axios", "request", "moment", "underscore",
        ];
        let test_name = if common_vulns.contains(&name) {
            name.to_string()
        } else {
            "express".to_string() // Default to a package with known vulnerabilities
        };

        Self::npm(&test_name, version)
    }
}

/// Factory for creating Vulnerability instances
pub struct VulnerabilityFactory;

impl VulnerabilityFactory {
    /// Create a basic vulnerability
    pub fn basic(
        id: &str,
        summary: &str,
        severity: Severity,
        affected_package: Package,
    ) -> Vulnerability {
        let affected = crate::common::factories::create_affected_package(affected_package, "1.0.0");

        Vulnerability::new(
            VulnerabilityId::new(id.to_string()).expect("Invalid vulnerability ID"),
            summary.to_string(),
            format!("Detailed description for {}", id),
            severity,
            vec![affected],
            vec![format!("https://example.com/{}", id)],
            Utc::now(),
            vec![VulnerabilitySource::OSV],
        ).expect("Failed to create vulnerability")
    }

    /// Create a high severity vulnerability
    pub fn high_severity(id: &str, package: Package) -> Vulnerability {
        Self::basic(id, &format!("High severity vulnerability {}", id), Severity::High, package)
    }

    /// Create a critical vulnerability
    pub fn critical(id: &str, package: Package) -> Vulnerability {
        Self::basic(id, &format!("Critical vulnerability {}", id), Severity::Critical, package)
    }

    /// Create a CVE-style vulnerability
    pub fn cve(cve_id: &str, package: Package, severity: Severity) -> Vulnerability {
        Self::basic(
            cve_id,
            &format!("Security vulnerability {}", cve_id),
            severity,
            package,
        )
    }

    /// Create a GHSA-style vulnerability
    pub fn ghsa(ghsa_id: &str, package: Package, severity: Severity) -> Vulnerability {
        let mut vuln = Self::basic(
            ghsa_id,
            &format!("GitHub Security Advisory {}", ghsa_id),
            severity,
            package,
        );
        // GHSA vulnerabilities typically come from GitHub
        vuln.sources = vec![VulnerabilitySource::GHSA];
        vuln
    }

    /// Create a vulnerability with multiple affected packages
    pub fn multi_package(id: &str, packages: Vec<Package>, severity: Severity) -> Vulnerability {
        let affected_packages = packages
            .into_iter()
            .map(|pkg| create_affected_package(pkg, "1.0.0"))
            .collect();

        Vulnerability::new(
            VulnerabilityId::new(id.to_string()).expect("Invalid vulnerability ID"),
            format!("Multi-package vulnerability {}", id),
            format!("Affects multiple packages: {}", id),
            severity,
            affected_packages,
            vec![format!("https://example.com/{}", id)],
            Utc::now(),
            vec![VulnerabilitySource::OSV],
        ).expect("Failed to create vulnerability")
    }
}

/// Factory for creating AnalysisReport instances
pub struct AnalysisReportFactory;

impl AnalysisReportFactory {
    /// Create a basic analysis report
    pub fn basic(packages: Vec<Package>, vulnerabilities: Vec<Vulnerability>) -> AnalysisReport {
        AnalysisReport::new(
            packages,
            vulnerabilities,
            std::time::Duration::from_millis(500),
            vec!["OSV".to_string()],
        )
    }

    /// Create a report with no vulnerabilities (clean report)
    pub fn clean(packages: Vec<Package>) -> AnalysisReport {
        Self::basic(packages, vec![])
    }

    /// Create a report with critical vulnerabilities
    pub fn critical(packages: Vec<Package>, count: usize) -> AnalysisReport {
        let vulnerabilities = (0..count)
            .map(|i| {
                let pkg = packages.get(i % packages.len()).unwrap_or(&packages[0]).clone();
                VulnerabilityFactory::critical(&format!("CRIT-{:04}", i), pkg)
            })
            .collect();

        Self::basic(packages, vulnerabilities)
    }

    /// Create a report with mixed severity vulnerabilities
    pub fn mixed_severity(packages: Vec<Package>) -> AnalysisReport {
        let severities = vec![Severity::Critical, Severity::High, Severity::Medium, Severity::Low];
        let vulnerabilities = packages
            .iter()
            .enumerate()
            .map(|(i, pkg)| {
                let severity = severities[i % severities.len()].clone();
                VulnerabilityFactory::basic(&format!("VULN-{:04}", i), "Test vulnerability", severity, pkg.clone())
            })
            .collect();

        Self::basic(packages, vulnerabilities)
    }
}

/// Helper function to create affected packages
fn create_affected_package(package: Package, fixed_version: &str) -> AffectedPackage {
    let fixed_version = Version::parse(fixed_version).expect("Invalid fixed version");
    AffectedPackage::new(
        package,
        vec![VersionRange::less_than(fixed_version.clone())],
        vec![fixed_version],
    )
}

/// Factory for creating test file contents
pub struct FileContentFactory;

impl FileContentFactory {
    /// Create a basic package.json content
    pub fn package_json(dependencies: HashMap<&str, &str>) -> String {
        let deps: Vec<String> = dependencies
            .iter()
            .map(|(name, version)| format!("\"{}\": \"{}\"", name, version))
            .collect();

        format!(
            r#"{{
    "name": "test-package",
    "version": "1.0.0",
    "dependencies": {{
        {}
    }}
}}"#,
            deps.join(",\n        ")
        )
    }

    /// Create a basic Cargo.toml content
    pub fn cargo_toml(dependencies: HashMap<&str, &str>) -> String {
        let deps: Vec<String> = dependencies
            .iter()
            .map(|(name, version)| format!("{} = \"{}\"", name, version))
            .collect();

        format!(
            r#"[package]
name = "test-package"
version = "1.0.0"

[dependencies]
{}
"#,
            deps.join("\n")
        )
    }

    /// Create a basic requirements.txt content
    pub fn requirements_txt(packages: Vec<&str>) -> String {
        packages.join("\n")
    }

    /// Create malformed package.json for edge case testing
    pub fn malformed_package_json() -> Vec<(&'static str, String)> {
        vec![
            ("empty_object", "{}".to_string()),
            ("malformed_json", r#"{"dependencies": {"express": "4.17.1",}}"#.to_string()),
            ("null_dependencies", r#"{"dependencies": null}"#.to_string()),
            ("array_dependencies", r#"{"dependencies": []}"#.to_string()),
            ("string_dependencies", r#"{"dependencies": "not an object"}"#.to_string()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_factory_creates_valid_packages() {
        let pkg = PackageFactory::npm("express", "4.17.1");
        assert_eq!(pkg.name, "express");
        assert_eq!(pkg.version.to_string(), "4.17.1");
        assert_eq!(pkg.ecosystem, Ecosystem::Npm);
    }

    #[test]
    fn test_vulnerability_factory_creates_valid_vulnerabilities() {
        let pkg = PackageFactory::npm("express", "4.17.1");
        let vuln = VulnerabilityFactory::high_severity("TEST-001", pkg);

        assert_eq!(vuln.id.as_str(), "TEST-001");
        assert_eq!(vuln.severity, Severity::High);
        assert!(!vuln.affected_packages.is_empty());
    }

    #[test]
    fn test_analysis_report_factory() {
        let packages = vec![
            PackageFactory::npm("express", "4.17.1"),
            PackageFactory::npm("lodash", "4.17.20"),
        ];

        let report = AnalysisReportFactory::clean(packages.clone());
        assert_eq!(report.packages.len(), 2);
        assert_eq!(report.vulnerabilities.len(), 0);

        let critical_report = AnalysisReportFactory::critical(packages.clone(), 3);
        assert_eq!(critical_report.vulnerabilities.len(), 3);
        assert!(critical_report.vulnerabilities.iter().all(|v| v.severity == Severity::Critical));
    }

    #[test]
    fn test_file_content_factory() {
        let mut deps = HashMap::new();
        deps.insert("express", "4.17.1");
        deps.insert("lodash", "4.17.20");

        let content = FileContentFactory::package_json(deps);
        assert!(content.contains("express"));
        assert!(content.contains("lodash"));
        assert!(content.contains("4.17.1"));
    }
}