//! Custom assertion helpers for more readable and specific test assertions
//!
//! This module provides domain-specific assertions that make tests more
//! expressive and easier to understand.

use vulnera_rust::domain::{
    entities::{Package, Vulnerability, AnalysisReport},
    value_objects::{Severity, VulnerabilityId},
};

/// Trait for assertions on AnalysisReport
pub trait AnalysisReportAssertions {
    /// Assert that the report contains exactly the expected number of packages
    fn assert_package_count(&self, expected: usize) -> &Self;

    /// Assert that the report contains exactly the expected number of vulnerabilities
    fn assert_vulnerability_count(&self, expected: usize) -> &Self;

    /// Assert that the report contains vulnerabilities of the specified severity
    fn assert_contains_severity(&self, severity: Severity) -> &Self;

    /// Assert that the report contains a vulnerability with the specified ID
    fn assert_contains_vulnerability(&self, vuln_id: &str) -> &Self;

    /// Assert that a specific package is affected by vulnerabilities
    fn assert_package_affected(&self, package_name: &str) -> &Self;

    /// Assert that the report has no critical vulnerabilities
    fn assert_no_critical_vulnerabilities(&self) -> &Self;

    /// Assert that the analysis took less than the specified duration
    fn assert_analysis_faster_than(&self, max_duration_ms: u64) -> &Self;
}

/// Trait for assertions on collections of Vulnerabilities
pub trait VulnerabilityAssertions {
    /// Assert the collection contains exactly the expected number of vulnerabilities
    fn assert_count(&self, expected: usize) -> &Self;

    /// Assert the collection contains at least one vulnerability of the specified severity
    fn assert_contains_severity(&self, severity: Severity) -> &Self;

    /// Assert the collection contains a vulnerability with the specified ID
    fn assert_contains_id(&self, vuln_id: &str) -> &Self;

    /// Assert all vulnerabilities have severity >= the specified minimum
    fn assert_all_severity_at_least(&self, min_severity: Severity) -> &Self;

    /// Assert the collection is sorted by severity (highest first)
    fn assert_sorted_by_severity_desc(&self) -> &Self;

    /// Assert no duplicate vulnerability IDs exist
    fn assert_no_duplicate_ids(&self) -> &Self;
}

/// Trait for assertions on collections of Packages
pub trait PackageAssertions {
    /// Assert the collection contains exactly the expected number of packages
    fn assert_count(&self, expected: usize) -> &Self;

    /// Assert the collection contains a package with the specified name
    fn assert_contains_name(&self, package_name: &str) -> &Self;

    /// Assert the collection contains a package with the specified ecosystem
    fn assert_contains_ecosystem(&self, ecosystem: vulnera_rust::domain::value_objects::Ecosystem) -> &Self;

    /// Assert all packages are from the specified ecosystem
    fn assert_all_from_ecosystem(&self, ecosystem: vulnera_rust::domain::value_objects::Ecosystem) -> &Self;

    /// Assert no duplicate package names exist
    fn assert_no_duplicate_names(&self) -> &Self;
}

impl AnalysisReportAssertions for AnalysisReport {
    fn assert_package_count(&self, expected: usize) -> &Self {
        assert_eq!(
            self.packages.len(),
            expected,
            "Expected {} packages, but found {}",
            expected,
            self.packages.len()
        );
        self
    }

    fn assert_vulnerability_count(&self, expected: usize) -> &Self {
        assert_eq!(
            self.vulnerabilities.len(),
            expected,
            "Expected {} vulnerabilities, but found {}",
            expected,
            self.vulnerabilities.len()
        );
        self
    }

    fn assert_contains_severity(&self, severity: Severity) -> &Self {
        let has_severity = self.vulnerabilities.iter().any(|v| v.severity == severity);
        assert!(
            has_severity,
            "Expected to find vulnerability with severity {:?} in report",
            severity
        );
        self
    }

    fn assert_contains_vulnerability(&self, vuln_id: &str) -> &Self {
        let has_vuln = self.vulnerabilities.iter().any(|v| v.id.as_str() == vuln_id);
        assert!(
            has_vuln,
            "Expected to find vulnerability with ID '{}' in report",
            vuln_id
        );
        self
    }

    fn assert_package_affected(&self, package_name: &str) -> &Self {
        let package_affected = self.vulnerabilities.iter().any(|v| {
            v.affected_packages.iter().any(|affected| affected.package.name == package_name)
        });
        assert!(
            package_affected,
            "Expected package '{}' to be affected by vulnerabilities",
            package_name
        );
        self
    }

    fn assert_no_critical_vulnerabilities(&self) -> &Self {
        let has_critical = self.vulnerabilities.iter().any(|v| v.severity == Severity::Critical);
        assert!(
            !has_critical,
            "Expected no critical vulnerabilities, but found some"
        );
        self
    }

    fn assert_analysis_faster_than(&self, max_duration_ms: u64) -> &Self {
        let duration_ms = self.metadata.analysis_time.as_millis() as u64;
        assert!(
            duration_ms < max_duration_ms,
            "Expected analysis to complete in <{}ms, but took {}ms",
            max_duration_ms,
            duration_ms
        );
        self
    }
}

impl VulnerabilityAssertions for &[Vulnerability] {
    fn assert_count(&self, expected: usize) -> &Self {
        assert_eq!(
            self.len(),
            expected,
            "Expected {} vulnerabilities, but found {}",
            expected,
            self.len()
        );
        self
    }

    fn assert_contains_severity(&self, severity: Severity) -> &Self {
        let has_severity = self.iter().any(|v| v.severity == severity);
        assert!(
            has_severity,
            "Expected to find vulnerability with severity {:?}",
            severity
        );
        self
    }

    fn assert_contains_id(&self, vuln_id: &str) -> &Self {
        let has_vuln = self.iter().any(|v| v.id.as_str() == vuln_id);
        assert!(
            has_vuln,
            "Expected to find vulnerability with ID '{}'",
            vuln_id
        );
        self
    }

    fn assert_all_severity_at_least(&self, min_severity: Severity) -> &Self {
        let violating_vulns: Vec<_> = self
            .iter()
            .filter(|v| v.severity < min_severity)
            .collect();

        assert!(
            violating_vulns.is_empty(),
            "Expected all vulnerabilities to have severity >= {:?}, but found {} with lower severity: {:?}",
            min_severity,
            violating_vulns.len(),
            violating_vulns.iter().map(|v| &v.id).collect::<Vec<_>>()
        );
        self
    }

    fn assert_sorted_by_severity_desc(&self) -> &Self {
        for window in self.windows(2) {
            let prev = &window[0];
            let next = &window[1];

            assert!(
                prev.severity >= next.severity,
                "Expected vulnerabilities to be sorted by severity descending, but found {:?} before {:?}",
                prev.id,
                next.id
            );
        }
        self
    }

    fn assert_no_duplicate_ids(&self) -> &Self {
        let mut seen_ids = std::collections::HashSet::new();
        let mut duplicates = Vec::new();

        for vuln in self.iter() {
            if !seen_ids.insert(vuln.id.as_str()) {
                duplicates.push(vuln.id.as_str());
            }
        }

        assert!(
            duplicates.is_empty(),
            "Expected no duplicate vulnerability IDs, but found: {:?}",
            duplicates
        );
        self
    }
}

impl VulnerabilityAssertions for Vec<Vulnerability> {
    fn assert_count(&self, expected: usize) -> &Self {
        self.as_slice().assert_count(expected);
        self
    }

    fn assert_contains_severity(&self, severity: Severity) -> &Self {
        self.as_slice().assert_contains_severity(severity);
        self
    }

    fn assert_contains_id(&self, vuln_id: &str) -> &Self {
        self.as_slice().assert_contains_id(vuln_id);
        self
    }

    fn assert_all_severity_at_least(&self, min_severity: Severity) -> &Self {
        self.as_slice().assert_all_severity_at_least(min_severity);
        self
    }

    fn assert_sorted_by_severity_desc(&self) -> &Self {
        self.as_slice().assert_sorted_by_severity_desc();
        self
    }

    fn assert_no_duplicate_ids(&self) -> &Self {
        self.as_slice().assert_no_duplicate_ids();
        self
    }
}

impl PackageAssertions for &[Package] {
    fn assert_count(&self, expected: usize) -> &Self {
        assert_eq!(
            self.len(),
            expected,
            "Expected {} packages, but found {}",
            expected,
            self.len()
        );
        self
    }

    fn assert_contains_name(&self, package_name: &str) -> &Self {
        let has_name = self.iter().any(|p| p.name == package_name);
        assert!(
            has_name,
            "Expected to find package with name '{}'",
            package_name
        );
        self
    }

    fn assert_contains_ecosystem(&self, ecosystem: vulnera_rust::domain::value_objects::Ecosystem) -> &Self {
        let has_ecosystem = self.iter().any(|p| p.ecosystem == ecosystem);
        assert!(
            has_ecosystem,
            "Expected to find package from ecosystem {:?}",
            ecosystem
        );
        self
    }

    fn assert_all_from_ecosystem(&self, ecosystem: vulnera_rust::domain::value_objects::Ecosystem) -> &Self {
        let other_ecosystems: Vec<_> = self
            .iter()
            .filter(|p| p.ecosystem != ecosystem)
            .map(|p| &p.ecosystem)
            .collect();

        assert!(
            other_ecosystems.is_empty(),
            "Expected all packages to be from ecosystem {:?}, but found packages from: {:?}",
            ecosystem,
            other_ecosystems
        );
        self
    }

    fn assert_no_duplicate_names(&self) -> &Self {
        let mut seen_names = std::collections::HashSet::new();
        let mut duplicates = Vec::new();

        for pkg in self.iter() {
            if !seen_names.insert(&pkg.name) {
                duplicates.push(&pkg.name);
            }
        }

        assert!(
            duplicates.is_empty(),
            "Expected no duplicate package names, but found: {:?}",
            duplicates
        );
        self
    }
}

impl PackageAssertions for Vec<Package> {
    fn assert_count(&self, expected: usize) -> &Self {
        self.as_slice().assert_count(expected);
        self
    }

    fn assert_contains_name(&self, package_name: &str) -> &Self {
        self.as_slice().assert_contains_name(package_name);
        self
    }

    fn assert_contains_ecosystem(&self, ecosystem: vulnera_rust::domain::value_objects::Ecosystem) -> &Self {
        self.as_slice().assert_contains_ecosystem(ecosystem);
        self
    }

    fn assert_all_from_ecosystem(&self, ecosystem: vulnera_rust::domain::value_objects::Ecosystem) -> &Self {
        self.as_slice().assert_all_from_ecosystem(ecosystem);
        self
    }

    fn assert_no_duplicate_names(&self) -> &Self {
        self.as_slice().assert_no_duplicate_names();
        self
    }
}

/// Additional utility assertions
pub struct AssertionHelpers;

impl AssertionHelpers {
    /// Assert that a Result is Ok and contains the expected value
    pub fn assert_ok_contains<T, E: std::fmt::Debug>(result: Result<T, E>, expected: T) -> T
    where
        T: std::fmt::Debug + PartialEq
    {
        match result {
            Ok(value) => {
                assert_eq!(value, expected, "Expected Ok({:?}), but got Ok({:?})", expected, value);
                value
            }
            Err(e) => panic!("Expected Ok({:?}), but got Err({:?})", expected, e),
        }
    }

    /// Assert that a Result is Err and contains the expected error
    pub fn assert_err_contains<T, E: std::fmt::Debug + PartialEq>(result: Result<T, E>, expected: E) -> E {
        match result {
            Ok(value) => panic!("Expected Err({:?}), but got Ok({:?})", expected, value),
            Err(e) => {
                assert_eq!(e, expected, "Expected Err({:?}), but got Err({:?})", expected, e);
                e
            }
        }
    }

    /// Assert that an Option is Some and contains the expected value
    pub fn assert_some_contains<T>(option: Option<T>, expected: T) -> T
    where
        T: std::fmt::Debug + PartialEq
    {
        match option {
            Some(value) => {
                assert_eq!(value, expected, "Expected Some({:?}), but got Some({:?})", expected, value);
                value
            }
            None => panic!("Expected Some({:?}), but got None", expected),
        }
    }

    /// Assert that an Option is None
    pub fn assert_none<T>(option: Option<T>) {
        assert!(option.is_none(), "Expected None, but got Some({:?})", option);
    }

    /// Assert that a collection contains exactly the expected items (order-independent)
    pub fn assert_contains_exactly<T, I>(actual: I, expected: I)
    where
        T: std::fmt::Debug + PartialEq + Eq + std::hash::Hash,
        I: IntoIterator<Item = T>,
    {
        let actual_set: std::collections::HashSet<_> = actual.into_iter().collect();
        let expected_set: std::collections::HashSet<_> = expected.into_iter().collect();

        assert_eq!(
            actual_set, expected_set,
            "Collections do not contain the same items.\nActual: {:?}\nExpected: {:?}",
            actual_set, expected_set
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::factories::*;

    #[test]
    fn test_analysis_report_assertions() {
        let packages = vec![
            PackageFactory::npm("express", "4.17.1"),
            PackageFactory::npm("lodash", "4.17.20"),
        ];

        let vulnerabilities = vec![
            VulnerabilityFactory::high_severity("TEST-001", packages[0].clone()),
            VulnerabilityFactory::critical("TEST-002", packages[1].clone()),
        ];

        let report = AnalysisReportFactory::basic(packages, vulnerabilities);

        report
            .assert_package_count(2)
            .assert_vulnerability_count(2)
            .assert_contains_severity(Severity::High)
            .assert_contains_vulnerability("TEST-001")
            .assert_package_affected("express");
    }

    #[test]
    fn test_vulnerability_assertions() {
        let vulnerabilities = vec![
            VulnerabilityFactory::critical("VULN-001", PackageFactory::npm("express", "4.17.1")),
            VulnerabilityFactory::high_severity("VULN-002", PackageFactory::npm("lodash", "4.17.20")),
            VulnerabilityFactory::medium_severity("VULN-003", PackageFactory::npm("axios", "0.21.1")),
        ];

        vulnerabilities
            .assert_count(3)
            .assert_contains_severity(Severity::Critical)
            .assert_contains_id("VULN-002")
            .assert_all_severity_at_least(Severity::Medium)
            .assert_no_duplicate_ids();
    }

    #[test]
    fn test_package_assertions() {
        let packages = vec![
            PackageFactory::npm("express", "4.17.1"),
            PackageFactory::npm("lodash", "4.17.20"),
            PackageFactory::cargo("serde", "1.0.0"),
        ];

        packages
            .assert_count(3)
            .assert_contains_name("express")
            .assert_contains_ecosystem(vulnera_rust::domain::value_objects::Ecosystem::Npm)
            .assert_no_duplicate_names();

        // Test ecosystem-specific assertions
        let npm_packages: Vec<_> = packages
            .iter()
            .filter(|p| p.ecosystem == vulnera_rust::domain::value_objects::Ecosystem::Npm)
            .cloned()
            .collect();

        npm_packages.assert_all_from_ecosystem(vulnera_rust::domain::value_objects::Ecosystem::Npm);
    }

    #[test]
    fn test_assertion_helpers() {
        // Test Ok assertions
        let ok_result: Result<i32, &str> = Ok(42);
        AssertionHelpers::assert_ok_contains(ok_result, 42);

        // Test Err assertions
        let err_result: Result<i32, &str> = Err("error");
        AssertionHelpers::assert_err_contains(err_result, "error");

        // Test Option assertions
        let some_option: Option<i32> = Some(42);
        AssertionHelpers::assert_some_contains(some_option, 42);

        let none_option: Option<i32> = None;
        AssertionHelpers::assert_none(none_option);

        // Test collection assertions
        let actual = vec![1, 2, 3];
        let expected = vec![3, 2, 1]; // Different order
        AssertionHelpers::assert_contains_exactly(actual, expected);
    }
}