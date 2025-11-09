//! Test data fixtures for vulnera-deps

use vulnera_core::domain::vulnerability::{
    entities::Package,
    value_objects::{Ecosystem, Version},
};

/// Create a test package for dependency resolution
pub fn test_package(name: impl Into<String>, version: impl Into<String>) -> Package {
    Package::new(
        name.into(),
        Version::parse(&version.into()).expect("Invalid version"),
        Ecosystem::Npm,
    )
}

/// Sample dependency graph data
pub fn sample_dependency_graph() -> Vec<(String, String, Vec<String>)> {
    vec![
        ("package-a".to_string(), "1.0.0".to_string(), vec![]),
        (
            "package-b".to_string(),
            "2.0.0".to_string(),
            vec!["package-a".to_string()],
        ),
        (
            "package-c".to_string(),
            "1.5.0".to_string(),
            vec!["package-a".to_string(), "package-b".to_string()],
        ),
    ]
}

