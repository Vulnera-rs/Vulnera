//! Integration tests for version resolution algorithms

use std::collections::HashMap;
use vulnera_core::domain::vulnerability::value_objects::{Ecosystem, Version};
use vulnera_deps::domain::{
    DependencyEdge, DependencyGraph, PackageId, PackageNode, VersionConstraint,
};
use vulnera_deps::services::resolution_algorithms::{BacktrackingResolver, LexicographicOptimizer};

fn create_version(v: &str) -> Version {
    Version::parse(v).unwrap()
}

fn _create_package_id(name: &str, _version: &str) -> PackageId {
    PackageId::new("npm".to_string(), name.to_string())
}

#[test]
fn test_lexicographic_optimizer_patch_preference() {
    let current = create_version("1.2.3");
    let candidates = vec![
        create_version("1.2.4"), // patch
        create_version("1.3.0"), // minor
        create_version("2.0.0"), // major
    ];

    let selected = LexicographicOptimizer::select_version(Some(&current), &candidates);
    assert_eq!(selected, Some(create_version("1.2.4")));
}

#[test]
fn test_lexicographic_optimizer_minor_preference() {
    let current = create_version("1.2.3");
    let candidates = vec![
        create_version("1.3.0"), // minor
        create_version("2.0.0"), // major
    ];

    let selected = LexicographicOptimizer::select_version(Some(&current), &candidates);
    assert_eq!(selected, Some(create_version("1.3.0")));
}

#[test]
fn test_lexicographic_optimizer_major_preference() {
    let current = create_version("1.2.3");
    let candidates = vec![
        create_version("2.0.0"), // major
    ];

    let selected = LexicographicOptimizer::select_version(Some(&current), &candidates);
    assert_eq!(selected, Some(create_version("2.0.0")));
}

#[test]
fn test_lexicographic_optimizer_downgrade_avoidance() {
    let current = create_version("1.2.3");
    let candidates = vec![
        create_version("1.2.2"), // downgrade
        create_version("1.2.1"), // downgrade
    ];

    let selected = LexicographicOptimizer::select_version(Some(&current), &candidates);
    assert_eq!(selected, None);
}

#[test]
fn test_lexicographic_optimizer_minimal_upgrade() {
    let current = create_version("1.2.3");
    let candidates = vec![
        create_version("1.2.4"), // patch
        create_version("1.2.5"), // patch (larger)
    ];

    let selected = LexicographicOptimizer::select_version(Some(&current), &candidates);
    assert_eq!(selected, Some(create_version("1.2.4")));
}

#[test]
fn test_backtracking_resolver_basic() {
    let mut graph = DependencyGraph::new();
    let pkg_a = vulnera_core::domain::vulnerability::entities::Package::new(
        "a".to_string(),
        create_version("1.0.0"),
        Ecosystem::Npm,
    )
    .unwrap();

    let node_a = PackageNode::new(pkg_a);
    let id_a = node_a.id.clone();
    graph.add_node(node_a);

    let mut available_versions = HashMap::new();
    available_versions.insert(
        id_a.clone(),
        vec![create_version("1.0.0"), create_version("1.1.0")],
    );

    let result = BacktrackingResolver::resolve(&graph, &available_versions);

    assert!(result.conflicts.is_empty());
    assert_eq!(result.resolved.get(&id_a), Some(&create_version("1.1.0"))); // Should pick latest
}

#[test]
fn test_backtracking_resolver_conflict() {
    let mut graph = DependencyGraph::new();
    let pkg_a = vulnera_core::domain::vulnerability::entities::Package::new(
        "a".to_string(),
        create_version("1.0.0"),
        Ecosystem::Npm,
    )
    .unwrap();

    let node_a = PackageNode::new(pkg_a);
    let id_a = node_a.id.clone();
    graph.add_node(node_a);

    // No versions available for 'a'
    let available_versions = HashMap::new();

    let result = BacktrackingResolver::resolve(&graph, &available_versions);

    assert!(!result.conflicts.is_empty());
    assert_eq!(result.conflicts[0].package, id_a);
}

#[test]
fn test_backtracking_resolver_with_dependencies() {
    // A -> B
    let mut graph = DependencyGraph::new();
    let pkg_a = vulnera_core::domain::vulnerability::entities::Package::new(
        "a".to_string(),
        create_version("1.0.0"),
        Ecosystem::Npm,
    )
    .unwrap();
    let pkg_b = vulnera_core::domain::vulnerability::entities::Package::new(
        "b".to_string(),
        create_version("1.0.0"),
        Ecosystem::Npm,
    )
    .unwrap();

    let node_a = PackageNode::new(pkg_a);
    let node_b = PackageNode::new(pkg_b);
    let id_a = node_a.id.clone();
    let id_b = node_b.id.clone();

    graph.add_node(node_a);
    graph.add_node(node_b);

    graph.add_edge(DependencyEdge::new(
        id_a.clone(),
        id_b.clone(),
        VersionConstraint::Any,
        false,
    ));

    let mut available_versions = HashMap::new();
    available_versions.insert(id_a.clone(), vec![create_version("1.0.0")]);
    available_versions.insert(id_b.clone(), vec![create_version("2.0.0")]);

    let result = BacktrackingResolver::resolve(&graph, &available_versions);

    assert!(result.conflicts.is_empty());
    assert_eq!(result.resolved.get(&id_a), Some(&create_version("1.0.0")));
    assert_eq!(result.resolved.get(&id_b), Some(&create_version("2.0.0")));
}
