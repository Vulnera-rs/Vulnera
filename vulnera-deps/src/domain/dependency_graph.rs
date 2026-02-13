//! Dependency graph data structures
//!
//! This module provides data structures for representing dependency graphs,
//! including nodes (packages), edges (dependencies), and graph algorithms.

use std::collections::{HashMap, HashSet};
use vulnera_core::domain::vulnerability::entities::Package;
use vulnera_core::domain::vulnerability::value_objects::Version;

use super::source_location::SourceLocation;
use super::version_constraint::VersionConstraint;

/// Unique identifier for a package in the dependency graph
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct PackageId {
    pub ecosystem: String,
    pub name: String,
}

impl PackageId {
    pub fn new(ecosystem: String, name: String) -> Self {
        Self { ecosystem, name }
    }

    pub fn from_package(package: &Package) -> Self {
        Self {
            ecosystem: package.ecosystem.canonical_name().to_string(),
            name: package.name.clone(),
        }
    }
}

impl std::fmt::Display for PackageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.ecosystem, self.name)
    }
}

/// Dependency edge in the graph
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DependencyEdge {
    /// Source package ID
    pub from: PackageId,
    /// Target package ID
    pub to: PackageId,
    /// Version constraint
    pub constraint: VersionConstraint,
    /// Whether this is a transitive dependency
    pub is_transitive: bool,
    /// Source location in the manifest file
    pub source_location: Option<SourceLocation>,
    /// Dependency type (e.g., "dependencies", "devDependencies", "optionalDependencies")
    pub dep_type: Option<String>,
}

impl DependencyEdge {
    pub fn new(
        from: PackageId,
        to: PackageId,
        constraint: VersionConstraint,
        is_transitive: bool,
    ) -> Self {
        Self {
            from,
            to,
            constraint,
            is_transitive,
            source_location: None,
            dep_type: None,
        }
    }

    pub fn with_location(mut self, location: SourceLocation) -> Self {
        self.source_location = Some(location);
        self
    }

    pub fn with_dep_type(mut self, dep_type: String) -> Self {
        self.dep_type = Some(dep_type);
        self
    }
}

/// Extended package metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackageMetadata {
    /// Resolved version (if available from lockfile)
    pub resolved_version: Option<Version>,
    /// Whether this is a direct dependency
    pub is_direct: bool,
    /// Whether this is a development dependency
    pub is_dev: bool,
    /// Whether this is an optional dependency
    pub is_optional: bool,
    /// Source location in manifest file
    pub source_location: Option<SourceLocation>,
}

impl Default for PackageMetadata {
    fn default() -> Self {
        Self {
            resolved_version: None,
            is_direct: true,
            is_dev: false,
            is_optional: false,
            source_location: None,
        }
    }
}

/// Package node in the dependency graph
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackageNode {
    /// Package ID
    pub id: PackageId,
    /// Package entity (with version)
    pub package: Package,
    /// Direct dependencies (package IDs)
    pub direct_dependencies: Vec<PackageId>,
    /// Packages that depend on this one (reverse dependencies)
    pub dependents: Vec<PackageId>,
    /// Extended metadata
    pub metadata: PackageMetadata,
}

impl PackageNode {
    pub fn new(package: Package) -> Self {
        let id = PackageId::from_package(&package);
        Self {
            id,
            package,
            direct_dependencies: Vec::new(),
            dependents: Vec::new(),
            metadata: PackageMetadata::default(),
        }
    }

    pub fn with_metadata(mut self, metadata: PackageMetadata) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Dependency graph representing the complete dependency structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DependencyGraph {
    /// All package nodes in the graph
    pub nodes: HashMap<PackageId, PackageNode>,
    /// All dependency edges
    pub edges: Vec<DependencyEdge>,
    /// Root packages (direct dependencies)
    pub root_packages: Vec<PackageId>,
}

impl DependencyGraph {
    /// Create a new empty dependency graph
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            root_packages: Vec::new(),
        }
    }

    /// Add a package node to the graph
    pub fn add_node(&mut self, node: PackageNode) {
        let id = node.id.clone();
        if node.metadata.is_direct && !self.root_packages.contains(&id) {
            self.root_packages.push(id.clone());
        }
        self.nodes.insert(id, node);
    }

    /// Add a dependency edge to the graph
    pub fn add_edge(&mut self, edge: DependencyEdge) {
        // Update the from node's direct dependencies
        if let Some(from_node) = self.nodes.get_mut(&edge.from)
            && !from_node.direct_dependencies.contains(&edge.to)
        {
            from_node.direct_dependencies.push(edge.to.clone());
        }

        // Update the to node's dependents
        if let Some(to_node) = self.nodes.get_mut(&edge.to)
            && !to_node.dependents.contains(&edge.from)
        {
            to_node.dependents.push(edge.from.clone());
        }

        self.edges.push(edge);
    }

    /// Get a node by ID
    pub fn get_node(&self, id: &PackageId) -> Option<&PackageNode> {
        self.nodes.get(id)
    }

    /// Get all transitive dependencies of a package
    pub fn get_transitive_dependencies(&self, package_id: &PackageId) -> HashSet<PackageId> {
        let mut visited = HashSet::new();
        let mut to_visit = vec![package_id.clone()];
        visited.insert(package_id.clone());

        while let Some(current) = to_visit.pop() {
            if let Some(node) = self.nodes.get(&current) {
                for dep_id in &node.direct_dependencies {
                    if !visited.contains(dep_id) {
                        visited.insert(dep_id.clone());
                        to_visit.push(dep_id.clone());
                    }
                }
            }
        }

        visited.remove(package_id);
        visited
    }

    /// Perform topological sort of packages
    /// Returns packages in dependency order (dependencies before dependents)
    pub fn topological_sort(&self) -> Result<Vec<PackageId>, String> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut visiting = HashSet::new();

        fn visit(
            graph: &DependencyGraph,
            node_id: &PackageId,
            visited: &mut HashSet<PackageId>,
            visiting: &mut HashSet<PackageId>,
            result: &mut Vec<PackageId>,
        ) -> Result<(), String> {
            if visited.contains(node_id) {
                return Ok(());
            }
            if visiting.contains(node_id) {
                return Err(format!(
                    "Circular dependency detected involving {}",
                    node_id
                ));
            }

            visiting.insert(node_id.clone());

            if let Some(node) = graph.nodes.get(node_id) {
                for dep_id in &node.direct_dependencies {
                    visit(graph, dep_id, visited, visiting, result)?;
                }
            }

            visiting.remove(node_id);
            visited.insert(node_id.clone());
            result.push(node_id.clone());

            Ok(())
        }

        for root_id in &self.root_packages {
            visit(self, root_id, &mut visited, &mut visiting, &mut result)?;
        }

        // Also visit any nodes not reachable from roots
        for node_id in self.nodes.keys() {
            if !visited.contains(node_id) {
                visit(self, node_id, &mut visited, &mut visiting, &mut result)?;
            }
        }

        Ok(result)
    }

    /// Get the total number of packages in the graph
    pub fn package_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get the total number of dependencies (edges) in the graph
    pub fn dependency_count(&self) -> usize {
        self.edges.len()
    }

    /// Export the graph to Graphviz DOT format
    pub fn to_dot(&self) -> String {
        let mut dot = String::from("digraph DependencyGraph {\n");
        dot.push_str("  node [shape=box, fontname=\"Helvetica\", fontsize=10];\n");
        dot.push_str("  edge [fontname=\"Helvetica\", fontsize=8];\n");
        dot.push_str("  rankdir=LR;\n");

        // Add nodes
        for (id, node) in &self.nodes {
            let label = format!("{}@{}", node.package.name, node.package.version);
            let color = if node.metadata.is_direct {
                "#add8e6"
            } else {
                "#ffffff"
            };
            dot.push_str(&format!(
                "  \"{}\" [label=\"{}\", style=filled, fillcolor=\"{}\"];\n",
                id, label, color
            ));
        }

        // Add edges
        for edge in &self.edges {
            let style = if edge.is_transitive {
                "dashed"
            } else {
                "solid"
            };
            dot.push_str(&format!(
                "  \"{}\" -> \"{}\" [label=\"{}\", style={}];\n",
                edge.from, edge.to, edge.constraint, style
            ));
        }

        dot.push_str("}\n");
        dot
    }

    /// Export the graph to a JSON format suitable for frontend visualization
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "nodes": self.nodes.values().map(|n| {
                serde_json::json!({
                    "id": n.id.to_string(),
                    "name": n.package.name,
                    "version": n.package.version.to_string(),
                    "is_direct": n.metadata.is_direct,
                    "ecosystem": n.package.ecosystem.canonical_name(),
                    "is_dev": n.metadata.is_dev,
                    "is_optional": n.metadata.is_optional
                })
            }).collect::<Vec<_>>(),
            "links": self.edges.iter().map(|e| {
                serde_json::json!({
                    "source": e.from.to_string(),
                    "target": e.to.to_string(),
                    "requirement": e.constraint.to_string(),
                    "is_transitive": e.is_transitive,
                    "dep_type": e.dep_type
                })
            }).collect::<Vec<_>>()
        })
    }
}

impl Default for DependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vulnera_core::domain::vulnerability::value_objects::Ecosystem;

    fn create_test_package(name: &str, version: &str) -> Package {
        Package::new(
            name.to_string(),
            Version::parse(version).unwrap(),
            Ecosystem::Npm,
        )
        .unwrap()
    }

    #[test]
    fn test_dependency_graph_new() {
        let graph = DependencyGraph::new();
        assert_eq!(graph.package_count(), 0);
        assert_eq!(graph.dependency_count(), 0);
    }

    #[test]
    fn test_add_node() {
        let mut graph = DependencyGraph::new();
        let pkg = create_test_package("express", "4.17.1");
        let node = PackageNode::new(pkg);
        graph.add_node(node);

        assert_eq!(graph.package_count(), 1);
        assert!(graph.root_packages.len() > 0);
    }

    #[test]
    fn test_add_edge() {
        let mut graph = DependencyGraph::new();
        let pkg1 = create_test_package("express", "4.17.1");
        let pkg2 = create_test_package("body-parser", "1.19.0");
        let node1 = PackageNode::new(pkg1);
        let node2 = PackageNode::new(pkg2);

        let id1 = node1.id.clone();
        let id2 = node2.id.clone();

        graph.add_node(node1);
        graph.add_node(node2);

        let edge = DependencyEdge::new(
            id1.clone(),
            id2.clone(),
            VersionConstraint::Exact(Version::parse("1.19.0").unwrap()),
            false,
        );
        graph.add_edge(edge);

        assert_eq!(graph.dependency_count(), 1);
        assert!(
            graph
                .get_node(&id1)
                .unwrap()
                .direct_dependencies
                .contains(&id2)
        );
        assert!(graph.get_node(&id2).unwrap().dependents.contains(&id1));
    }

    #[test]
    fn test_topological_sort() {
        let mut graph = DependencyGraph::new();
        let pkg1 = create_test_package("express", "4.17.1");
        let pkg2 = create_test_package("body-parser", "1.19.0");
        let pkg3 = create_test_package("bytes", "3.1.0");

        let node1 = PackageNode::new(pkg1);
        let node2 = PackageNode::new(pkg2);
        let node3 = PackageNode::new(pkg3);

        let id1 = node1.id.clone();
        let id2 = node2.id.clone();
        let id3 = node3.id.clone();

        graph.add_node(node1);
        graph.add_node(node2);
        graph.add_node(node3);

        // express -> body-parser -> bytes
        graph.add_edge(DependencyEdge::new(
            id1.clone(),
            id2.clone(),
            VersionConstraint::Any,
            false,
        ));
        graph.add_edge(DependencyEdge::new(
            id2.clone(),
            id3.clone(),
            VersionConstraint::Any,
            false,
        ));

        let sorted = graph.topological_sort().unwrap();
        // bytes should come before body-parser, body-parser before express
        let idx1 = sorted.iter().position(|x| x == &id1).unwrap();
        let idx2 = sorted.iter().position(|x| x == &id2).unwrap();
        let idx3 = sorted.iter().position(|x| x == &id3).unwrap();

        assert!(idx3 < idx2);
        assert!(idx2 < idx1);
    }

    #[test]
    fn test_get_transitive_dependencies() {
        let mut graph = DependencyGraph::new();
        let pkg1 = create_test_package("express", "4.17.1");
        let pkg2 = create_test_package("body-parser", "1.19.0");
        let pkg3 = create_test_package("bytes", "3.1.0");

        let node1 = PackageNode::new(pkg1);
        let node2 = PackageNode::new(pkg2);
        let node3 = PackageNode::new(pkg3);

        let id1 = node1.id.clone();
        let id2 = node2.id.clone();
        let id3 = node3.id.clone();

        graph.add_node(node1);
        graph.add_node(node2);
        graph.add_node(node3);

        graph.add_edge(DependencyEdge::new(
            id1.clone(),
            id2.clone(),
            VersionConstraint::Any,
            false,
        ));
        graph.add_edge(DependencyEdge::new(
            id2.clone(),
            id3.clone(),
            VersionConstraint::Any,
            true, // transitive
        ));

        let transitive = graph.get_transitive_dependencies(&id1);
        assert!(transitive.contains(&id2));
        assert!(transitive.contains(&id3));
        assert!(!transitive.contains(&id1));
    }

    #[test]
    fn test_topological_sort_cycle() {
        let mut graph = DependencyGraph::new();
        let pkg1 = create_test_package("a", "1.0.0");
        let pkg2 = create_test_package("b", "1.0.0");
        let pkg3 = create_test_package("c", "1.0.0");

        let node1 = PackageNode::new(pkg1);
        let node2 = PackageNode::new(pkg2);
        let node3 = PackageNode::new(pkg3);

        let id1 = node1.id.clone();
        let id2 = node2.id.clone();
        let id3 = node3.id.clone();

        graph.add_node(node1);
        graph.add_node(node2);
        graph.add_node(node3);

        // a -> b -> c -> a
        graph.add_edge(DependencyEdge::new(
            id1.clone(),
            id2.clone(),
            VersionConstraint::Any,
            false,
        ));
        graph.add_edge(DependencyEdge::new(
            id2.clone(),
            id3.clone(),
            VersionConstraint::Any,
            false,
        ));
        graph.add_edge(DependencyEdge::new(
            id3.clone(),
            id1.clone(),
            VersionConstraint::Any,
            false,
        ));

        let result = graph.topological_sort();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Circular dependency"));
    }

    #[test]
    fn test_diamond_dependencies() {
        let mut graph = DependencyGraph::new();
        // A -> B -> D
        // A -> C -> D
        let pkg_a = create_test_package("a", "1.0.0");
        let pkg_b = create_test_package("b", "1.0.0");
        let pkg_c = create_test_package("c", "1.0.0");
        let pkg_d = create_test_package("d", "1.0.0");

        let id_a = PackageId::from_package(&pkg_a);
        let id_b = PackageId::from_package(&pkg_b);
        let id_c = PackageId::from_package(&pkg_c);
        let id_d = PackageId::from_package(&pkg_d);

        graph.add_node(PackageNode::new(pkg_a));
        graph.add_node(PackageNode::new(pkg_b));
        graph.add_node(PackageNode::new(pkg_c));
        graph.add_node(PackageNode::new(pkg_d));

        graph.add_edge(DependencyEdge::new(
            id_a.clone(),
            id_b.clone(),
            VersionConstraint::Any,
            false,
        ));
        graph.add_edge(DependencyEdge::new(
            id_a.clone(),
            id_c.clone(),
            VersionConstraint::Any,
            false,
        ));
        graph.add_edge(DependencyEdge::new(
            id_b.clone(),
            id_d.clone(),
            VersionConstraint::Any,
            false,
        ));
        graph.add_edge(DependencyEdge::new(
            id_c.clone(),
            id_d.clone(),
            VersionConstraint::Any,
            false,
        ));

        let sorted = graph.topological_sort().unwrap();

        let idx_a = sorted.iter().position(|x| x == &id_a).unwrap();
        let idx_b = sorted.iter().position(|x| x == &id_b).unwrap();
        let idx_c = sorted.iter().position(|x| x == &id_c).unwrap();
        let idx_d = sorted.iter().position(|x| x == &id_d).unwrap();

        // D must be before B and C
        assert!(idx_d < idx_b);
        assert!(idx_d < idx_c);
        // B and C must be before A
        assert!(idx_b < idx_a);
        assert!(idx_c < idx_a);
    }

    #[test]
    fn test_orphaned_nodes() {
        let mut graph = DependencyGraph::new();
        let pkg1 = create_test_package("a", "1.0.0");
        let pkg2 = create_test_package("b", "1.0.0"); // Orphan

        let id1 = PackageId::from_package(&pkg1);
        let id2 = PackageId::from_package(&pkg2);

        graph.add_node(PackageNode::new(pkg1));
        graph.add_node(PackageNode::new(pkg2));

        let sorted = graph.topological_sort().unwrap();
        assert!(sorted.contains(&id1));
        assert!(sorted.contains(&id2));
        assert_eq!(sorted.len(), 2);
    }

    #[test]
    fn test_disconnected_components() {
        let mut graph = DependencyGraph::new();
        // A -> B
        // C -> D
        let pkg_a = create_test_package("a", "1.0.0");
        let pkg_b = create_test_package("b", "1.0.0");
        let pkg_c = create_test_package("c", "1.0.0");
        let pkg_d = create_test_package("d", "1.0.0");

        let id_a = PackageId::from_package(&pkg_a);
        let id_b = PackageId::from_package(&pkg_b);
        let id_c = PackageId::from_package(&pkg_c);
        let id_d = PackageId::from_package(&pkg_d);

        graph.add_node(PackageNode::new(pkg_a));
        graph.add_node(PackageNode::new(pkg_b));
        graph.add_node(PackageNode::new(pkg_c));
        graph.add_node(PackageNode::new(pkg_d));

        graph.add_edge(DependencyEdge::new(
            id_a.clone(),
            id_b.clone(),
            VersionConstraint::Any,
            false,
        ));
        graph.add_edge(DependencyEdge::new(
            id_c.clone(),
            id_d.clone(),
            VersionConstraint::Any,
            false,
        ));

        let sorted = graph.topological_sort().unwrap();

        let idx_a = sorted.iter().position(|x| x == &id_a).unwrap();
        let idx_b = sorted.iter().position(|x| x == &id_b).unwrap();
        let idx_c = sorted.iter().position(|x| x == &id_c).unwrap();
        let idx_d = sorted.iter().position(|x| x == &id_d).unwrap();

        assert!(idx_b < idx_a);
        assert!(idx_d < idx_c);
    }

    #[test]
    fn test_deep_dependency_tree() {
        let mut graph = DependencyGraph::new();
        // Create a chain of 100 packages: p0 -> p1 -> ... -> p99
        let count = 100;
        let mut ids = Vec::new();

        for i in 0..count {
            let pkg = create_test_package(&format!("p{}", i), "1.0.0");
            let id = PackageId::from_package(&pkg);
            ids.push(id.clone());
            graph.add_node(PackageNode::new(pkg));
        }

        for i in 0..count - 1 {
            graph.add_edge(DependencyEdge::new(
                ids[i].clone(),
                ids[i + 1].clone(),
                VersionConstraint::Any,
                false,
            ));
        }

        let sorted = graph.topological_sort().unwrap();
        assert_eq!(sorted.len(), count);

        // Verify order: p99 should be first, p0 last
        for i in 0..count - 1 {
            let idx_curr = sorted.iter().position(|x| x == &ids[i]).unwrap();
            let idx_next = sorted.iter().position(|x| x == &ids[i + 1]).unwrap();
            assert!(idx_next < idx_curr);
        }
    }
}
