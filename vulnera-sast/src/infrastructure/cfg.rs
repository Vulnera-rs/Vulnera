//! Control-Flow Graph (CFG) foundations for path-sensitive analysis.
//!
//! This module provides a lightweight, language-agnostic CFG representation
//! intended as a stable substrate for future path-sensitive data-flow lanes.

use std::collections::{BTreeMap, BTreeSet};

/// A node identifier inside a CFG.
pub type CfgNodeId = usize;

/// Basic block kind for path-sensitive reasoning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfgNodeKind {
    Entry,
    Exit,
    Statement,
    Branch,
    Merge,
}

/// A single CFG node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgNode {
    pub id: CfgNodeId,
    pub kind: CfgNodeKind,
    pub line: Option<u32>,
    pub label: Option<String>,
}

/// Directed edge type in a CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfgEdgeKind {
    Normal,
    TrueBranch,
    FalseBranch,
}

/// Edge between CFG nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgEdge {
    pub from: CfgNodeId,
    pub to: CfgNodeId,
    pub kind: CfgEdgeKind,
}

/// Constraint collected when traversing a branch edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathConstraint {
    /// Branch node where this constraint originated.
    pub branch_node: CfgNodeId,
    /// Optional source-code line for diagnostics.
    pub line: Option<u32>,
    /// Human-friendly condition label (if known).
    pub condition_label: Option<String>,
    /// Whether the branch was taken as true or false.
    pub expected_truth: bool,
}

/// A single path state through CFG with accumulated constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgPath {
    pub nodes: Vec<CfgNodeId>,
    pub constraints: Vec<PathConstraint>,
}

/// Immutable control-flow graph.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlFlowGraph {
    nodes: BTreeMap<CfgNodeId, CfgNode>,
    outgoing: BTreeMap<CfgNodeId, Vec<CfgEdge>>,
    incoming: BTreeMap<CfgNodeId, Vec<CfgEdge>>,
    entry_id: Option<CfgNodeId>,
    exit_id: Option<CfgNodeId>,
}

impl ControlFlowGraph {
    pub fn entry_id(&self) -> Option<CfgNodeId> {
        self.entry_id
    }

    pub fn exit_id(&self) -> Option<CfgNodeId> {
        self.exit_id
    }

    pub fn node(&self, id: CfgNodeId) -> Option<&CfgNode> {
        self.nodes.get(&id)
    }

    pub fn nodes(&self) -> impl Iterator<Item = &CfgNode> {
        self.nodes.values()
    }

    pub fn outgoing(&self, id: CfgNodeId) -> &[CfgEdge] {
        self.outgoing.get(&id).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn incoming(&self, id: CfgNodeId) -> &[CfgEdge] {
        self.incoming.get(&id).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Conservative branch count used as a quick path-sensitivity signal.
    pub fn branch_count(&self) -> usize {
        self.nodes
            .values()
            .filter(|node| node.kind == CfgNodeKind::Branch)
            .count()
    }

    /// Acyclic upper-bound estimate for number of path splits.
    ///
    /// This computes $2^b$ where $b$ is number of branch nodes, capped at 1<<20.
    pub fn path_split_upper_bound(&self) -> usize {
        let branches = self.branch_count().min(20) as u32;
        1usize << branches
    }

    /// Enumerate execution paths from entry to exit while collecting branch constraints.
    ///
    /// The search is bounded by `max_paths` to prevent combinatorial explosion.
    pub fn enumerate_paths(&self, max_paths: usize) -> Vec<CfgPath> {
        if max_paths == 0 {
            return Vec::new();
        }

        let Some(entry) = self.entry_id else {
            return Vec::new();
        };
        let Some(exit) = self.exit_id else {
            return Vec::new();
        };

        let mut collected = Vec::new();
        let mut stack = vec![CfgPath {
            nodes: vec![entry],
            constraints: Vec::new(),
        }];

        while let Some(path) = stack.pop() {
            let Some(&current) = path.nodes.last() else {
                continue;
            };

            if current == exit {
                collected.push(path);
                if collected.len() >= max_paths {
                    break;
                }
                continue;
            }

            for edge in self.outgoing(current).iter().rev() {
                // Keep traversal loop-safe without requiring full cycle summaries yet.
                if path.nodes.contains(&edge.to) {
                    continue;
                }

                let mut next = path.clone();
                next.nodes.push(edge.to);

                if let Some(constraint) = self.constraint_from_edge(edge) {
                    next.constraints.push(constraint);
                }

                stack.push(next);
            }
        }

        collected
    }

    fn constraint_from_edge(&self, edge: &CfgEdge) -> Option<PathConstraint> {
        let expected_truth = match edge.kind {
            CfgEdgeKind::TrueBranch => Some(true),
            CfgEdgeKind::FalseBranch => Some(false),
            CfgEdgeKind::Normal => None,
        }?;

        let source_node = self.node(edge.from)?;
        if source_node.kind != CfgNodeKind::Branch {
            return None;
        }

        Some(PathConstraint {
            branch_node: source_node.id,
            line: source_node.line,
            condition_label: source_node.label.clone(),
            expected_truth,
        })
    }
}

/// Builder for constructing CFGs.
#[derive(Debug, Default)]
pub struct CfgBuilder {
    graph: ControlFlowGraph,
    next_id: CfgNodeId,
}

impl CfgBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(
        &mut self,
        kind: CfgNodeKind,
        line: Option<u32>,
        label: Option<String>,
    ) -> CfgNodeId {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);

        let node = CfgNode {
            id,
            kind,
            line,
            label,
        };

        if kind == CfgNodeKind::Entry {
            self.graph.entry_id = Some(id);
        }
        if kind == CfgNodeKind::Exit {
            self.graph.exit_id = Some(id);
        }

        self.graph.nodes.insert(id, node);
        id
    }

    pub fn add_edge(&mut self, from: CfgNodeId, to: CfgNodeId, kind: CfgEdgeKind) {
        let edge = CfgEdge { from, to, kind };
        self.graph
            .outgoing
            .entry(from)
            .or_default()
            .push(edge.clone());
        self.graph.incoming.entry(to).or_default().push(edge);
    }

    pub fn build(self) -> ControlFlowGraph {
        self.graph
    }

    /// Create a simple linear CFG from statement lines.
    pub fn linear_from_lines(lines: &[u32]) -> ControlFlowGraph {
        let mut builder = Self::new();
        let entry = builder.add_node(CfgNodeKind::Entry, None, Some("entry".to_string()));

        let mut prev = entry;
        for line in lines {
            let stmt = builder.add_node(CfgNodeKind::Statement, Some(*line), None);
            builder.add_edge(prev, stmt, CfgEdgeKind::Normal);
            prev = stmt;
        }

        let exit = builder.add_node(CfgNodeKind::Exit, None, Some("exit".to_string()));
        builder.add_edge(prev, exit, CfgEdgeKind::Normal);

        builder.build()
    }

    /// Validate graph connectivity from entry for basic soundness checks.
    pub fn reachable_from_entry(graph: &ControlFlowGraph) -> BTreeSet<CfgNodeId> {
        let mut visited = BTreeSet::new();
        let Some(entry) = graph.entry_id() else {
            return visited;
        };

        let mut stack = vec![entry];
        while let Some(node) = stack.pop() {
            if !visited.insert(node) {
                continue;
            }

            for edge in graph.outgoing(node) {
                stack.push(edge.to);
            }
        }

        visited
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_cfg_has_entry_and_exit() {
        let cfg = CfgBuilder::linear_from_lines(&[10, 11, 12]);
        assert!(cfg.entry_id().is_some());
        assert!(cfg.exit_id().is_some());
        assert_eq!(cfg.branch_count(), 0);
        assert_eq!(cfg.path_split_upper_bound(), 1);
    }

    #[test]
    fn branch_cfg_counts_splits() {
        let mut builder = CfgBuilder::new();
        let entry = builder.add_node(CfgNodeKind::Entry, None, None);
        let branch = builder.add_node(CfgNodeKind::Branch, Some(20), Some("if".to_string()));
        let then_n = builder.add_node(CfgNodeKind::Statement, Some(21), None);
        let else_n = builder.add_node(CfgNodeKind::Statement, Some(23), None);
        let merge = builder.add_node(CfgNodeKind::Merge, Some(24), None);
        let exit = builder.add_node(CfgNodeKind::Exit, None, None);

        builder.add_edge(entry, branch, CfgEdgeKind::Normal);
        builder.add_edge(branch, then_n, CfgEdgeKind::TrueBranch);
        builder.add_edge(branch, else_n, CfgEdgeKind::FalseBranch);
        builder.add_edge(then_n, merge, CfgEdgeKind::Normal);
        builder.add_edge(else_n, merge, CfgEdgeKind::Normal);
        builder.add_edge(merge, exit, CfgEdgeKind::Normal);

        let cfg = builder.build();
        assert_eq!(cfg.branch_count(), 1);
        assert_eq!(cfg.path_split_upper_bound(), 2);

        let reachable = CfgBuilder::reachable_from_entry(&cfg);
        assert_eq!(reachable.len(), 6);
    }

    #[test]
    fn enumerate_paths_collects_true_false_constraints() {
        let mut builder = CfgBuilder::new();
        let entry = builder.add_node(CfgNodeKind::Entry, None, None);
        let branch = builder.add_node(
            CfgNodeKind::Branch,
            Some(40),
            Some("user_is_admin".to_string()),
        );
        let then_n = builder.add_node(CfgNodeKind::Statement, Some(41), None);
        let else_n = builder.add_node(CfgNodeKind::Statement, Some(42), None);
        let merge = builder.add_node(CfgNodeKind::Merge, Some(43), None);
        let exit = builder.add_node(CfgNodeKind::Exit, None, None);

        builder.add_edge(entry, branch, CfgEdgeKind::Normal);
        builder.add_edge(branch, then_n, CfgEdgeKind::TrueBranch);
        builder.add_edge(branch, else_n, CfgEdgeKind::FalseBranch);
        builder.add_edge(then_n, merge, CfgEdgeKind::Normal);
        builder.add_edge(else_n, merge, CfgEdgeKind::Normal);
        builder.add_edge(merge, exit, CfgEdgeKind::Normal);

        let cfg = builder.build();
        let paths = cfg.enumerate_paths(8);

        assert_eq!(paths.len(), 2, "Expected both true/false execution paths");

        let truth_values: BTreeSet<bool> = paths
            .iter()
            .flat_map(|p| p.constraints.iter().map(|c| c.expected_truth))
            .collect();
        assert_eq!(truth_values, [false, true].into_iter().collect());

        for path in paths {
            assert_eq!(path.constraints.len(), 1);
            let c = &path.constraints[0];
            assert_eq!(c.branch_node, branch);
            assert_eq!(c.line, Some(40));
            assert_eq!(c.condition_label.as_deref(), Some("user_is_admin"));
        }
    }

    #[test]
    fn enumerate_paths_respects_max_paths_bound() {
        let mut builder = CfgBuilder::new();
        let entry = builder.add_node(CfgNodeKind::Entry, None, None);
        let branch_a = builder.add_node(CfgNodeKind::Branch, Some(10), Some("a".to_string()));
        let branch_b = builder.add_node(CfgNodeKind::Branch, Some(20), Some("b".to_string()));
        let a_true = builder.add_node(CfgNodeKind::Statement, Some(11), None);
        let a_false = builder.add_node(CfgNodeKind::Statement, Some(12), None);
        let b_true = builder.add_node(CfgNodeKind::Statement, Some(21), None);
        let b_false = builder.add_node(CfgNodeKind::Statement, Some(22), None);
        let merge_a = builder.add_node(CfgNodeKind::Merge, Some(13), None);
        let merge_b = builder.add_node(CfgNodeKind::Merge, Some(23), None);
        let exit = builder.add_node(CfgNodeKind::Exit, None, None);

        builder.add_edge(entry, branch_a, CfgEdgeKind::Normal);
        builder.add_edge(branch_a, a_true, CfgEdgeKind::TrueBranch);
        builder.add_edge(branch_a, a_false, CfgEdgeKind::FalseBranch);
        builder.add_edge(a_true, merge_a, CfgEdgeKind::Normal);
        builder.add_edge(a_false, merge_a, CfgEdgeKind::Normal);
        builder.add_edge(merge_a, branch_b, CfgEdgeKind::Normal);
        builder.add_edge(branch_b, b_true, CfgEdgeKind::TrueBranch);
        builder.add_edge(branch_b, b_false, CfgEdgeKind::FalseBranch);
        builder.add_edge(b_true, merge_b, CfgEdgeKind::Normal);
        builder.add_edge(b_false, merge_b, CfgEdgeKind::Normal);
        builder.add_edge(merge_b, exit, CfgEdgeKind::Normal);

        let cfg = builder.build();
        let all_paths = cfg.enumerate_paths(16);
        assert_eq!(all_paths.len(), 4, "Two branches should produce 4 paths");

        let bounded_paths = cfg.enumerate_paths(3);
        assert_eq!(
            bounded_paths.len(),
            3,
            "Path enumeration should honor max_paths"
        );
    }
}
