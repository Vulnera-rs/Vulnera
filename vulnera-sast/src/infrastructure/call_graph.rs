//! Call Graph Analysis
//!
//! Inter-procedural call graph construction and traversal for SAST analysis.
//! Enables tracking function calls across module boundaries.

use std::collections::{HashMap, HashSet};
use tree_sitter::Tree;

use crate::domain::entities::{CallGraphNode, CallSite, FunctionSignature};
use crate::domain::value_objects::Language;
use crate::infrastructure::call_graph_queries::*;
use crate::infrastructure::query_engine::TreeSitterQueryEngine;

/// Call graph for inter-procedural analysis
#[derive(Debug, Default)]
pub struct CallGraph {
    /// Map from function ID to its node
    nodes: HashMap<String, CallGraphNode>,
    /// Adjacency list: caller -> callees
    edges: HashMap<String, Vec<CallSite>>,
    /// Reverse edges: callee -> callers
    reverse_edges: HashMap<String, Vec<String>>,
    /// Entry points (functions not called by others)
    entry_points: HashSet<String>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function node to the call graph
    pub fn add_function(&mut self, node: CallGraphNode) {
        let id = node.id.clone();
        self.nodes.insert(id.clone(), node);
        self.edges.entry(id.clone()).or_default();
        self.entry_points.insert(id);
    }

    /// Add a call edge from caller to callee
    pub fn add_call(&mut self, caller_id: &str, call_site: CallSite) {
        let callee_id = call_site.target_id.clone();

        // Add forward edge
        self.edges
            .entry(caller_id.to_string())
            .or_default()
            .push(call_site);

        // Add reverse edge
        self.reverse_edges
            .entry(callee_id.clone())
            .or_default()
            .push(caller_id.to_string());

        // Callee is no longer an entry point (it's called by someone)
        self.entry_points.remove(&callee_id);
    }

    /// Get a function node by ID
    pub fn get_function(&self, id: &str) -> Option<&CallGraphNode> {
        self.nodes.get(id)
    }

    /// Get all call sites from a function
    pub fn get_calls(&self, caller_id: &str) -> &[CallSite] {
        self.edges
            .get(caller_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get all callers of a function
    pub fn get_callers(&self, callee_id: &str) -> Vec<&str> {
        self.reverse_edges
            .get(callee_id)
            .map(|v| v.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Get all entry points (functions not called by others)
    pub fn entry_points(&self) -> impl Iterator<Item = &str> {
        self.entry_points.iter().map(|s| s.as_str())
    }

    /// Get all functions in the graph
    pub fn functions(&self) -> impl Iterator<Item = &CallGraphNode> {
        self.nodes.values()
    }

    /// Get reachable functions from a starting point (BFS)
    pub fn reachable_from(&self, start_id: &str) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut queue = vec![start_id.to_string()];

        while let Some(current) = queue.pop() {
            if visited.insert(current.clone()) {
                if let Some(calls) = self.edges.get(&current) {
                    for call in calls {
                        if !visited.contains(&call.target_id) {
                            queue.push(call.target_id.clone());
                        }
                    }
                }
            }
        }

        visited
    }

    /// Get reverse reachable functions (who can reach this function)
    pub fn reverse_reachable_from(&self, target_id: &str) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut queue = vec![target_id.to_string()];

        while let Some(current) = queue.pop() {
            if visited.insert(current.clone()) {
                if let Some(callers) = self.reverse_edges.get(&current) {
                    for caller in callers {
                        if !visited.contains(caller) {
                            queue.push(caller.clone());
                        }
                    }
                }
            }
        }

        visited
    }

    /// Check if there's a path from source to target
    pub fn has_path(&self, source_id: &str, target_id: &str) -> bool {
        self.reachable_from(source_id).contains(target_id)
    }

    /// Get all strongly connected components (cycles)
    pub fn find_cycles(&self) -> Vec<Vec<String>> {
        // Tarjan's algorithm for SCC
        let mut index_counter = 0;
        let mut stack = Vec::new();
        let mut lowlinks = HashMap::new();
        let mut index_map = HashMap::new();
        let mut on_stack = HashSet::new();
        let mut sccs = Vec::new();

        for node_id in self.nodes.keys() {
            if !index_map.contains_key(node_id) {
                self.strongconnect(
                    node_id,
                    &mut index_counter,
                    &mut stack,
                    &mut lowlinks,
                    &mut index_map,
                    &mut on_stack,
                    &mut sccs,
                );
            }
        }

        // Filter to only cycles (SCCs with more than one node or self-loops)
        sccs.into_iter()
            .filter(|scc| {
                scc.len() > 1
                    || (scc.len() == 1
                        && self
                            .edges
                            .get(&scc[0])
                            .map(|calls| calls.iter().any(|c| c.target_id == scc[0]))
                            .unwrap_or(false))
            })
            .collect()
    }

    fn strongconnect(
        &self,
        v: &str,
        index_counter: &mut usize,
        stack: &mut Vec<String>,
        lowlinks: &mut HashMap<String, usize>,
        index_map: &mut HashMap<String, usize>,
        on_stack: &mut HashSet<String>,
        sccs: &mut Vec<Vec<String>>,
    ) {
        index_map.insert(v.to_string(), *index_counter);
        lowlinks.insert(v.to_string(), *index_counter);
        *index_counter += 1;
        stack.push(v.to_string());
        on_stack.insert(v.to_string());

        if let Some(calls) = self.edges.get(v) {
            for call in calls {
                let w = &call.target_id;
                if !index_map.contains_key(w) {
                    self.strongconnect(
                        w,
                        index_counter,
                        stack,
                        lowlinks,
                        index_map,
                        on_stack,
                        sccs,
                    );
                    let w_lowlink = *lowlinks.get(w).unwrap();
                    let v_lowlink = lowlinks.get_mut(v).unwrap();
                    *v_lowlink = (*v_lowlink).min(w_lowlink);
                } else if on_stack.contains(w) {
                    let w_index = *index_map.get(w).unwrap();
                    let v_lowlink = lowlinks.get_mut(v).unwrap();
                    *v_lowlink = (*v_lowlink).min(w_index);
                }
            }
        }

        if lowlinks.get(v) == index_map.get(v) {
            let mut scc = Vec::new();
            loop {
                let w = stack.pop().unwrap();
                on_stack.remove(&w);
                scc.push(w.clone());
                if w == v {
                    break;
                }
            }
            sccs.push(scc);
        }
    }
}

/// Builder for constructing call graphs from AST
#[derive(Debug)]
pub struct CallGraphBuilder {
    graph: CallGraph,
    // We capture unresolved calls here: File -> Vec<CallSite>
    // but simplifying for this step: direct graph insertion
}

impl CallGraphBuilder {
    pub fn new() -> Self {
        Self {
            graph: CallGraph::new(),
        }
    }

    /// Analyze a source file using Tree-sitter AST
    pub fn analyze_ast(
        &mut self,
        file_path: &str,
        tree: &Tree,
        language: &Language,
        source: &str,
        query_engine: &mut TreeSitterQueryEngine,
    ) {
        let source_bytes = source.as_bytes();
        let (def_query_str, call_query_str) = match language {
            Language::Python => (PYTHON_DEFINITIONS, PYTHON_CALLS),
            Language::JavaScript => (JAVASCRIPT_DEFINITIONS, JAVASCRIPT_CALLS),
            Language::TypeScript => (TYPESCRIPT_DEFINITIONS, TYPESCRIPT_CALLS),
            Language::Rust => (RUST_DEFINITIONS, RUST_CALLS),
            Language::Go => (GO_DEFINITIONS, GO_CALLS),
            Language::C => (C_DEFINITIONS, C_CALLS),
            Language::Cpp => (CPP_DEFINITIONS, CPP_CALLS),
            // Default empty for unsupported langs
            _ => ("", ""),
        };

        if def_query_str.is_empty() {
            return;
        }

        // 1. Find Definitions (The logic here needs to compile queries)
        // We assume query_engine can compile string -> Query
        // Note: In real enterprise code, we pre-compile these once.
        // For now, we rely on the engine's cache.

        // Define struct for collected functions
        struct DefinedFunction {
            id: String,
            start_byte: usize,
            end_byte: usize,
        }

        let mut functions: Vec<DefinedFunction> = Vec::new();

        // Run definition query
        if let Ok(query) = query_engine.compile_query(def_query_str, language) {
            let matches = query_engine.execute_query(&query, tree, source_bytes);
            for m in matches {
                let name_node = m.captures.get("name");
                if let Some(name_n) = name_node {
                    let func_name = &source[name_n.start_byte..name_n.end_byte];

                    // Construct ID (Simplified: File::Name)
                    // In future: proper module resolution
                    let id = format!("{}::{}", file_path, func_name);

                    let start_line = m.start_position.0 as u32 + 1;
                    let end_line = m.end_position.0 as u32 + 1;

                    let sig = FunctionSignature {
                        name: func_name.to_string(),
                        module_path: Some(file_path.to_string()),
                        parameters: Vec::new(), // TODO: Extract params
                        return_type: None,
                    };

                    let node = CallGraphNode {
                        id: id.clone(),
                        signature: sig,
                        file_path: file_path.to_string(),
                        start_line,
                        end_line,
                    };
                    self.graph.add_function(node);

                    functions.push(DefinedFunction {
                        id,
                        start_byte: m.start_byte,
                        end_byte: m.end_byte,
                    });
                }
            }
        }

        // 2. Find Calls
        if let Ok(query) = query_engine.compile_query(call_query_str, language) {
            let matches = query_engine.execute_query(&query, tree, source_bytes);
            for m in matches {
                let name_node = m.captures.get("name");
                if let Some(name_n) = name_node {
                    let callee_name = &source[name_n.start_byte..name_n.end_byte];

                    // Determine Caller by checking which function definition contains this call
                    let caller_id = functions
                        .iter()
                        .find(|f| m.start_byte >= f.start_byte && m.end_byte <= f.end_byte)
                        .map(|f| f.id.clone());

                    if let Some(caller) = caller_id {
                        // Resolve Target (Fuzzy: Look for same function name in same file first)
                        // In Phase 2: We would create an "Unresolved Edge" and link later.
                        // Impl for now: Direct link if local, or create a 'phantom' ID.

                        // NOTE: This logic assumes internal calls for now.
                        let target_id = format!("{}::{}", file_path, callee_name); // Assume local internal call

                        // We also add a cross-file heuristic for the future:
                        // If not found locally, we'd search the graph.
                        // For now, we just add the edges.

                        let call_site = CallSite {
                            target_id,
                            target_name: callee_name.to_string(),
                            line: m.start_position.0 as u32 + 1,
                            column: m.start_position.1 as u32,
                            arguments: Vec::new(),
                        };

                        self.graph.add_call(&caller, call_site);
                    }
                }
            }
        }
    }

    /// Get a reference to the built call graph
    pub fn graph(&self) -> &CallGraph {
        &self.graph
    }

    /// Build and return the call graph
    pub fn build(self) -> CallGraph {
        self.graph
    }
}

impl Default for CallGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(name: &str) -> CallGraphNode {
        CallGraphNode {
            id: name.to_string(),
            signature: FunctionSignature {
                name: name.to_string(),
                module_path: None,
                parameters: vec![],
                return_type: None,
            },
            file_path: "test.py".to_string(),
            start_line: 1,
            end_line: 10,
        }
    }

    fn make_call(target: &str, line: u32) -> CallSite {
        CallSite {
            target_id: target.to_string(),
            target_name: target.to_string(),
            arguments: vec![],
            line,
            column: 0,
        }
    }

    #[test]
    fn test_add_function() {
        let mut graph = CallGraph::new();
        graph.add_function(make_node("main"));

        assert!(graph.get_function("main").is_some());
        assert!(graph.entry_points().collect::<Vec<_>>().contains(&"main"));
    }

    #[test]
    fn test_add_call() {
        let mut graph = CallGraph::new();
        graph.add_function(make_node("main"));
        graph.add_function(make_node("helper"));
        graph.add_call("main", make_call("helper", 5));

        assert_eq!(graph.get_calls("main").len(), 1);
        assert_eq!(graph.get_callers("helper"), vec!["main"]);
        // helper is no longer an entry point
        assert!(!graph.entry_points().collect::<Vec<_>>().contains(&"helper"));
    }

    #[test]
    fn test_reachability() {
        let mut graph = CallGraph::new();
        graph.add_function(make_node("a"));
        graph.add_function(make_node("b"));
        graph.add_function(make_node("c"));
        graph.add_call("a", make_call("b", 1));
        graph.add_call("b", make_call("c", 2));

        let reachable = graph.reachable_from("a");
        assert!(reachable.contains("a"));
        assert!(reachable.contains("b"));
        assert!(reachable.contains("c"));

        assert!(graph.has_path("a", "c"));
        assert!(!graph.has_path("c", "a"));
    }

    #[test]
    fn test_find_cycles() {
        let mut graph = CallGraph::new();
        graph.add_function(make_node("a"));
        graph.add_function(make_node("b"));
        graph.add_function(make_node("c"));
        graph.add_call("a", make_call("b", 1));
        graph.add_call("b", make_call("c", 2));
        graph.add_call("c", make_call("a", 3)); // Creates cycle

        let cycles = graph.find_cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 3);
    }
}
