//! Call Graph Analysis
//!
//! Inter-procedural call graph construction and traversal for SAST analysis.
//! Enables tracking function calls across module boundaries.

use std::collections::{HashMap, HashSet};

use crate::domain::entities::{CallGraphNode, CallSite, FunctionSignature};

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
    /// Current scope stack for resolving function calls
    scope_stack: Vec<String>,
}

impl CallGraphBuilder {
    pub fn new() -> Self {
        Self {
            graph: CallGraph::new(),
            scope_stack: Vec::new(),
        }
    }

    /// Analyze a source file and extract function definitions/calls
    ///
    /// This is a simplified version that scans for function patterns.
    /// A full implementation would use tree-sitter queries for each language.
    pub fn analyze_file(&mut self, file_path: &str, content: &str) {
        // Extract function definitions and calls using simple pattern matching
        // A production implementation would use tree-sitter for accurate AST parsing
        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num as u32 + 1;

            // Simple pattern: detect Python/JS function definitions
            if let Some(func_name) = Self::extract_function_def(line, file_path) {
                let sig = FunctionSignature {
                    name: func_name.clone(),
                    module_path: Some(file_path.to_string()),
                    parameters: Vec::new(),
                    return_type: None,
                };
                let id = sig.fully_qualified_name();
                let node = CallGraphNode {
                    id: id.clone(),
                    signature: sig,
                    file_path: file_path.to_string(),
                    start_line: line_num,
                    end_line: line_num, // Simplified
                };
                self.graph.add_function(node);
                self.scope_stack.push(id);
            }

            // Detect function calls within current scope
            for callee_name in Self::extract_function_calls(line) {
                if let Some(caller_id) = self.scope_stack.last() {
                    let call_site = CallSite {
                        target_id: format!("{}::{}", file_path, callee_name),
                        target_name: callee_name,
                        line: line_num,
                        column: 0,
                        arguments: Vec::new(),
                    };
                    self.graph.add_call(caller_id, call_site);
                }
            }
        }
    }

    /// Extract function definition name from a line (simplified)
    fn extract_function_def(line: &str, _file_path: &str) -> Option<String> {
        let trimmed = line.trim();

        // Python: def function_name(
        if let Some(rest) = trimmed.strip_prefix("def ") {
            if let Some(paren_idx) = rest.find('(') {
                return Some(rest[..paren_idx].trim().to_string());
            }
        }

        // JavaScript/TypeScript: function name( or async function name(
        let rest = trimmed
            .strip_prefix("async ")
            .unwrap_or(trimmed)
            .strip_prefix("function ")
            .or_else(|| {
                // Arrow functions with const/let: const name = (
                trimmed
                    .strip_prefix("const ")
                    .or_else(|| trimmed.strip_prefix("let "))
                    .and_then(|r| {
                        if r.contains("=>") || r.contains("function") {
                            Some(r)
                        } else {
                            None
                        }
                    })
            });

        if let Some(rest) = rest {
            // Get the function name before the parenthesis or =
            let end_idx = rest
                .find('(')
                .or_else(|| rest.find('='))
                .unwrap_or(rest.len());
            let name = rest[..end_idx].trim();
            if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                return Some(name.to_string());
            }
        }

        // Rust: fn name(
        if let Some(rest) = trimmed.strip_prefix("fn ") {
            if let Some(paren_idx) = rest.find('(') {
                let name = rest[..paren_idx].trim();
                // Handle generic parameters
                let name = name.split('<').next().unwrap_or(name);
                return Some(name.to_string());
            }
        }

        // Go: func name( or func (receiver) name(
        if let Some(rest) = trimmed.strip_prefix("func ") {
            // Skip receiver if present
            let rest = if rest.starts_with('(') {
                rest.find(')').map(|i| &rest[i + 1..]).unwrap_or(rest)
            } else {
                rest
            };
            let rest = rest.trim();
            if let Some(paren_idx) = rest.find('(') {
                let name = rest[..paren_idx].trim();
                return Some(name.to_string());
            }
        }

        None
    }

    /// Extract function call names from a line (simplified)
    fn extract_function_calls(line: &str) -> Vec<String> {
        let mut calls = Vec::new();
        let mut chars = line.chars().peekable();
        let mut current_word = String::new();

        while let Some(c) = chars.next() {
            if c.is_alphanumeric() || c == '_' || c == '.' {
                current_word.push(c);
            } else if c == '(' && !current_word.is_empty() {
                // Found a function call
                // Get the last part after any dots (method name)
                let name = current_word.split('.').last().unwrap_or(&current_word);
                if !name.is_empty() && !Self::is_keyword(name) {
                    calls.push(name.to_string());
                }
                current_word.clear();
            } else {
                current_word.clear();
            }
        }

        calls
    }

    /// Check if a word is a language keyword (not a function call)
    fn is_keyword(word: &str) -> bool {
        matches!(
            word,
            "if" | "else"
                | "for"
                | "while"
                | "return"
                | "def"
                | "class"
                | "function"
                | "const"
                | "let"
                | "var"
                | "fn"
                | "impl"
                | "struct"
                | "match"
                | "switch"
                | "case"
                | "try"
                | "catch"
                | "async"
                | "await"
        )
    }

    /// Enter a function scope
    pub fn enter_function(&mut self, signature: FunctionSignature) {
        let id = signature.fully_qualified_name();
        let node = CallGraphNode {
            id: id.clone(),
            signature,
            file_path: String::new(),
            start_line: 0,
            end_line: 0,
        };
        self.graph.add_function(node);
        self.scope_stack.push(id);
    }

    /// Exit the current function scope
    pub fn exit_function(&mut self) {
        self.scope_stack.pop();
    }

    /// Record a function call at current scope
    pub fn record_call(&mut self, call_site: CallSite) {
        if let Some(caller_id) = self.scope_stack.last() {
            self.graph.add_call(caller_id, call_site);
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
