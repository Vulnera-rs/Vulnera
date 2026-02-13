//! Call Graph Analysis
//!
//! Inter-procedural call graph construction and traversal for SAST analysis.
//! Enables tracking function calls across module boundaries.

use std::collections::{HashMap, HashSet, VecDeque};
use tree_sitter::Tree;

use crate::domain::call_graph::{CallGraphNode, CallSite, FunctionSignature, ParameterInfo};
use crate::domain::taint_types::FunctionTaintSummary;
use crate::domain::value_objects::Language;
use crate::infrastructure::call_graph_queries::*;

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
    /// Index: function_name (without path) -> list of fully qualified IDs
    name_index: HashMap<String, Vec<String>>,
    /// Unresolved calls pending cross-file resolution
    unresolved_calls: Vec<UnresolvedCall>,
    /// Function taint summaries for inter-procedural analysis
    function_summaries: HashMap<String, FunctionTaintSummary>,
}

/// Unresolved call site pending cross-file resolution
#[derive(Debug, Clone)]
pub struct UnresolvedCall {
    /// Caller function ID
    pub caller_id: String,
    /// Called function name (without module path)
    pub callee_name: String,
    /// Optional module hint (e.g., from import statement)
    pub module_hint: Option<String>,
    /// Caller file path, used for locality-aware disambiguation.
    pub caller_file_path: String,
    /// Optional caller scope/class name (for method disambiguation).
    pub caller_scope: Option<String>,
    /// Call location
    pub line: u32,
    pub column: u32,
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

    #[allow(clippy::too_many_arguments)]
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

    // =========================================================================
    // Symbol Resolution & Cross-File Linking
    // =========================================================================

    /// Build the name index for fast function lookup by name
    pub fn build_name_index(&mut self) {
        self.name_index.clear();
        for (id, node) in &self.nodes {
            self.name_index
                .entry(node.signature.name.clone())
                .or_default()
                .push(id.clone());
        }
    }

    /// Add an unresolved call for later resolution
    pub fn add_unresolved_call(&mut self, call: UnresolvedCall) {
        self.unresolved_calls.push(call);
    }

    /// Resolve all pending cross-file calls
    /// Returns the number of calls successfully resolved
    pub fn resolve_all_calls(&mut self) -> usize {
        // Ensure name index is built
        if self.name_index.is_empty() {
            self.build_name_index();
        }

        let mut resolved_count = 0;
        let unresolved = std::mem::take(&mut self.unresolved_calls);

        for call in unresolved {
            if let Some(target_id) = self.resolve_call(&call) {
                let call_site = CallSite {
                    target_id: target_id.clone(),
                    target_name: call.callee_name.clone(),
                    line: call.line,
                    column: call.column,
                    arguments: Vec::new(),
                };
                self.add_call(&call.caller_id, call_site);
                resolved_count += 1;
            }
            // Unresolved calls are dropped (could log or store for reporting)
        }

        resolved_count
    }

    /// Try to resolve a single call to its target function ID
    fn resolve_call(&self, call: &UnresolvedCall) -> Option<String> {
        if let Some(candidates) = self.name_index.get(&call.callee_name) {
            if candidates.len() == 1 {
                return Some(candidates[0].clone());
            }

            let mut ranked: Vec<(&String, i32)> = candidates
                .iter()
                .filter_map(|candidate| {
                    let node = self.nodes.get(candidate)?;
                    Some((candidate, Self::score_candidate(call, node)))
                })
                .collect();

            ranked.sort_by(|(lhs_id, lhs_score), (rhs_id, rhs_score)| {
                rhs_score
                    .cmp(lhs_score)
                    .then_with(|| lhs_id.cmp(rhs_id))
            });

            if let Some((best_id, _)) = ranked.first() {
                return Some((*best_id).clone());
            }
        }

        None
    }

    fn score_candidate(call: &UnresolvedCall, node: &CallGraphNode) -> i32 {
        let mut score = 0;

        if node.file_path == call.caller_file_path {
            score += 120;
        }

        if let Some(caller_dir) = std::path::Path::new(&call.caller_file_path).parent() {
            if node.file_path.starts_with(caller_dir.to_string_lossy().as_ref()) {
                score += 70;
            }
        }

        if let Some(ref hint) = call.module_hint {
            if !hint.is_empty()
                && (node.file_path.contains(hint)
                    || std::path::Path::new(&node.file_path)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .map(|stem| stem == hint)
                        .unwrap_or(false))
            {
                score += 90;
            }
        }

        if let Some(ref scope) = call.caller_scope {
            if node.id.contains(&format!("::{}::", scope)) {
                score += 100;
            }
        }

        score + Self::path_similarity_bonus(&call.caller_file_path, &node.file_path)
    }

    fn path_similarity_bonus(lhs: &str, rhs: &str) -> i32 {
        let lhs_components = lhs.split('/').collect::<Vec<_>>();
        let rhs_components = rhs.split('/').collect::<Vec<_>>();
        let common_prefix = lhs_components
            .iter()
            .zip(rhs_components.iter())
            .take_while(|(l, r)| l == r)
            .count() as i32;

        common_prefix * 3
    }

    // =========================================================================
    // Topological Sort for Analysis Order
    // =========================================================================

    /// Get functions in topological order (callees before callers)
    /// This ensures we analyze leaf functions first, then their callers
    pub fn topological_order(&self) -> Vec<String> {
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        let mut result = Vec::new();
        let mut queue = VecDeque::new();

        // Initialize in-degrees
        for id in self.nodes.keys() {
            in_degree.insert(id.clone(), 0);
        }

        // Count incoming edges (how many functions call this one)
        for callers in self.reverse_edges.values() {
            for caller in callers {
                if let Some(degree) = in_degree.get_mut(caller) {
                    *degree += 1;
                }
            }
        }

        // Start with leaf functions (no outgoing calls, or calls to external functions)
        for (id, degree) in &in_degree {
            if *degree == 0 {
                queue.push_back(id.clone());
            }
        }

        // BFS/Kahn's algorithm
        while let Some(current) = queue.pop_front() {
            result.push(current.clone());

            // For each function that calls current, reduce its in-degree
            if let Some(callers) = self.reverse_edges.get(&current) {
                for caller in callers {
                    if let Some(degree) = in_degree.get_mut(caller) {
                        *degree -= 1;
                        if *degree == 0 {
                            queue.push_back(caller.clone());
                        }
                    }
                }
            }
        }

        result
    }

    // =========================================================================
    // Function Summaries
    // =========================================================================

    /// Set the taint summary for a function
    pub fn set_function_summary(&mut self, function_id: &str, summary: FunctionTaintSummary) {
        self.function_summaries
            .insert(function_id.to_string(), summary);
    }

    /// Get the taint summary for a function
    pub fn get_function_summary(&self, function_id: &str) -> Option<&FunctionTaintSummary> {
        self.function_summaries.get(function_id)
    }

    /// Check if a function propagates taint from any parameter to return
    pub fn propagates_taint(&self, function_id: &str) -> bool {
        self.function_summaries
            .get(function_id)
            .map(|s| !s.params_to_return.is_empty() || s.return_tainted)
            .unwrap_or(false)
    }

    /// Extract file-level dependency map from cross-file call edges.
    ///
    /// Returns a map where each key is a file path and the value is the set of
    /// other files it depends on (files containing functions it calls).
    /// Only cross-file edges are included (self-dependencies are excluded).
    pub fn file_dependencies(&self) -> HashMap<String, HashSet<String>> {
        let mut deps: HashMap<String, HashSet<String>> = HashMap::new();

        for (caller_id, call_sites) in &self.edges {
            let caller_file = match self.nodes.get(caller_id) {
                Some(node) => &node.file_path,
                None => continue,
            };

            for call_site in call_sites {
                let callee_file = match self.nodes.get(&call_site.target_id) {
                    Some(node) => &node.file_path,
                    None => continue,
                };

                // Only track cross-file dependencies
                if caller_file != callee_file {
                    deps.entry(caller_file.clone())
                        .or_default()
                        .insert(callee_file.clone());
                }
            }
        }

        deps
    }

    /// Get statistics about the call graph
    pub fn stats(&self) -> CallGraphStats {
        let total_edges: usize = self.edges.values().map(|v| v.len()).sum();
        CallGraphStats {
            total_functions: self.nodes.len(),
            total_calls: total_edges,
            entry_points: self.entry_points.len(),
            resolved_summaries: self.function_summaries.len(),
        }
    }
}

/// Statistics about the call graph
#[derive(Debug, Clone)]
pub struct CallGraphStats {
    pub total_functions: usize,
    pub total_calls: usize,
    pub entry_points: usize,
    pub resolved_summaries: usize,
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
    pub fn analyze_ast(&mut self, file_path: &str, tree: &Tree, language: &Language, source: &str) {
        let source_bytes = source.as_bytes();

        // Get query strings for this language
        let (def_query_str, call_query_str, param_query_str, class_query_str) = match language {
            Language::Python => (
                PYTHON_DEFINITIONS,
                PYTHON_CALLS,
                Some(PYTHON_PARAMETERS),
                Some(PYTHON_CLASS_METHODS),
            ),
            Language::JavaScript => (
                JAVASCRIPT_DEFINITIONS,
                JAVASCRIPT_CALLS,
                Some(JAVASCRIPT_PARAMETERS),
                Some(JAVASCRIPT_CLASS_METHODS),
            ),
            Language::TypeScript => (
                TYPESCRIPT_DEFINITIONS,
                TYPESCRIPT_CALLS,
                Some(TYPESCRIPT_PARAMETERS),
                Some(TYPESCRIPT_CLASS_METHODS),
            ),
            Language::Rust => (
                RUST_DEFINITIONS,
                RUST_CALLS,
                Some(RUST_PARAMETERS),
                Some(RUST_IMPL_METHODS),
            ),
            Language::Go => (
                GO_DEFINITIONS,
                GO_CALLS,
                Some(GO_PARAMETERS),
                Some(GO_STRUCT_METHODS),
            ),
            Language::C => (
                C_DEFINITIONS,
                C_CALLS,
                Some(C_PARAMETERS),
                None, // C doesn't have classes
            ),
            Language::Cpp => (
                CPP_DEFINITIONS,
                CPP_CALLS,
                Some(CPP_PARAMETERS),
                Some(CPP_CLASS_METHODS),
            ),
        };

        // Check if queries are empty (unsupported language configuration)
        if def_query_str.is_empty() {
            return;
        }

        // Define struct for collected classes/structs with byte ranges
        struct ClassContext {
            name: String,
            start_byte: usize,
            end_byte: usize,
        }

        // 1. Extract class/struct contexts first
        let mut class_contexts: Vec<ClassContext> = Vec::new();
        if let Some(class_query) = class_query_str {
            if let Ok(query) =
                crate::infrastructure::query_engine::compile_query(class_query, language)
            {
                let matches =
                    crate::infrastructure::query_engine::execute_query(&query, tree, source_bytes);
                for m in matches {
                    // Look for class.name, type.name, or struct.name depending on language
                    let class_name = m
                        .captures
                        .get("class.name")
                        .or_else(|| m.captures.get("type.name"))
                        .or_else(|| m.captures.get("struct.name"));

                    if let Some(name_node) = class_name {
                        let name = source[name_node.start_byte..name_node.end_byte].to_string();
                        class_contexts.push(ClassContext {
                            name,
                            start_byte: m.start_byte,
                            end_byte: m.end_byte,
                        });
                    }
                }
            }
        }

        // 2. Extract parameters for functions (build a map: func_name -> params)
        let mut function_params: HashMap<String, Vec<ParameterInfo>> = HashMap::new();
        if let Some(param_query) = param_query_str {
            if let Ok(query) =
                crate::infrastructure::query_engine::compile_query(param_query, language)
            {
                let matches =
                    crate::infrastructure::query_engine::execute_query(&query, tree, source_bytes);
                for m in matches {
                    let name_node = m.captures.get("name");
                    let param_node = m.captures.get("param.name");
                    let type_node = m.captures.get("param.type");

                    if let (Some(name_n), Some(param_n)) = (name_node, param_node) {
                        let func_name = source[name_n.start_byte..name_n.end_byte].to_string();
                        let param_name = source[param_n.start_byte..param_n.end_byte].to_string();

                        // Extract type if available
                        let type_hint =
                            type_node.map(|t| source[t.start_byte..t.end_byte].to_string());

                        let param_info = ParameterInfo {
                            name: param_name,
                            type_hint,
                            default_value: None, // Default values not extracted currently
                        };

                        function_params
                            .entry(func_name)
                            .or_default()
                            .push(param_info);
                    }
                }
            }
        }

        // Define struct for collected functions
        struct DefinedFunction {
            id: String,
            start_byte: usize,
            end_byte: usize,
        }

        let mut functions: Vec<DefinedFunction> = Vec::new();

        // 3. Find Definitions and build qualified IDs
        if let Ok(query) =
            crate::infrastructure::query_engine::compile_query(def_query_str, language)
        {
            let matches =
                crate::infrastructure::query_engine::execute_query(&query, tree, source_bytes);
            for m in matches {
                let name_node = m.captures.get("name");
                if let Some(name_n) = name_node {
                    let func_name = &source[name_n.start_byte..name_n.end_byte];

                    // Check if this function is inside a class/struct
                    let containing_class = class_contexts
                        .iter()
                        .find(|ctx| m.start_byte >= ctx.start_byte && m.end_byte <= ctx.end_byte);

                    // Build qualified ID: file::Class::method or file::function
                    let id = if let Some(class_ctx) = containing_class {
                        format!("{}::{}::{}", file_path, class_ctx.name, func_name)
                    } else {
                        format!("{}::{}", file_path, func_name)
                    };

                    let start_line = m.start_position.0 as u32 + 1;
                    let end_line = m.end_position.0 as u32 + 1;

                    // Get parameters for this function
                    let params = function_params.get(func_name).cloned().unwrap_or_default();

                    let sig = FunctionSignature {
                        name: func_name.to_string(),
                        module_path: Some(file_path.to_string()),
                        parameters: params,
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
        // Build a set of local function names for quick lookup
        let local_function_names: HashSet<&str> = functions
            .iter()
            .filter_map(|f| {
                // Extract just the function name from the ID (after "::")
                f.id.split("::").last()
            })
            .collect();

        if let Ok(query) =
            crate::infrastructure::query_engine::compile_query(call_query_str, language)
        {
            let matches =
                crate::infrastructure::query_engine::execute_query(&query, tree, source_bytes);
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
                        let caller_scope = caller
                            .rsplit("::")
                            .nth(1)
                            .filter(|segment| *segment != file_path)
                            .map(|segment| segment.to_string());

                        // Check if this is a local function call
                        if local_function_names.contains(callee_name) {
                            // Local call - create direct edge; prefer class-scoped method if present.
                            let class_scoped_target = caller_scope
                                .as_ref()
                                .map(|scope| format!("{}::{}::{}", file_path, scope, callee_name));
                            let target_id = class_scoped_target
                                .filter(|candidate| self.graph.get_function(candidate).is_some())
                                .unwrap_or_else(|| format!("{}::{}", file_path, callee_name));

                            let call_site = CallSite {
                                target_id,
                                target_name: callee_name.to_string(),
                                line: m.start_position.0 as u32 + 1,
                                column: m.start_position.1 as u32,
                                arguments: Vec::new(),
                            };
                            self.graph.add_call(&caller, call_site);
                        } else {
                            // Cross-file or external call - add as unresolved
                            // Extract module hint from method call pattern (e.g., "module.function")
                            let module_hint = m.captures.get("obj").map(|obj_node| {
                                source[obj_node.start_byte..obj_node.end_byte].to_string()
                            });

                            let unresolved = UnresolvedCall {
                                caller_id: caller.clone(),
                                callee_name: callee_name.to_string(),
                                module_hint,
                                caller_file_path: file_path.to_string(),
                                caller_scope,
                                line: m.start_position.0 as u32 + 1,
                                column: m.start_position.1 as u32,
                            };
                            self.graph.add_unresolved_call(unresolved);
                        }
                    }
                }
            }
        }
    }

    /// Get a reference to the built call graph
    pub fn graph(&self) -> &CallGraph {
        &self.graph
    }

    /// Get a mutable reference to the call graph
    pub fn graph_mut(&mut self) -> &mut CallGraph {
        &mut self.graph
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
