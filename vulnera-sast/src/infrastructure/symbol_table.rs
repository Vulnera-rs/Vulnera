//! Symbol Table for SAST Analysis
//!
//! Provides scope-aware symbol resolution for improved taint analysis accuracy.
//! Enables proper tracking of variables with the same name in different scopes
//! and handles variable reassignments correctly.

use std::collections::HashMap;
use tree_sitter::Node;

use crate::domain::finding::{Location, TaintState};
use crate::domain::value_objects::Language;

/// Kind of symbol in the program
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// Variable or constant binding
    Variable,
    /// Function definition
    Function,
    /// Function parameter
    Parameter,
    /// Class or type definition
    Class,
    /// Imported module or symbol
    Import,
    /// File/module scope
    Module,
    /// Type alias (e.g., type MyInt = int)
    TypeAlias,
}

/// Type information for symbols
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeInfo {
    /// Primitive types: int, str, bool, etc.
    Primitive(String),
    /// List/Array type: list[T]
    List(Box<TypeInfo>),
    /// Dictionary/Map type: dict[K, V]
    Dict(Box<TypeInfo>, Box<TypeInfo>),
    /// Object/Class instance
    Object(String),
    /// Function type with params and return
    Function {
        params: Vec<TypeInfo>,
        return_type: Box<TypeInfo>,
    },
    /// Union type: Union[T1, T2] or T1 | T2
    Union(Vec<TypeInfo>),
    /// Optional/Nullable type: Optional[T] or T | None
    Optional(Box<TypeInfo>),
    /// Unknown type (needs inference)
    Unknown,
}

/// A symbol in the symbol table
#[derive(Debug, Clone)]
pub struct Symbol {
    /// Symbol name/identifier
    pub name: String,
    /// Kind of symbol
    pub kind: SymbolKind,
    /// Scope ID where this symbol is defined
    pub scope_id: usize,
    /// Location where symbol is defined
    pub defined_at: Location,
    /// Locations where symbol is referenced
    pub used_at: Vec<Location>,
    /// Type information (if known)
    pub type_info: Option<TypeInfo>,
    /// Current taint state (if tainted)
    pub taint_state: Option<TaintState>,
    /// Whether this symbol is mutable
    pub is_mutable: bool,
}

impl Symbol {
    /// Create a new symbol
    pub fn new(
        name: impl Into<String>,
        kind: SymbolKind,
        scope_id: usize,
        defined_at: Location,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            scope_id,
            defined_at,
            used_at: Vec::new(),
            type_info: None,
            taint_state: None,
            is_mutable: true, // Default to mutable for Python/JS
        }
    }

    /// Set type information
    pub fn with_type(mut self, type_info: TypeInfo) -> Self {
        self.type_info = Some(type_info);
        self
    }

    /// Set mutability
    pub fn with_mutable(mut self, is_mutable: bool) -> Self {
        self.is_mutable = is_mutable;
        self
    }

    /// Record a use of this symbol
    pub fn record_use(&mut self, location: Location) {
        self.used_at.push(location);
    }

    /// Check if symbol is currently tainted
    pub fn is_tainted(&self) -> bool {
        self.taint_state.is_some()
    }

    /// Get taint state reference
    pub fn taint_state(&self) -> Option<&TaintState> {
        self.taint_state.as_ref()
    }

    /// Update taint state
    pub fn set_taint(&mut self, taint: TaintState) {
        self.taint_state = Some(taint);
    }

    /// Clear taint (sanitization)
    pub fn clear_taint(&mut self) {
        self.taint_state = None;
    }
}

/// Kind of scope in the program
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScopeKind {
    /// Global/file scope
    Global,
    /// Function scope
    Function,
    /// Class scope
    Class,
    /// Block scope (if/else, try/catch, etc.)
    Block,
    /// Loop scope (for/while)
    Loop,
    /// Module scope (for imports)
    Module,
    /// Closure/capture scope
    Closure,
}

/// A scope in the program
#[derive(Debug, Clone)]
pub struct Scope {
    /// Unique scope ID
    pub id: usize,
    /// Parent scope ID (None for global)
    pub parent: Option<usize>,
    /// Symbols defined in this scope
    pub symbols: HashMap<String, Symbol>,
    /// Kind of scope
    pub kind: ScopeKind,
}

impl Scope {
    /// Create a new scope
    pub fn new(id: usize, parent: Option<usize>, kind: ScopeKind) -> Self {
        Self {
            id,
            parent,
            symbols: HashMap::new(),
            kind,
        }
    }

    /// Declare a symbol in this scope
    pub fn declare(&mut self, symbol: Symbol) -> Result<(), SymbolError> {
        if self.symbols.contains_key(&symbol.name) {
            return Err(SymbolError::DuplicateName {
                name: symbol.name.clone(),
                scope_id: self.id,
            });
        }
        self.symbols.insert(symbol.name.clone(), symbol);
        Ok(())
    }

    /// Look up a symbol by name (local only)
    pub fn resolve(&self, name: &str) -> Option<&Symbol> {
        self.symbols.get(name)
    }

    /// Look up a symbol mutably
    pub fn resolve_mut(&mut self, name: &str) -> Option<&mut Symbol> {
        self.symbols.get_mut(name)
    }

    /// Get all symbols in this scope
    pub fn all_symbols(&self) -> Vec<&Symbol> {
        self.symbols.values().collect()
    }

    /// Check if scope contains a symbol
    pub fn contains(&self, name: &str) -> bool {
        self.symbols.contains_key(name)
    }
}

/// Errors that can occur in symbol table operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolError {
    /// Duplicate symbol name in scope
    DuplicateName { name: String, scope_id: usize },
    /// Scope not found
    ScopeNotFound { scope_id: usize },
    /// Cannot exit global scope
    CannotExitGlobal,
}

impl std::fmt::Display for SymbolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SymbolError::DuplicateName { name, scope_id } => {
                write!(f, "Duplicate symbol '{}' in scope {}", name, scope_id)
            }
            SymbolError::ScopeNotFound { scope_id } => {
                write!(f, "Scope {} not found", scope_id)
            }
            SymbolError::CannotExitGlobal => {
                write!(f, "Cannot exit global scope")
            }
        }
    }
}

impl std::error::Error for SymbolError {}

/// Symbol table with scope hierarchy
#[derive(Debug, Clone)]
pub struct SymbolTable {
    /// All scopes in the program
    scopes: Vec<Scope>,
    /// Current scope being analyzed
    current_scope: usize,
    /// Next scope ID to assign
    next_scope_id: usize,
}

impl SymbolTable {
    /// Create a new symbol table with global scope
    pub fn new() -> Self {
        let global_scope = Scope::new(0, None, ScopeKind::Global);

        Self {
            scopes: vec![global_scope],
            current_scope: 0,
            next_scope_id: 1,
        }
    }

    /// Enter a new scope
    pub fn enter_scope(&mut self, kind: ScopeKind) -> usize {
        let scope_id = self.next_scope_id;
        self.next_scope_id += 1;

        let scope = Scope::new(scope_id, Some(self.current_scope), kind);
        self.scopes.push(scope);
        self.current_scope = scope_id;

        scope_id
    }

    /// Exit current scope and return to parent
    pub fn exit_scope(&mut self) -> Result<(), SymbolError> {
        let current = self
            .scopes
            .get(self.current_scope)
            .ok_or(SymbolError::ScopeNotFound {
                scope_id: self.current_scope,
            })?;

        if let Some(parent_id) = current.parent {
            self.current_scope = parent_id;
            Ok(())
        } else {
            Err(SymbolError::CannotExitGlobal)
        }
    }

    /// Get current scope ID
    pub fn current_scope_id(&self) -> usize {
        self.current_scope
    }

    /// Get current scope kind
    pub fn current_scope_kind(&self) -> Option<ScopeKind> {
        self.scopes
            .get(self.current_scope)
            .map(|s| s.kind)
    }

    /// Get a scope by ID
    pub fn get_scope(&self, scope_id: usize) -> Option<&Scope> {
        self.scopes.get(scope_id)
    }

    /// Get a scope mutably
    pub fn get_scope_mut(&mut self, scope_id: usize) -> Option<&mut Scope> {
        self.scopes.get_mut(scope_id)
    }

    /// Declare a symbol in the current scope
    pub fn declare(&mut self, symbol: Symbol) -> Result<(), SymbolError> {
        let scope = self
            .scopes
            .get_mut(self.current_scope)
            .ok_or(SymbolError::ScopeNotFound {
                scope_id: self.current_scope,
            })?;
        scope.declare(symbol)
    }

    /// Declare a symbol in a specific scope
    pub fn declare_in_scope(
        &mut self,
        scope_id: usize,
        symbol: Symbol,
    ) -> Result<(), SymbolError> {
        let scope = self
            .scopes
            .get_mut(scope_id)
            .ok_or(SymbolError::ScopeNotFound { scope_id })?;
        scope.declare(symbol)
    }

    /// Resolve a symbol by walking up the scope chain (lexical scoping)
    pub fn resolve(&self, name: &str) -> Option<&Symbol> {
        let mut current = Some(self.current_scope);

        while let Some(scope_id) = current {
            if let Some(scope) = self.scopes.get(scope_id) {
                if let Some(symbol) = scope.resolve(name) {
                    return Some(symbol);
                }
                current = scope.parent;
            } else {
                break;
            }
        }

        None
    }

    /// Resolve a symbol in a specific scope only
    pub fn resolve_in_scope(&self, scope_id: usize, name: &str) -> Option<&Symbol> {
        self.scopes.get(scope_id)?.resolve(name)
    }

    /// Resolve a symbol mutably (for updating taint state)
    pub fn resolve_mut(&mut self, name: &str) -> Option<&mut Symbol> {
        // First find which scope contains the symbol
        let target_scope = self.find_symbol_scope(name)?;
        self.scopes.get_mut(target_scope)?.resolve_mut(name)
    }

    /// Find which scope contains a symbol
    fn find_symbol_scope(&self, name: &str) -> Option<usize> {
        let mut current = Some(self.current_scope);

        while let Some(scope_id) = current {
            if let Some(scope) = self.scopes.get(scope_id) {
                if scope.contains(name) {
                    return Some(scope_id);
                }
                current = scope.parent;
            } else {
                break;
            }
        }

        None
    }

    /// Update taint state for a resolved symbol
    pub fn update_taint(&mut self, name: &str, taint: TaintState) -> bool {
        if let Some(symbol) = self.resolve_mut(name) {
            symbol.set_taint(taint);
            true
        } else {
            false
        }
    }

    /// Clear taint for a symbol (sanitization)
    pub fn clear_taint(&mut self, name: &str) -> bool {
        if let Some(symbol) = self.resolve_mut(name) {
            symbol.clear_taint();
            true
        } else {
            false
        }
    }

    /// Check if a resolved symbol is tainted
    pub fn is_tainted(&self, name: &str) -> bool {
        self.resolve(name)
            .map(|s| s.is_tainted())
            .unwrap_or(false)
    }

    /// Get taint state for a resolved symbol
    pub fn get_taint(&self, name: &str) -> Option<&TaintState> {
        self.resolve(name)?.taint_state()
    }

    /// Get all tainted symbols in current scope and ancestors
    pub fn get_all_tainted(&self) -> Vec<(&str, &TaintState)> {
        let mut result = Vec::new();
        let mut current = Some(self.current_scope);

        while let Some(scope_id) = current {
            if let Some(scope) = self.scopes.get(scope_id) {
                for (name, symbol) in &scope.symbols {
                    if let Some(taint) = symbol.taint_state() {
                        result.push((name.as_str(), taint));
                    }
                }
                current = scope.parent;
            } else {
                break;
            }
        }

        result
    }

    /// Get all symbols in a specific scope
    pub fn symbols_in_scope(&self, scope_id: usize) -> Vec<&Symbol> {
        self.scopes
            .get(scope_id)
            .map(|s| s.all_symbols())
            .unwrap_or_default()
    }

    /// Record a use of a symbol at a location
    pub fn record_use(&mut self, name: &str, location: Location) {
        if let Some(scope_id) = self.find_symbol_scope(name) {
            if let Some(scope) = self.scopes.get_mut(scope_id) {
                if let Some(symbol) = scope.resolve_mut(name) {
                    symbol.record_use(location);
                }
            }
        }
    }

    /// Get all unused symbols in a scope (for diagnostics)
    pub fn get_unused_symbols(&self, scope_id: usize) -> Vec<&Symbol> {
        self.symbols_in_scope(scope_id)
            .into_iter()
            .filter(|s| s.used_at.is_empty())
            .collect()
    }

    /// Check if a name would shadow an outer scope symbol
    pub fn would_shadow(&self, name: &str) -> bool {
        let mut current = self
            .scopes
            .get(self.current_scope)
            .and_then(|s| s.parent);

        while let Some(scope_id) = current {
            if let Some(scope) = self.scopes.get(scope_id) {
                if scope.contains(name) {
                    return true;
                }
                current = scope.parent;
            } else {
                break;
            }
        }

        false
    }

    /// Get all scopes
    pub fn all_scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// Get the global scope ID (always 0)
    pub fn global_scope_id(&self) -> usize {
        0
    }
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing symbol table from AST
pub struct SymbolTableBuilder<'a> {
    table: SymbolTable,
    source: &'a str,
    language: Language,
    file_path: String,
}

impl<'a> SymbolTableBuilder<'a> {
    /// Create a new builder
    pub fn new(source: &'a str, language: Language, file_path: impl Into<String>) -> Self {
        Self {
            table: SymbolTable::new(),
            source,
            language,
            file_path: file_path.into(),
        }
    }

    /// Build symbol table from tree-sitter AST
    pub fn build_from_ast(mut self, root: Node) -> SymbolTable {
        self.visit_node(root);
        self.table
    }

    /// Visit a node and its children
    fn visit_node(&mut self, node: Node) {
        match self.language {
            Language::Python => self.visit_python_node(node),
            Language::JavaScript | Language::TypeScript => self.visit_js_node(node),
            Language::Rust => self.visit_rust_node(node),
            Language::Go => self.visit_go_node(node),
            _ => self.visit_generic_node(node),
        }
    }

    /// Visit Python-specific nodes
    fn visit_python_node(&mut self, node: Node) {
        match node.kind() {
            // Function definition
            "function_definition" => {
                self.handle_python_function(node);
            }
            // Class definition
            "class_definition" => {
                self.handle_python_class(node);
            }
            // Assignment
            "assignment" | "augmented_assignment" => {
                self.handle_python_assignment(node);
            }
            // For loop (creates new scope)
            "for_statement" => {
                self.handle_python_for_loop(node);
            }
            // While loop
            "while_statement" => {
                self.handle_python_while_loop(node);
            }
            // If/else (block scope)
            "if_statement" => {
                self.handle_python_if(node);
            }
            // Try/except
            "try_statement" => {
                self.handle_python_try(node);
            }
            // Import statements
            "import_statement" | "import_from_statement" => {
                self.handle_python_import(node);
            }
            // Lambda (creates function scope)
            "lambda" => {
                self.handle_python_lambda(node);
            }
            // Default: visit children
            _ => {
                self.visit_children(node);
            }
        }
    }

    fn handle_python_function(&mut self, node: Node) {
        // Extract function name and declare in current scope
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = self.node_text(name_node);
            let location = self.node_location(name_node);

            let symbol = Symbol::new(name.clone(), SymbolKind::Function, self.table.current_scope_id(), location)
                .with_type(TypeInfo::Function {
                    params: Vec::new(), // Will be populated from parameters
                    return_type: Box::new(TypeInfo::Unknown),
                })
                .with_mutable(false);

            let _ = self.table.declare(symbol);

            // Enter function scope
            self.table.enter_scope(ScopeKind::Function);

            // Handle parameters in function scope
            if let Some(params) = node.child_by_field_name("parameters") {
                self.handle_python_parameters(params);
            }

            // Visit function body
            if let Some(body) = node.child_by_field_name("body") {
                self.visit_node(body);
            }

            // Exit function scope
            let _ = self.table.exit_scope();
        } else {
            // Anonymous function - just enter scope and visit
            self.table.enter_scope(ScopeKind::Function);
            if let Some(params) = node.child_by_field_name("parameters") {
                self.handle_python_parameters(params);
            }
            if let Some(body) = node.child_by_field_name("body") {
                self.visit_node(body);
            }
            let _ = self.table.exit_scope();
        }
    }

    fn handle_python_class(&mut self, node: Node) {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = self.node_text(name_node);
            let location = self.node_location(name_node);

            let symbol = Symbol::new(name.clone(), SymbolKind::Class, self.table.current_scope_id(), location)
                .with_type(TypeInfo::Object(name))
                .with_mutable(false);

            let _ = self.table.declare(symbol);

            // Enter class scope
            self.table.enter_scope(ScopeKind::Class);

            // Visit class body
            if let Some(body) = node.child_by_field_name("body") {
                self.visit_node(body);
            }

            let _ = self.table.exit_scope();
        }
    }

    fn handle_python_parameters(&mut self, params_node: Node) {
        let mut cursor = params_node.walk();

        for child in params_node.children(&mut cursor) {
            match child.kind() {
                "identifier" => {
                    let name = self.node_text(child);
                    let location = self.node_location(child);

                    let symbol = Symbol::new(name, SymbolKind::Parameter, self.table.current_scope_id(), location);

                    let _ = self.table.declare(symbol);
                }
                "typed_parameter" | "default_parameter" | "keyword_separator" => {
                    // These have an identifier child
                    if let Some(ident) = child.child_by_field_name("name") {
                        let name = self.node_text(ident);
                        let location = self.node_location(ident);

                        let symbol = Symbol::new(name, SymbolKind::Parameter, self.table.current_scope_id(), location);

                        let _ = self.table.declare(symbol);
                    }
                }
                _ => {}
            }
        }
    }

    fn handle_python_assignment(&mut self, node: Node) {
        if let Some(left) = node.child_by_field_name("left") {
            self.declare_python_variables(left);
        }

        // Visit the rest of the assignment
        self.visit_children(node);
    }

    fn declare_python_variables(&mut self, node: Node) {
        match node.kind() {
            "identifier" => {
                let name = self.node_text(node);
                let location = self.node_location(node);

                let symbol = Symbol::new(name, SymbolKind::Variable, self.table.current_scope_id(), location);

                let _ = self.table.declare(symbol);
            }
            "pattern_list" | "tuple_pattern" => {
                // Unpacking: a, b = ...
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.declare_python_variables(child);
                }
            }
            _ => {}
        }
    }

    fn handle_python_for_loop(&mut self, node: Node) {
        self.table.enter_scope(ScopeKind::Loop);

        // Declare loop variable(s)
        if let Some(left) = node.child_by_field_name("left") {
            self.declare_python_variables(left);
        }

        // Visit the iterable expression
        if let Some(right) = node.child_by_field_name("right") {
            self.visit_node(right);
        }

        // Visit body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        // Visit else clause if present
        if let Some(alternative) = node.child_by_field_name("alternative") {
            self.visit_node(alternative);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_python_while_loop(&mut self, node: Node) {
        self.table.enter_scope(ScopeKind::Loop);

        // Visit condition
        if let Some(condition) = node.child_by_field_name("condition") {
            self.visit_node(condition);
        }

        // Visit body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        // Visit else clause if present
        if let Some(alternative) = node.child_by_field_name("alternative") {
            self.visit_node(alternative);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_python_if(&mut self, node: Node) {
        // Python doesn't create block scope for if statements
        // But we enter a block scope for better analysis
        self.table.enter_scope(ScopeKind::Block);

        // Visit condition
        if let Some(condition) = node.child_by_field_name("condition") {
            self.visit_node(condition);
        }

        // Visit consequence
        if let Some(consequence) = node.child_by_field_name("consequence") {
            self.visit_node(consequence);
        }

        let _ = self.table.exit_scope();

        // Visit alternative (elif/else)
        if let Some(alternative) = node.child_by_field_name("alternative") {
            self.visit_node(alternative);
        }
    }

    fn handle_python_try(&mut self, node: Node) {
        // Try block
        self.table.enter_scope(ScopeKind::Block);
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }
        let _ = self.table.exit_scope();

        // Except handlers - each creates its own scope
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "except_clause" || child.kind() == "except_group_clause" {
                self.table.enter_scope(ScopeKind::Block);

                // Declare exception variable if present
                if let Some(name) = child.child_by_field_name("name") {
                    self.declare_python_variables(name);
                }

                if let Some(body) = child.child_by_field_name("body") {
                    self.visit_node(body);
                }

                let _ = self.table.exit_scope();
            }
        }

        // Else block
        if let Some(else_clause) = node.child_by_field_name("else_clause") {
            self.table.enter_scope(ScopeKind::Block);
            self.visit_node(else_clause);
            let _ = self.table.exit_scope();
        }

        // Finally block
        if let Some(finally_clause) = node.child_by_field_name("finally_clause") {
            self.table.enter_scope(ScopeKind::Block);
            self.visit_node(finally_clause);
            let _ = self.table.exit_scope();
        }
    }

    fn handle_python_import(&mut self, node: Node) {
        let mut cursor = node.walk();

        for child in node.children(&mut cursor) {
            match child.kind() {
                "dotted_name" | "identifier" => {
                    let name = self.node_text(child);
                    let location = self.node_location(child);

                    let symbol = Symbol::new(name, SymbolKind::Import, self.table.current_scope_id(), location)
                        .with_mutable(false);

                    let _ = self.table.declare(symbol);
                }
                "aliased_import" => {
                    // from x import y as z
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = self.node_text(name_node);
                        let location = self.node_location(name_node);

                        let symbol = Symbol::new(name, SymbolKind::Import, self.table.current_scope_id(), location)
                            .with_mutable(false);

                        let _ = self.table.declare(symbol);
                    }
                }
                _ => {}
            }
        }
    }

    fn handle_python_lambda(&mut self, node: Node) {
        self.table.enter_scope(ScopeKind::Function);

        // Handle lambda parameters
        if let Some(params) = node.child_by_field_name("parameters") {
            self.handle_python_parameters(params);
        }

        // Visit lambda body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    /// Visit JavaScript/TypeScript nodes
    fn visit_js_node(&mut self, node: Node) {
        // Similar to Python but with JS-specific scoping rules
        // var is function-scoped, let/const are block-scoped
        // For now, fall through to generic
        self.visit_generic_node(node);
    }

    /// Visit Rust nodes
    fn visit_rust_node(&mut self, node: Node) {
        self.visit_generic_node(node);
    }

    /// Visit Go nodes
    fn visit_go_node(&mut self, node: Node) {
        self.visit_generic_node(node);
    }

    /// Generic node visitor (fallback)
    fn visit_generic_node(&mut self, node: Node) {
        self.visit_children(node);
    }

    /// Visit all children of a node
    fn visit_children(&mut self, node: Node) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.visit_node(child);
        }
    }

    /// Extract text from a node
    fn node_text(&self, node: Node) -> String {
        node.utf8_text(self.source.as_bytes())
            .unwrap_or("")
            .to_string()
    }

    /// Create a Location from a node
    fn node_location(&self, node: Node) -> Location {
        Location {
            file_path: self.file_path.clone(),
            line: node.start_position().row as u32 + 1, // 1-indexed
            column: Some(node.start_position().column as u32),
            end_line: Some(node.end_position().row as u32 + 1),
            end_column: Some(node.end_position().column as u32),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_table_creation() {
        let table = SymbolTable::new();
        assert_eq!(table.current_scope_id(), 0);
        assert_eq!(table.global_scope_id(), 0);
    }

    #[test]
    fn test_scope_management() {
        let mut table = SymbolTable::new();

        // Enter function scope
        let func_scope = table.enter_scope(ScopeKind::Function);
        assert_eq!(table.current_scope_id(), func_scope);
        assert!(func_scope > 0);

        // Enter nested block scope
        let block_scope = table.enter_scope(ScopeKind::Block);
        assert_eq!(table.current_scope_id(), block_scope);

        // Exit block scope
        assert!(table.exit_scope().is_ok());
        assert_eq!(table.current_scope_id(), func_scope);

        // Exit function scope
        assert!(table.exit_scope().is_ok());
        assert_eq!(table.current_scope_id(), 0);

        // Cannot exit global
        assert!(table.exit_scope().is_err());
    }

    #[test]
    fn test_symbol_declaration_and_resolution() {
        let mut table = SymbolTable::new();

        let loc = Location::new("test.py".to_string(), 1);
        let symbol = Symbol::new("x", SymbolKind::Variable, 0, loc.clone());

        assert!(table.declare(symbol).is_ok());
        assert!(table.resolve("x").is_some());
        assert_eq!(table.resolve("x").unwrap().name, "x");
    }

    #[test]
    fn test_duplicate_declaration_error() {
        let mut table = SymbolTable::new();

        let loc = Location::new("test.py".to_string(), 1);
        let symbol1 = Symbol::new("x", SymbolKind::Variable, 0, loc.clone());
        let symbol2 = Symbol::new("x", SymbolKind::Variable, 0, loc.clone());

        assert!(table.declare(symbol1).is_ok());
        assert!(table.declare(symbol2).is_err());
    }

    #[test]
    fn test_lexical_scoping() {
        let mut table = SymbolTable::new();

        // Declare in global scope
        let loc = Location::new("test.py".to_string(), 1);
        let global_x = Symbol::new("x", SymbolKind::Variable, 0, loc.clone());
        table.declare(global_x).unwrap();

        // Enter function scope
        table.enter_scope(ScopeKind::Function);

        // Should still see global x
        assert!(table.resolve("x").is_some());
        assert_eq!(table.resolve("x").unwrap().scope_id, 0);

        // Declare local y
        let local_y = Symbol::new("y", SymbolKind::Variable, table.current_scope_id(), loc.clone());
        table.declare(local_y).unwrap();

        // Should see both
        assert!(table.resolve("x").is_some());
        assert!(table.resolve("y").is_some());

        // Exit function
        table.exit_scope().unwrap();

        // Should still see x, but not y
        assert!(table.resolve("x").is_some());
        assert!(table.resolve("y").is_none());
    }

    #[test]
    fn test_same_name_different_scopes() {
        let mut table = SymbolTable::new();

        let loc1 = Location::new("test.py".to_string(), 1);
        let loc2 = Location::new("test.py".to_string(), 5);

        // Global x
        let global_x = Symbol::new("x", SymbolKind::Variable, 0, loc1);
        table.declare(global_x).unwrap();

        // Enter function, declare different x
        table.enter_scope(ScopeKind::Function);
        let func_scope = table.current_scope_id();
        let local_x = Symbol::new("x", SymbolKind::Variable, func_scope, loc2);
        table.declare(local_x).unwrap();

        // Resolve should find local x (innermost)
        let resolved = table.resolve("x").unwrap();
        assert_eq!(resolved.scope_id, func_scope);
        assert_eq!(resolved.defined_at.line, 5);

        // Exit function, resolve should find global x
        table.exit_scope().unwrap();
        let resolved = table.resolve("x").unwrap();
        assert_eq!(resolved.scope_id, 0);
        assert_eq!(resolved.defined_at.line, 1);
    }

    #[test]
    fn test_taint_tracking() {
        let mut table = SymbolTable::new();

        let loc = Location::new("test.py".to_string(), 1);
        let symbol = Symbol::new("user_input", SymbolKind::Variable, 0, loc);
        table.declare(symbol).unwrap();

        // Initially not tainted
        assert!(!table.is_tainted("user_input"));

        // Mark as tainted
        let taint = TaintState {
            labels: vec![],
            origin_file: "test.py".to_string(),
            origin_line: 1,
            flow_path: vec![],
        };
        assert!(table.update_taint("user_input", taint));
        assert!(table.is_tainted("user_input"));

        // Get taint state
        assert!(table.get_taint("user_input").is_some());

        // Clear taint (sanitization)
        assert!(table.clear_taint("user_input"));
        assert!(!table.is_tainted("user_input"));
    }

    #[test]
    fn test_get_all_tainted() {
        let mut table = SymbolTable::new();

        let loc = Location::new("test.py".to_string(), 1);

        // Create multiple symbols
        let s1 = Symbol::new("a", SymbolKind::Variable, 0, loc.clone());
        let s2 = Symbol::new("b", SymbolKind::Variable, 0, loc.clone());
        let s3 = Symbol::new("c", SymbolKind::Variable, 0, loc.clone());

        table.declare(s1).unwrap();
        table.declare(s2).unwrap();
        table.declare(s3).unwrap();

        // Taint a and c
        let taint = TaintState {
            labels: vec![],
            origin_file: "test.py".to_string(),
            origin_line: 1,
            flow_path: vec![],
        };
        table.update_taint("a", taint.clone());
        table.update_taint("c", taint);

        let tainted = table.get_all_tainted();
        assert_eq!(tainted.len(), 2);
        assert!(tainted.iter().any(|(n, _)| *n == "a"));
        assert!(tainted.iter().any(|(n, _)| *n == "c"));
        assert!(!tainted.iter().any(|(n, _)| *n == "b"));
    }

    #[test]
    fn test_shadowing_detection() {
        let mut table = SymbolTable::new();

        let loc = Location::new("test.py".to_string(), 1);
        let symbol = Symbol::new("x", SymbolKind::Variable, 0, loc);
        table.declare(symbol).unwrap();

        // In global scope, nothing to shadow
        assert!(!table.would_shadow("x"));

        // Enter function scope
        table.enter_scope(ScopeKind::Function);

        // Now x would shadow the global
        assert!(table.would_shadow("x"));

        // y doesn't shadow anything
        assert!(!table.would_shadow("y"));
    }

    #[test]
    fn test_unused_symbols() {
        let mut table = SymbolTable::new();

        let loc1 = Location::new("test.py".to_string(), 1);
        let loc2 = Location::new("test.py".to_string(), 5);

        // Declare symbols
        let s1 = Symbol::new("used_var", SymbolKind::Variable, 0, loc1);
        let s2 = Symbol::new("unused_var", SymbolKind::Variable, 0, loc2.clone());

        table.declare(s1).unwrap();
        table.declare(s2).unwrap();

        // Record use of used_var
        table.record_use("used_var", loc2);

        // Check unused
        let unused = table.get_unused_symbols(0);
        assert_eq!(unused.len(), 1);
        assert_eq!(unused[0].name, "unused_var");
    }

    #[test]
    fn test_symbol_with_type() {
        let loc = Location::new("test.py".to_string(), 1);
        let symbol = Symbol::new("items", SymbolKind::Variable, 0, loc)
            .with_type(TypeInfo::List(Box::new(TypeInfo::Primitive("str".to_string()))));

        assert!(matches!(
            symbol.type_info,
            Some(TypeInfo::List(_))
        ));
    }

    #[test]
    fn test_resolve_mut_for_taint_update() {
        let mut table = SymbolTable::new();

        let loc = Location::new("test.py".to_string(), 1);
        let symbol = Symbol::new("data", SymbolKind::Variable, 0, loc);
        table.declare(symbol).unwrap();

        // Get mutable reference and update taint
        let taint = TaintState {
            labels: vec![],
            origin_file: "test.py".to_string(),
            origin_line: 1,
            flow_path: vec![],
        };

        if let Some(sym) = table.resolve_mut("data") {
            sym.set_taint(taint);
        }

        assert!(table.is_tainted("data"));
    }
}
