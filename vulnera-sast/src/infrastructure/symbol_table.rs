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
        self.scopes.get(self.current_scope).map(|s| s.kind)
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
    pub fn declare_in_scope(&mut self, scope_id: usize, symbol: Symbol) -> Result<(), SymbolError> {
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
        self.resolve(name).map(|s| s.is_tainted()).unwrap_or(false)
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

    /// Get taint state by name across all scopes (ignores current scope)
    pub fn get_taint_any_scope(&self, name: &str) -> Option<&TaintState> {
        for scope in &self.scopes {
            if let Some(symbol) = scope.resolve(name) {
                if let Some(taint) = symbol.taint_state() {
                    return Some(taint);
                }
            }
        }
        None
    }

    /// Check if a symbol is tainted in any scope
    pub fn is_tainted_any_scope(&self, name: &str) -> bool {
        self.get_taint_any_scope(name).is_some()
    }

    /// Get all tainted symbols in all scopes
    pub fn get_all_tainted_in_all_scopes(&self) -> Vec<(&str, &TaintState)> {
        let mut result = Vec::new();
        for scope in &self.scopes {
            for (name, symbol) in &scope.symbols {
                if let Some(taint) = symbol.taint_state() {
                    result.push((name.as_str(), taint));
                }
            }
        }
        result
    }

    /// Update taint state for a symbol in any scope
    pub fn update_taint_any_scope(&mut self, name: &str, taint: TaintState) -> bool {
        for scope in &mut self.scopes {
            if let Some(symbol) = scope.resolve_mut(name) {
                symbol.set_taint(taint);
                return true;
            }
        }
        false
    }

    /// Clear taint for a symbol in any scope
    pub fn clear_taint_any_scope(&mut self, name: &str) -> bool {
        for scope in &mut self.scopes {
            if let Some(symbol) = scope.resolve_mut(name) {
                symbol.clear_taint();
                return true;
            }
        }
        false
    }

    /// Clear taint for all symbols in all scopes
    pub fn clear_all_taints(&mut self) {
        for scope in &mut self.scopes {
            for symbol in scope.symbols.values_mut() {
                symbol.clear_taint();
            }
        }
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
        let mut current = self.scopes.get(self.current_scope).and_then(|s| s.parent);

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
            Language::C => self.visit_c_node(node),
            Language::Cpp => self.visit_cpp_node(node),
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

            let symbol = Symbol::new(
                name.clone(),
                SymbolKind::Function,
                self.table.current_scope_id(),
                location,
            )
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

            let symbol = Symbol::new(
                name.clone(),
                SymbolKind::Class,
                self.table.current_scope_id(),
                location,
            )
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

                    let symbol = Symbol::new(
                        name,
                        SymbolKind::Parameter,
                        self.table.current_scope_id(),
                        location,
                    );

                    let _ = self.table.declare(symbol);
                }
                "typed_parameter" | "default_parameter" | "keyword_separator" => {
                    // These have an identifier child
                    if let Some(ident) = child.child_by_field_name("name") {
                        let name = self.node_text(ident);
                        let location = self.node_location(ident);

                        let symbol = Symbol::new(
                            name,
                            SymbolKind::Parameter,
                            self.table.current_scope_id(),
                            location,
                        );

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

                let symbol = Symbol::new(
                    name,
                    SymbolKind::Variable,
                    self.table.current_scope_id(),
                    location,
                );

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

                    let symbol = Symbol::new(
                        name,
                        SymbolKind::Import,
                        self.table.current_scope_id(),
                        location,
                    )
                    .with_mutable(false);

                    let _ = self.table.declare(symbol);
                }
                "aliased_import" => {
                    // from x import y as z
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = self.node_text(name_node);
                        let location = self.node_location(name_node);

                        let symbol = Symbol::new(
                            name,
                            SymbolKind::Import,
                            self.table.current_scope_id(),
                            location,
                        )
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
        match node.kind() {
            // Function declaration
            "function_declaration" | "function" => {
                self.handle_js_function(node);
            }
            // Arrow function
            "arrow_function" => {
                self.handle_js_arrow_function(node);
            }
            // Method definition in class
            "method_definition" => {
                self.handle_js_method(node);
            }
            // Variable declarations (var, let, const)
            "variable_declaration" => {
                self.handle_js_variable_declaration(node);
            }
            // Class declaration
            "class_declaration" => {
                self.handle_js_class(node);
            }
            // Block statement (for let/const scoping)
            "statement_block" => {
                self.handle_js_block(node);
            }
            // For loops
            "for_statement" | "for_in_statement" | "for_of_statement" => {
                self.handle_js_for_loop(node);
            }
            // While loop
            "while_statement" => {
                self.handle_js_while_loop(node);
            }
            // If statement
            "if_statement" => {
                self.handle_js_if(node);
            }
            // Try/catch
            "try_statement" => {
                self.handle_js_try(node);
            }
            // Import statement
            "import_statement" => {
                self.handle_js_import(node);
            }
            // Catch clause
            "catch_clause" => {
                self.handle_js_catch(node);
            }
            // Default: visit children
            _ => {
                self.visit_children(node);
            }
        }
    }

    fn handle_js_function(&mut self, node: Node) {
        // Extract function name if available
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = self.node_text(name_node);
            let location = self.node_location(name_node);

            let symbol = Symbol::new(
                name.clone(),
                SymbolKind::Function,
                self.table.current_scope_id(),
                location,
            )
            .with_type(TypeInfo::Function {
                params: Vec::new(),
                return_type: Box::new(TypeInfo::Unknown),
            })
            .with_mutable(false);

            let _ = self.table.declare(symbol);
        }

        // Enter function scope
        self.table.enter_scope(ScopeKind::Function);

        // Handle parameters
        if let Some(params) = node.child_by_field_name("parameters") {
            self.handle_js_parameters(params);
        }

        // Visit body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_js_arrow_function(&mut self, node: Node) {
        // Enter function scope (arrow functions create their own scope)
        self.table.enter_scope(ScopeKind::Function);

        // Handle parameters
        if let Some(params) = node.child_by_field_name("parameters") {
            self.handle_js_parameters(params);
        }

        // Visit body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_js_method(&mut self, node: Node) {
        // Extract method name
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = self.node_text(name_node);
            let location = self.node_location(name_node);

            let symbol = Symbol::new(
                name,
                SymbolKind::Function,
                self.table.current_scope_id(),
                location,
            )
            .with_mutable(false);

            let _ = self.table.declare(symbol);
        }

        // Enter function scope for method
        self.table.enter_scope(ScopeKind::Function);

        // Handle parameters (includes 'this' implicitly)
        if let Some(params) = node.child_by_field_name("parameters") {
            self.handle_js_parameters(params);
        }

        // Visit body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_js_parameters(&mut self, params_node: Node) {
        let mut cursor = params_node.walk();

        for child in params_node.children(&mut cursor) {
            match child.kind() {
                "identifier" => {
                    let name = self.node_text(child);
                    let location = self.node_location(child);

                    let symbol = Symbol::new(
                        name,
                        SymbolKind::Parameter,
                        self.table.current_scope_id(),
                        location,
                    );

                    let _ = self.table.declare(symbol);
                }
                "formal_parameter" => {
                    // Has identifier child
                    if let Some(ident) = child.child_by_field_name("pattern") {
                        self.handle_js_pattern(ident);
                    }
                }
                _ => {}
            }
        }
    }

    fn handle_js_pattern(&mut self, node: Node) {
        // Handle destructuring patterns and simple identifiers
        match node.kind() {
            "identifier" => {
                let name = self.node_text(node);
                let location = self.node_location(node);

                let symbol = Symbol::new(
                    name,
                    SymbolKind::Variable,
                    self.table.current_scope_id(),
                    location,
                );

                let _ = self.table.declare(symbol);
            }
            "array_pattern" | "object_pattern" => {
                // Destructuring: visit children recursively
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.handle_js_pattern(child);
                }
            }
            _ => {}
        }
    }

    fn handle_js_variable_declaration(&mut self, node: Node) {
        // Check if it's var, let, or const
        let is_var = self.node_has_keyword(node, "var");
        let is_const = self.node_has_keyword(node, "const");

        // Get the declarator child
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_declarator" {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = self.node_text(name_node);
                    let location = self.node_location(name_node);

                    // Determine scope: var is function-scoped, let/const are block-scoped
                    let target_scope = if is_var {
                        self.find_nearest_function_scope()
                    } else {
                        self.table.current_scope_id()
                    };

                    let symbol =
                        Symbol::new(name.clone(), SymbolKind::Variable, target_scope, location)
                            .with_mutable(!is_const); // const is immutable

                    let _ = self.table.declare_in_scope(target_scope, symbol);
                }

                // Visit initializer if present
                if let Some(value) = child.child_by_field_name("value") {
                    self.visit_node(value);
                }
            }
        }
    }

    fn handle_js_class(&mut self, node: Node) {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = self.node_text(name_node);
            let location = self.node_location(name_node);

            let symbol = Symbol::new(
                name.clone(),
                SymbolKind::Class,
                self.table.current_scope_id(),
                location,
            )
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

    fn handle_js_block(&mut self, node: Node) {
        // Enter block scope for let/const declarations
        self.table.enter_scope(ScopeKind::Block);

        // Visit children
        self.visit_children(node);

        let _ = self.table.exit_scope();
    }

    fn handle_js_for_loop(&mut self, node: Node) {
        // Enter loop scope
        self.table.enter_scope(ScopeKind::Loop);

        // Handle loop variable (in for-in/of, it's the left part)
        if let Some(left) = node.child_by_field_name("left") {
            self.handle_js_pattern(left);
        }

        // Handle initializer (for traditional for loop)
        if let Some(init) = node.child_by_field_name("initializer") {
            self.visit_node(init);
        }

        // Visit condition and update
        if let Some(condition) = node.child_by_field_name("condition") {
            self.visit_node(condition);
        }
        if let Some(update) = node.child_by_field_name("update") {
            self.visit_node(update);
        }

        // Handle right side (for-in/of)
        if let Some(right) = node.child_by_field_name("right") {
            self.visit_node(right);
        }

        // Visit body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_js_while_loop(&mut self, node: Node) {
        self.table.enter_scope(ScopeKind::Loop);

        if let Some(condition) = node.child_by_field_name("condition") {
            self.visit_node(condition);
        }

        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_js_if(&mut self, node: Node) {
        // Visit condition
        if let Some(condition) = node.child_by_field_name("condition") {
            self.visit_node(condition);
        }

        // Consequence (block statement will create its own scope if needed)
        if let Some(consequence) = node.child_by_field_name("consequence") {
            self.visit_node(consequence);
        }

        // Alternative (else/else if)
        if let Some(alternative) = node.child_by_field_name("alternative") {
            self.visit_node(alternative);
        }
    }

    fn handle_js_try(&mut self, node: Node) {
        // Try block - create a scope
        self.table.enter_scope(ScopeKind::Block);
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }
        let _ = self.table.exit_scope();

        // Handle catch clause if present
        if let Some(handler) = node.child_by_field_name("handler") {
            self.visit_node(handler);
        }

        // Finally block if present
        if let Some(finalizer) = node.child_by_field_name("finalizer") {
            self.table.enter_scope(ScopeKind::Block);
            self.visit_node(finalizer);
            let _ = self.table.exit_scope();
        }
    }

    fn handle_js_catch(&mut self, node: Node) {
        self.table.enter_scope(ScopeKind::Block);

        // Declare catch parameter (error variable)
        if let Some(param) = node.child_by_field_name("parameter") {
            self.handle_js_pattern(param);
        }

        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_js_import(&mut self, node: Node) {
        // Handle import clauses
        if let Some(import_clause) = node.child_by_field_name("import_clause") {
            self.handle_js_import_clause(import_clause);
        }

        // Also handle direct imports like: import "module"
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "string" {
                // Module path, we could track this but usually not needed for variable tracking
                break;
            }
        }
    }

    fn handle_js_import_clause(&mut self, node: Node) {
        match node.kind() {
            "identifier" => {
                // import defaultExport from "module"
                let name = self.node_text(node);
                let location = self.node_location(node);

                let symbol = Symbol::new(
                    name,
                    SymbolKind::Import,
                    self.table.current_scope_id(),
                    location,
                )
                .with_mutable(false);

                let _ = self.table.declare(symbol);
            }
            "named_imports" => {
                // import { a, b } from "module"
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "import_specifier" {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            let name = self.node_text(name_node);
                            let location = self.node_location(name_node);

                            let symbol = Symbol::new(
                                name,
                                SymbolKind::Import,
                                self.table.current_scope_id(),
                                location,
                            )
                            .with_mutable(false);

                            let _ = self.table.declare(symbol);
                        }
                    }
                }
            }
            "namespace_import" => {
                // import * as name from "module"
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = self.node_text(name_node);
                    let location = self.node_location(name_node);

                    let symbol = Symbol::new(
                        name,
                        SymbolKind::Import,
                        self.table.current_scope_id(),
                        location,
                    )
                    .with_mutable(false);

                    let _ = self.table.declare(symbol);
                }
            }
            _ => {
                // Visit children for other cases
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.handle_js_import_clause(child);
                }
            }
        }
    }

    fn node_has_keyword(&self, node: Node, keyword: &str) -> bool {
        let text = self.node_text(node).to_lowercase();
        text.starts_with(keyword)
    }

    fn find_nearest_function_scope(&self) -> usize {
        // Walk up from current scope to find nearest function scope
        let mut current = Some(self.table.current_scope_id());

        while let Some(scope_id) = current {
            if let Some(scope) = self.table.get_scope(scope_id) {
                if matches!(scope.kind, ScopeKind::Function | ScopeKind::Global) {
                    return scope_id;
                }
                current = scope.parent;
            } else {
                break;
            }
        }

        // Fallback to global scope
        0
    }

    /// Visit Rust nodes
    fn visit_rust_node(&mut self, node: Node) {
        match node.kind() {
            // Function
            "function_item" => {
                self.handle_rust_function(node);
            }
            // Impl block (methods)
            "impl_item" => {
                self.handle_rust_impl(node);
            }
            // Let declaration
            "let_declaration" => {
                self.handle_rust_let(node);
            }
            // Const declaration
            "const_item" => {
                self.handle_rust_const(node);
            }
            // Static declaration
            "static_item" => {
                self.handle_rust_static(node);
            }
            // Use declaration (import)
            "use_declaration" => {
                self.handle_rust_use(node);
            }
            // Struct/enum
            "struct_item" | "enum_item" => {
                self.handle_rust_type(node);
            }
            // Trait
            "trait_item" => {
                self.handle_rust_trait(node);
            }
            // For loop
            "for_expression" => {
                self.handle_rust_for(node);
            }
            // While loop
            "while_expression" => {
                self.handle_rust_while(node);
            }
            // If expression (includes if let)
            "if_expression" => {
                self.handle_rust_if(node);
            }
            // Match expression
            "match_expression" => {
                self.handle_rust_match(node);
            }
            // Closure
            "closure_expression" => {
                self.handle_rust_closure(node);
            }
            // Block (unsafe, etc.)
            "block" => {
                self.handle_rust_block(node);
            }
            // Mod declaration
            "mod_item" => {
                self.handle_rust_mod(node);
            }
            _ => {
                self.visit_children(node);
            }
        }
    }

    fn handle_rust_function(&mut self, node: Node) {
        // Extract function name
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = self.node_text(name_node);
            let location = self.node_location(name_node);

            let symbol = Symbol::new(
                name.clone(),
                SymbolKind::Function,
                self.table.current_scope_id(),
                location,
            )
            .with_type(TypeInfo::Function {
                params: Vec::new(),
                return_type: Box::new(TypeInfo::Unknown),
            })
            .with_mutable(false);

            let _ = self.table.declare(symbol);
        }

        // Enter function scope
        self.table.enter_scope(ScopeKind::Function);

        // Handle generic parameters if any
        if let Some(type_params) = node.child_by_field_name("type_parameters") {
            self.handle_rust_type_parameters(type_params);
        }

        // Handle parameters
        if let Some(params) = node.child_by_field_name("parameters") {
            self.handle_rust_parameters(params);
        }

        // Visit body (block)
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_rust_impl(&mut self, node: Node) {
        // Enter impl scope (treated like a class scope for methods)
        self.table.enter_scope(ScopeKind::Class);

        // Handle type parameters for the impl
        if let Some(type_params) = node.child_by_field_name("type_parameters") {
            self.handle_rust_type_parameters(type_params);
        }

        // Visit the body which contains method definitions
        if let Some(body) = node.child_by_field_name("body") {
            let mut cursor = body.walk();
            for child in body.children(&mut cursor) {
                match child.kind() {
                    "function_item" => {
                        self.handle_rust_method(child);
                    }
                    "const_item" => {
                        self.handle_rust_const(child);
                    }
                    "type_item" => {
                        self.handle_rust_type_alias(child);
                    }
                    _ => self.visit_node(child),
                }
            }
        }

        let _ = self.table.exit_scope();
    }

    fn handle_rust_method(&mut self, node: Node) {
        // Extract method name
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = self.node_text(name_node);
            let location = self.node_location(name_node);

            let symbol = Symbol::new(
                name,
                SymbolKind::Function,
                self.table.current_scope_id(),
                location,
            )
            .with_mutable(false);

            let _ = self.table.declare(symbol);
        }

        // Enter method scope (function scope)
        self.table.enter_scope(ScopeKind::Function);

        // Handle self parameter (implicit)
        if let Some(params) = node.child_by_field_name("parameters") {
            self.handle_rust_parameters(params);
        }

        // Visit body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_rust_parameters(&mut self, params_node: Node) {
        let mut cursor = params_node.walk();

        for child in params_node.children(&mut cursor) {
            match child.kind() {
                "parameter" | "self_parameter" => {
                    if let Some(pattern) = child.child_by_field_name("pattern") {
                        self.handle_rust_pattern(pattern);
                    }
                    // Also check for self keyword
                    if child.kind() == "self_parameter" {
                        let location = self.node_location(child);
                        let symbol = Symbol::new(
                            "self",
                            SymbolKind::Parameter,
                            self.table.current_scope_id(),
                            location,
                        )
                        .with_mutable(false);
                        let _ = self.table.declare(symbol);
                    }
                }
                _ => {}
            }
        }
    }

    fn handle_rust_pattern(&mut self, node: Node) {
        match node.kind() {
            "identifier" => {
                let name = self.node_text(node);
                let location = self.node_location(node);

                let symbol = Symbol::new(
                    name,
                    SymbolKind::Parameter,
                    self.table.current_scope_id(),
                    location,
                );

                let _ = self.table.declare(symbol);
            }
            "tuple_pattern" | "struct_pattern" | "slice_pattern" => {
                // Destructuring: visit children recursively
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.handle_rust_pattern(child);
                }
            }
            _ => {}
        }
    }

    fn handle_rust_type_parameters(&mut self, node: Node) {
        // Type parameters are like generics: <T, U: Trait>
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "type_identifier" || child.kind() == "identifier" {
                let name = self.node_text(child);
                let location = self.node_location(child);

                let symbol = Symbol::new(
                    name,
                    SymbolKind::TypeAlias,
                    self.table.current_scope_id(),
                    location,
                )
                .with_mutable(false);

                let _ = self.table.declare(symbol);
            }
        }
    }

    fn handle_rust_let(&mut self, node: Node) {
        // Check for mut keyword
        let has_mut = self.node_has_keyword(node, "let mut");

        // Get the pattern (variable name or destructuring)
        if let Some(pattern) = node.child_by_field_name("pattern") {
            self.handle_rust_let_pattern(pattern, has_mut);
        }

        // Visit type annotation if present
        if let Some(type_node) = node.child_by_field_name("type") {
            self.visit_node(type_node);
        }

        // Visit value if present
        if let Some(value) = node.child_by_field_name("value") {
            self.visit_node(value);
        }
    }

    fn handle_rust_let_pattern(&mut self, node: Node, is_mutable: bool) {
        match node.kind() {
            "identifier" => {
                let name = self.node_text(node);
                let location = self.node_location(node);

                let symbol = Symbol::new(
                    name,
                    SymbolKind::Variable,
                    self.table.current_scope_id(),
                    location,
                )
                .with_mutable(is_mutable);

                let _ = self.table.declare(symbol);
            }
            "tuple_pattern" => {
                // let (a, b) = ...
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.handle_rust_let_pattern(child, is_mutable);
                }
            }
            _ => {}
        }
    }

    fn handle_rust_const(&mut self, node: Node) {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = self.node_text(name_node);
            let location = self.node_location(name_node);

            let symbol = Symbol::new(
                name,
                SymbolKind::Variable,
                self.table.current_scope_id(),
                location,
            )
            .with_mutable(false);

            let _ = self.table.declare(symbol);
        }

        // Visit children
        self.visit_children(node);
    }

    fn handle_rust_static(&mut self, node: Node) {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = self.node_text(name_node);
            let location = self.node_location(name_node);

            let symbol = Symbol::new(
                name,
                SymbolKind::Variable,
                self.table.current_scope_id(),
                location,
            )
            .with_mutable(true); // static is mutable

            let _ = self.table.declare(symbol);
        }

        self.visit_children(node);
    }

    fn handle_rust_use(&mut self, node: Node) {
        // Handle use declarations (imports)
        if let Some(tree_node) = node.child_by_field_name("tree") {
            self.handle_rust_use_tree(tree_node);
        }
    }

    fn handle_rust_use_tree(&mut self, node: Node) {
        match node.kind() {
            "identifier" | "type_identifier" => {
                let name = self.node_text(node);
                let location = self.node_location(node);

                let symbol = Symbol::new(
                    name,
                    SymbolKind::Import,
                    self.table.current_scope_id(),
                    location,
                )
                .with_mutable(false);

                let _ = self.table.declare(symbol);
            }
            "use_tree" => {
                // Nested use tree: visit children
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.handle_rust_use_tree(child);
                }
            }
            _ => {
                // Visit children for other cases
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.handle_rust_use_tree(child);
                }
            }
        }
    }

    fn handle_rust_type(&mut self, node: Node) {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = self.node_text(name_node);
            let location = self.node_location(name_node);

            let symbol = Symbol::new(
                name.clone(),
                SymbolKind::Class,
                self.table.current_scope_id(),
                location,
            )
            .with_type(TypeInfo::Object(name))
            .with_mutable(false);

            let _ = self.table.declare(symbol);

            // Handle type parameters
            if let Some(type_params) = node.child_by_field_name("type_parameters") {
                self.handle_rust_type_parameters(type_params);
            }
        }

        self.visit_children(node);
    }

    fn handle_rust_trait(&mut self, node: Node) {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = self.node_text(name_node);
            let location = self.node_location(name_node);

            let symbol = Symbol::new(
                name,
                SymbolKind::Class,
                self.table.current_scope_id(),
                location,
            )
            .with_mutable(false);

            let _ = self.table.declare(symbol);
        }

        // Visit trait body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }
    }

    fn handle_rust_type_alias(&mut self, node: Node) {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = self.node_text(name_node);
            let location = self.node_location(name_node);

            let symbol = Symbol::new(
                name,
                SymbolKind::TypeAlias,
                self.table.current_scope_id(),
                location,
            )
            .with_mutable(false);

            let _ = self.table.declare(symbol);
        }

        self.visit_children(node);
    }

    fn handle_rust_for(&mut self, node: Node) {
        self.table.enter_scope(ScopeKind::Loop);

        // Get the loop variable (pattern)
        if let Some(pattern) = node.child_by_field_name("pattern") {
            self.handle_rust_let_pattern(pattern, false);
        }

        // Visit value being iterated
        if let Some(value) = node.child_by_field_name("value") {
            self.visit_node(value);
        }

        // Visit body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_rust_while(&mut self, node: Node) {
        self.table.enter_scope(ScopeKind::Loop);

        // Visit condition
        if let Some(condition) = node.child_by_field_name("condition") {
            self.visit_node(condition);
        }

        // Visit body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_rust_if(&mut self, node: Node) {
        // If let creates a new binding, so we need a scope
        let has_pattern = node.child_by_field_name("pattern").is_some();

        if has_pattern {
            self.table.enter_scope(ScopeKind::Block);

            // Handle if let pattern
            if let Some(pattern) = node.child_by_field_name("pattern") {
                self.handle_rust_let_pattern(pattern, false);
            }

            // Visit value
            if let Some(value) = node.child_by_field_name("value") {
                self.visit_node(value);
            }

            // Visit consequence
            if let Some(consequence) = node.child_by_field_name("consequence") {
                self.visit_node(consequence);
            }

            let _ = self.table.exit_scope();
        } else {
            // Regular if - no new scope for condition, block creates its own
            if let Some(condition) = node.child_by_field_name("condition") {
                self.visit_node(condition);
            }

            if let Some(consequence) = node.child_by_field_name("consequence") {
                self.visit_node(consequence);
            }
        }

        // Visit alternative (else branch)
        if let Some(alternative) = node.child_by_field_name("alternative") {
            self.visit_node(alternative);
        }
    }

    fn handle_rust_match(&mut self, node: Node) {
        // Visit value being matched
        if let Some(value) = node.child_by_field_name("value") {
            self.visit_node(value);
        }

        // Visit match arms - each arm creates its own scope for bindings
        if let Some(arms) = node.child_by_field_name("arms") {
            let mut cursor = arms.walk();
            for child in arms.children(&mut cursor) {
                if child.kind() == "match_arm" {
                    self.handle_rust_match_arm(child);
                }
            }
        }
    }

    fn handle_rust_match_arm(&mut self, node: Node) {
        // Each match arm creates a scope for its pattern bindings
        self.table.enter_scope(ScopeKind::Block);

        // Visit pattern
        if let Some(pattern) = node.child_by_field_name("pattern") {
            self.handle_rust_match_pattern(pattern);
        }

        // Visit body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_rust_match_pattern(&mut self, node: Node) {
        // Similar to let pattern but for match arms
        match node.kind() {
            "identifier" => {
                let name = self.node_text(node);
                let location = self.node_location(node);

                let symbol = Symbol::new(
                    name,
                    SymbolKind::Variable,
                    self.table.current_scope_id(),
                    location,
                )
                .with_mutable(false);

                let _ = self.table.declare(symbol);
            }
            "tuple_pattern" | "struct_pattern" | "slice_pattern" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.handle_rust_match_pattern(child);
                }
            }
            _ => {}
        }
    }

    fn handle_rust_closure(&mut self, node: Node) {
        // Enter closure scope
        self.table.enter_scope(ScopeKind::Closure);

        // Handle parameters
        if let Some(params) = node.child_by_field_name("parameters") {
            self.handle_rust_parameters(params);
        }

        // Visit body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_rust_block(&mut self, node: Node) {
        // Enter block scope
        self.table.enter_scope(ScopeKind::Block);

        // Visit children
        self.visit_children(node);

        let _ = self.table.exit_scope();
    }

    fn handle_rust_mod(&mut self, node: Node) {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = self.node_text(name_node);
            let location = self.node_location(name_node);

            let symbol = Symbol::new(
                name,
                SymbolKind::Module,
                self.table.current_scope_id(),
                location,
            )
            .with_mutable(false);

            let _ = self.table.declare(symbol);
        }

        // Visit body if present
        if let Some(body) = node.child_by_field_name("body") {
            self.table.enter_scope(ScopeKind::Module);
            self.visit_node(body);
            let _ = self.table.exit_scope();
        }
    }

    /// Visit Go nodes
    fn visit_go_node(&mut self, node: Node) {
        match node.kind() {
            // Function declaration
            "function_declaration" => {
                self.handle_go_function(node);
            }
            // Method declaration (has receiver)
            "method_declaration" => {
                self.handle_go_method(node);
            }
            // Variable declaration
            "var_declaration" => {
                self.handle_go_var_declaration(node);
            }
            // Short variable declaration (:=)
            "short_var_declaration" => {
                self.handle_go_short_var_declaration(node);
            }
            // Const declaration
            "const_declaration" => {
                self.handle_go_const(node);
            }
            // Type declaration (struct, interface)
            "type_declaration" => {
                self.handle_go_type(node);
            }
            // Import declaration
            "import_declaration" => {
                self.handle_go_import(node);
            }
            // For loop
            "for_statement" => {
                self.handle_go_for(node);
            }
            // If statement
            "if_statement" => {
                self.handle_go_if(node);
            }
            // Block
            "block" => {
                self.handle_go_block(node);
            }
            _ => {
                self.visit_children(node);
            }
        }
    }

    fn handle_go_function(&mut self, node: Node) {
        // Get function name
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = self.node_text(name_node);
            let location = self.node_location(name_node);

            let symbol = Symbol::new(
                name,
                SymbolKind::Function,
                self.table.current_scope_id(),
                location,
            )
            .with_mutable(false);

            let _ = self.table.declare(symbol);
        }

        // Enter function scope
        self.table.enter_scope(ScopeKind::Function);

        // Handle parameters
        if let Some(params) = node.child_by_field_name("parameters") {
            self.handle_go_parameters(params);
        }

        // Visit body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_go_method(&mut self, node: Node) {
        // Get method name
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = self.node_text(name_node);
            let location = self.node_location(name_node);

            let symbol = Symbol::new(
                name,
                SymbolKind::Function,
                self.table.current_scope_id(),
                location,
            )
            .with_mutable(false);

            let _ = self.table.declare(symbol);
        }

        // Enter function scope
        self.table.enter_scope(ScopeKind::Function);

        // Handle receiver (self-like parameter)
        if let Some(receiver) = node.child_by_field_name("receiver") {
            self.handle_go_parameters(receiver);
        }

        // Handle parameters
        if let Some(params) = node.child_by_field_name("parameters") {
            self.handle_go_parameters(params);
        }

        // Visit body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_go_parameters(&mut self, params_node: Node) {
        let mut cursor = params_node.walk();

        for child in params_node.children(&mut cursor) {
            if child.kind() == "parameter_declaration" {
                // Get parameter names (can be multiple: a, b int)
                let param_cursor = &mut child.walk();
                for param_child in child.children(param_cursor) {
                    if param_child.kind() == "identifier" {
                        let name = self.node_text(param_child);
                        let location = self.node_location(param_child);

                        let symbol = Symbol::new(
                            name,
                            SymbolKind::Parameter,
                            self.table.current_scope_id(),
                            location,
                        );

                        let _ = self.table.declare(symbol);
                    }
                }
            }
        }
    }

    fn handle_go_var_declaration(&mut self, node: Node) {
        // var x int or var x = ...
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "var_spec" {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = self.node_text(name_node);
                    let location = self.node_location(name_node);

                    let symbol = Symbol::new(
                        name,
                        SymbolKind::Variable,
                        self.table.current_scope_id(),
                        location,
                    );

                    let _ = self.table.declare(symbol);
                }

                // Visit value if present
                if let Some(value) = child.child_by_field_name("value") {
                    self.visit_node(value);
                }
            }
        }
    }

    fn handle_go_short_var_declaration(&mut self, node: Node) {
        // x := ... (LHS is variable names)
        if let Some(left) = node.child_by_field_name("left") {
            let mut cursor = left.walk();
            for child in left.children(&mut cursor) {
                if child.kind() == "identifier" {
                    let name = self.node_text(child);
                    let location = self.node_location(child);

                    let symbol = Symbol::new(
                        name,
                        SymbolKind::Variable,
                        self.table.current_scope_id(),
                        location,
                    );

                    let _ = self.table.declare(symbol);
                }
            }
        }

        // Visit right side
        if let Some(right) = node.child_by_field_name("right") {
            self.visit_node(right);
        }
    }

    fn handle_go_const(&mut self, node: Node) {
        // const x = ...
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "const_spec" {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = self.node_text(name_node);
                    let location = self.node_location(name_node);

                    let symbol = Symbol::new(
                        name,
                        SymbolKind::Variable,
                        self.table.current_scope_id(),
                        location,
                    )
                    .with_mutable(false);

                    let _ = self.table.declare(symbol);
                }

                // Visit value if present
                if let Some(value) = child.child_by_field_name("value") {
                    self.visit_node(value);
                }
            }
        }
    }

    fn handle_go_type(&mut self, node: Node) {
        // type X struct{...} or type Y interface{...}
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "type_spec" {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = self.node_text(name_node);
                    let location = self.node_location(name_node);

                    let symbol = Symbol::new(
                        name.clone(),
                        SymbolKind::Class,
                        self.table.current_scope_id(),
                        location,
                    )
                    .with_type(TypeInfo::Object(name))
                    .with_mutable(false);

                    let _ = self.table.declare(symbol);
                }

                // Visit the type definition
                if let Some(params) = child.child_by_field_name("params") {
                    self.visit_node(params);
                }
            }
        }
    }

    fn handle_go_import(&mut self, node: Node) {
        // import "pkg" or import alias "pkg"
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            match child.kind() {
                "import_spec" => {
                    // Get the import name (alias or package name)
                    let name = if let Some(name_node) = child.child_by_field_name("name") {
                        self.node_text(name_node)
                    } else if let Some(path_node) = child.child_by_field_name("path") {
                        // Extract package name from path
                        let path = self.node_text(path_node);
                        path.trim_matches('"')
                            .split('/')
                            .next_back()
                            .unwrap_or("")
                            .to_string()
                    } else {
                        continue;
                    };

                    let location = self.node_location(child);

                    let symbol = Symbol::new(
                        name,
                        SymbolKind::Import,
                        self.table.current_scope_id(),
                        location,
                    )
                    .with_mutable(false);

                    let _ = self.table.declare(symbol);
                }
                "import_spec_list" => {
                    // Multiple imports in parens
                    let mut list_cursor = child.walk();
                    for spec in child.children(&mut list_cursor) {
                        if spec.kind() == "import_spec" {
                            let name = if let Some(name_node) = spec.child_by_field_name("name") {
                                self.node_text(name_node)
                            } else if let Some(path_node) = spec.child_by_field_name("path") {
                                let path = self.node_text(path_node);
                                path.trim_matches('"')
                                    .split('/')
                                    .next_back()
                                    .unwrap_or("")
                                    .to_string()
                            } else {
                                continue;
                            };

                            let location = self.node_location(spec);

                            let symbol = Symbol::new(
                                name,
                                SymbolKind::Import,
                                self.table.current_scope_id(),
                                location,
                            )
                            .with_mutable(false);

                            let _ = self.table.declare(symbol);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn handle_go_for(&mut self, node: Node) {
        // Go has: for init; cond; post { } or for range { }
        self.table.enter_scope(ScopeKind::Loop);

        // Handle range clause if present
        if let Some(range_clause) = node.child_by_field_name("range_clause") {
            if let Some(left) = range_clause.child_by_field_name("left") {
                self.handle_go_range_variables(left);
            }

            if let Some(right) = range_clause.child_by_field_name("right") {
                self.visit_node(right);
            }
        }

        // Handle traditional for components
        if let Some(init) = node.child_by_field_name("initializer") {
            self.visit_node(init);
        }
        if let Some(condition) = node.child_by_field_name("condition") {
            self.visit_node(condition);
        }
        if let Some(update) = node.child_by_field_name("update") {
            self.visit_node(update);
        }

        // Visit body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_go_range_variables(&mut self, node: Node) {
        // Handle variables in range clause: for i, v := range ...
        match node.kind() {
            "identifier" => {
                let name = self.node_text(node);
                let location = self.node_location(node);

                let symbol = Symbol::new(
                    name,
                    SymbolKind::Variable,
                    self.table.current_scope_id(),
                    location,
                );

                let _ = self.table.declare(symbol);
            }
            "expression_list" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "identifier" {
                        let name = self.node_text(child);
                        let location = self.node_location(child);

                        let symbol = Symbol::new(
                            name,
                            SymbolKind::Variable,
                            self.table.current_scope_id(),
                            location,
                        );

                        let _ = self.table.declare(symbol);
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_go_if(&mut self, node: Node) {
        // if statement - Go has optional init statement: if x := ...; x > 0 { }
        self.table.enter_scope(ScopeKind::Block);

        // Handle initializer if present
        if let Some(init) = node.child_by_field_name("initializer") {
            self.visit_node(init);
        }

        // Handle condition
        if let Some(condition) = node.child_by_field_name("condition") {
            self.visit_node(condition);
        }

        // Handle consequence
        if let Some(consequence) = node.child_by_field_name("consequence") {
            self.visit_node(consequence);
        }

        // Handle alternative (else)
        if let Some(alternative) = node.child_by_field_name("alternative") {
            self.visit_node(alternative);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_go_block(&mut self, node: Node) {
        // Generic block - create a new scope
        self.table.enter_scope(ScopeKind::Block);

        self.visit_children(node);

        let _ = self.table.exit_scope();
    }

    /// Visit C nodes
    fn visit_c_node(&mut self, node: Node) {
        match node.kind() {
            // Function definition
            "function_definition" => {
                self.handle_c_function(node);
            }
            // Variable declaration
            "declaration" => {
                self.handle_c_declaration(node);
            }
            // For loop
            "for_statement" => {
                self.handle_c_for(node);
            }
            // While loop
            "while_statement" => {
                self.handle_c_while(node);
            }
            // If statement
            "if_statement" => {
                self.handle_c_if(node);
            }
            // Compound statement (block)
            "compound_statement" => {
                self.handle_c_block(node);
            }
            _ => {
                self.visit_children(node);
            }
        }
    }

    fn handle_c_function(&mut self, node: Node) {
        // Get declarator which contains function name
        if let Some(declarator) = node.child_by_field_name("declarator") {
            self.handle_c_function_declarator(declarator);
        }

        // Enter function scope
        self.table.enter_scope(ScopeKind::Function);

        // Handle parameters from declarator
        if let Some(declarator) = node.child_by_field_name("declarator") {
            self.handle_c_function_parameters(declarator);
        }

        // Visit body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_c_function_declarator(&mut self, node: Node) {
        // Get function name from declarator
        match node.kind() {
            "function_declarator" => {
                if let Some(decl) = node.child_by_field_name("declarator") {
                    self.handle_c_function_declarator(decl);
                }
            }
            "identifier" => {
                let name = self.node_text(node);
                let location = self.node_location(node);

                let symbol = Symbol::new(
                    name,
                    SymbolKind::Function,
                    self.table.current_scope_id(),
                    location,
                )
                .with_mutable(false);

                let _ = self.table.declare(symbol);
            }
            "pointer_declarator" => {
                // Skip pointer and get to identifier
                if let Some(decl) = node.child_by_field_name("declarator") {
                    self.handle_c_function_declarator(decl);
                }
            }
            _ => {}
        }
    }

    fn handle_c_function_parameters(&mut self, node: Node) {
        // Extract parameter declarations from function declarator
        if node.kind() == "function_declarator" {
            if let Some(params) = node.child_by_field_name("parameters") {
                let mut cursor = params.walk();
                for child in params.children(&mut cursor) {
                    if child.kind() == "parameter_declaration" {
                        self.handle_c_parameter(child);
                    }
                }
            }
        }
    }

    fn handle_c_parameter(&mut self, node: Node) {
        // Get parameter name from parameter declaration
        if let Some(declarator) = node.child_by_field_name("declarator") {
            self.extract_c_identifier(declarator, SymbolKind::Parameter);
        }
    }

    fn extract_c_identifier(&mut self, node: Node, kind: SymbolKind) {
        match node.kind() {
            "identifier" => {
                let name = self.node_text(node);
                let location = self.node_location(node);

                let symbol = Symbol::new(name, kind, self.table.current_scope_id(), location);

                let _ = self.table.declare(symbol);
            }
            "pointer_declarator" | "array_declarator" => {
                // Skip pointer/array and get to identifier
                if let Some(decl) = node.child_by_field_name("declarator") {
                    self.extract_c_identifier(decl, kind);
                }
            }
            "function_declarator" => {
                if let Some(decl) = node.child_by_field_name("declarator") {
                    self.extract_c_identifier(decl, kind);
                }
            }
            _ => {}
        }
    }

    fn handle_c_declaration(&mut self, node: Node) {
        // Variable or type declaration
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            match child.kind() {
                "init_declarator" => {
                    if let Some(declarator) = child.child_by_field_name("declarator") {
                        self.extract_c_identifier(declarator, SymbolKind::Variable);
                    }
                    // Visit initializer if present
                    if let Some(value) = child.child_by_field_name("value") {
                        self.visit_node(value);
                    }
                }
                "declarator" => {
                    self.extract_c_identifier(child, SymbolKind::Variable);
                }
                _ => {}
            }
        }
    }

    fn handle_c_for(&mut self, node: Node) {
        // For loop in C creates a new scope
        self.table.enter_scope(ScopeKind::Loop);

        // Handle initializer
        if let Some(init) = node.child_by_field_name("initializer") {
            self.visit_node(init);
        }

        // Handle condition
        if let Some(condition) = node.child_by_field_name("condition") {
            self.visit_node(condition);
        }

        // Handle update
        if let Some(update) = node.child_by_field_name("update") {
            self.visit_node(update);
        }

        // Handle body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_c_while(&mut self, node: Node) {
        self.table.enter_scope(ScopeKind::Loop);

        if let Some(condition) = node.child_by_field_name("condition") {
            self.visit_node(condition);
        }

        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_c_if(&mut self, node: Node) {
        // C doesn't create block scope for if, but we do for analysis
        self.table.enter_scope(ScopeKind::Block);

        if let Some(condition) = node.child_by_field_name("condition") {
            self.visit_node(condition);
        }

        if let Some(consequence) = node.child_by_field_name("consequence") {
            self.visit_node(consequence);
        }

        let _ = self.table.exit_scope();

        // Handle else
        if let Some(alternative) = node.child_by_field_name("alternative") {
            self.table.enter_scope(ScopeKind::Block);
            self.visit_node(alternative);
            let _ = self.table.exit_scope();
        }
    }

    fn handle_c_block(&mut self, node: Node) {
        self.table.enter_scope(ScopeKind::Block);

        self.visit_children(node);

        let _ = self.table.exit_scope();
    }

    /// Visit C++ nodes (extends C)
    fn visit_cpp_node(&mut self, node: Node) {
        match node.kind() {
            // C++ specific nodes
            "class_specifier" => {
                self.handle_cpp_class(node);
            }
            "namespace_definition" => {
                self.handle_cpp_namespace(node);
            }
            "template_declaration" => {
                self.handle_cpp_template(node);
            }
            "function_definition" => {
                // Check if it's a method (inside class)
                self.handle_cpp_function(node);
            }
            // Fall through to C handling for common nodes
            _ => {
                // Try C handling first
                self.visit_c_node(node);
            }
        }
    }

    fn handle_cpp_class(&mut self, node: Node) {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = self.node_text(name_node);
            let location = self.node_location(name_node);

            let symbol = Symbol::new(
                name.clone(),
                SymbolKind::Class,
                self.table.current_scope_id(),
                location,
            )
            .with_type(TypeInfo::Object(name))
            .with_mutable(false);

            let _ = self.table.declare(symbol);
        }

        // Enter class scope
        self.table.enter_scope(ScopeKind::Class);

        // Visit base classes
        if let Some(bases) = node.child_by_field_name("bases") {
            self.visit_node(bases);
        }

        // Visit body (field declarations, method declarations)
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_cpp_namespace(&mut self, node: Node) {
        let name = if let Some(name_node) = node.child_by_field_name("name") {
            self.node_text(name_node)
        } else {
            // Anonymous namespace
            "(anonymous)".to_string()
        };

        let location = self.node_location(node);

        let symbol = Symbol::new(
            name,
            SymbolKind::Module,
            self.table.current_scope_id(),
            location,
        )
        .with_mutable(false);

        let _ = self.table.declare(symbol);

        // Enter namespace scope
        self.table.enter_scope(ScopeKind::Module);

        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_cpp_template(&mut self, node: Node) {
        // Enter template scope
        self.table.enter_scope(ScopeKind::Block);

        // Handle template parameters
        if let Some(params) = node.child_by_field_name("parameters") {
            let mut cursor = params.walk();
            for child in params.children(&mut cursor) {
                if child.kind() == "type_parameter_declaration"
                    || child.kind() == "parameter_declaration"
                {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = self.node_text(name_node);
                        let location = self.node_location(name_node);

                        let symbol = Symbol::new(
                            name,
                            SymbolKind::TypeAlias,
                            self.table.current_scope_id(),
                            location,
                        )
                        .with_mutable(false);

                        let _ = self.table.declare(symbol);
                    }
                }
            }
        }

        // Visit the declaration being templated
        self.visit_children(node);

        let _ = self.table.exit_scope();
    }

    fn handle_cpp_function(&mut self, node: Node) {
        // Similar to C but handles C++ features
        if let Some(declarator) = node.child_by_field_name("declarator") {
            self.handle_cpp_function_declarator(declarator);
        }

        // Enter function scope
        self.table.enter_scope(ScopeKind::Function);

        // Handle parameters
        if let Some(declarator) = node.child_by_field_name("declarator") {
            self.handle_cpp_function_parameters(declarator);
        }

        // Visit body
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_node(body);
        }

        let _ = self.table.exit_scope();
    }

    fn handle_cpp_function_declarator(&mut self, node: Node) {
        // Get function name from declarator (handles C++ features like ::)
        match node.kind() {
            "function_declarator" | "qualified_identifier" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    self.handle_cpp_function_declarator(name_node);
                } else if let Some(decl) = node.child_by_field_name("declarator") {
                    self.handle_cpp_function_declarator(decl);
                }
            }
            "identifier" | "field_identifier" | "destructor_name" => {
                let name = self.node_text(node);
                let location = self.node_location(node);

                let symbol = Symbol::new(
                    name,
                    SymbolKind::Function,
                    self.table.current_scope_id(),
                    location,
                )
                .with_mutable(false);

                let _ = self.table.declare(symbol);
            }
            "pointer_declarator" | "reference_declarator" => {
                if let Some(decl) = node.child_by_field_name("declarator") {
                    self.handle_cpp_function_declarator(decl);
                }
            }
            _ => {}
        }
    }

    fn handle_cpp_function_parameters(&mut self, node: Node) {
        // Extract parameter declarations
        if node.kind() == "function_declarator" {
            if let Some(params) = node.child_by_field_name("parameters") {
                let mut cursor = params.walk();
                for child in params.children(&mut cursor) {
                    if child.kind() == "parameter_declaration"
                        || child.kind() == "optional_parameter_declaration"
                    {
                        self.handle_cpp_parameter(child);
                    }
                }
            }
        }
    }

    fn handle_cpp_parameter(&mut self, node: Node) {
        // Get parameter name
        if let Some(declarator) = node.child_by_field_name("declarator") {
            self.extract_cpp_identifier(declarator, SymbolKind::Parameter);
        }
    }

    fn extract_cpp_identifier(&mut self, node: Node, kind: SymbolKind) {
        match node.kind() {
            "identifier" | "field_identifier" => {
                let name = self.node_text(node);
                let location = self.node_location(node);

                let symbol = Symbol::new(name, kind, self.table.current_scope_id(), location);

                let _ = self.table.declare(symbol);
            }
            "pointer_declarator" | "reference_declarator" | "array_declarator" => {
                if let Some(decl) = node.child_by_field_name("declarator") {
                    self.extract_cpp_identifier(decl, kind);
                }
            }
            "function_declarator" => {
                if let Some(decl) = node.child_by_field_name("declarator") {
                    self.extract_cpp_identifier(decl, kind);
                }
            }
            "qualified_identifier" => {
                // For qualified names, use the final part
                if let Some(name_node) = node.child_by_field_name("name") {
                    self.extract_cpp_identifier(name_node, kind);
                }
            }
            _ => {}
        }
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
    use super::{ScopeKind, Symbol, SymbolKind, SymbolTable, TypeInfo};
    use crate::domain::finding::{Location, TaintState};

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
        let local_y = Symbol::new(
            "y",
            SymbolKind::Variable,
            table.current_scope_id(),
            loc.clone(),
        );
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
        let symbol = Symbol::new("items", SymbolKind::Variable, 0, loc).with_type(TypeInfo::List(
            Box::new(TypeInfo::Primitive("str".to_string())),
        ));

        assert!(matches!(symbol.type_info, Some(TypeInfo::List(_))));
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
