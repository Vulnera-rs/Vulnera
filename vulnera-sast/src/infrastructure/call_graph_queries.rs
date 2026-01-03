//! Tree-sitter queries for building the call graph
//!
//! These queries are used to extract function definitions and function calls
//! from source code with parameter extraction and class context.

// =============================================================================
// Python Queries
// =============================================================================

pub const PYTHON_DEFINITIONS: &str = r#"
(function_definition
  name: (identifier) @name
) @definition

(class_definition
  name: (identifier) @name
) @class_definition
"#;

/// Python parameter extraction query
pub const PYTHON_PARAMETERS: &str = r#"
(function_definition
  name: (identifier) @name
  parameters: (parameters
    (identifier) @param.name
  )?
) @function_with_params

(function_definition
  name: (identifier) @name
  parameters: (parameters
    (typed_parameter
      (identifier) @param.name
      type: (type) @param.type
    )
  )?
) @function_with_typed_params

(function_definition
  name: (identifier) @name
  parameters: (parameters
    (default_parameter
      name: (identifier) @param.name
    )
  )?
) @function_with_default_params
"#;

/// Python class method context query
pub const PYTHON_CLASS_METHODS: &str = r#"
(class_definition
  name: (identifier) @class.name
  body: (block
    (function_definition
      name: (identifier) @method.name
    ) @method
  )
) @class_with_methods
"#;

pub const PYTHON_CALLS: &str = r#"
(call
  function: (identifier) @name
) @call

(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method
  )
) @method_call
"#;

// =============================================================================
// JavaScript Queries
// =============================================================================

pub const JAVASCRIPT_DEFINITIONS: &str = r#"
(function_declaration
  name: (identifier) @name
) @definition

(class_declaration
  name: (identifier) @name
) @class_definition

(method_definition
  name: (property_identifier) @name
) @method_definition

(arrow_function) @arrow_function
"#;

/// JavaScript parameter extraction query
pub const JAVASCRIPT_PARAMETERS: &str = r#"
(function_declaration
  name: (identifier) @name
  parameters: (formal_parameters
    (identifier) @param.name
  )
) @function_with_params

(method_definition
  name: (property_identifier) @name
  parameters: (formal_parameters
    (identifier) @param.name
  )
) @method_with_params

(arrow_function
  parameters: (formal_parameters
    (identifier) @param.name
  )
) @arrow_with_params
"#;

/// JavaScript class method context query
pub const JAVASCRIPT_CLASS_METHODS: &str = r#"
(class_declaration
  name: (identifier) @class.name
  body: (class_body
    (method_definition
      name: (property_identifier) @method.name
    ) @method
  )
) @class_with_methods
"#;

pub const JAVASCRIPT_CALLS: &str = r#"
(call_expression
  function: (identifier) @name
) @call

(call_expression
  function: (member_expression
    property: (property_identifier) @name
  )
) @method_call

(new_expression
  constructor: (identifier) @name
) @constructor_call
"#;

// =============================================================================
// TypeScript Queries
// =============================================================================

pub const TYPESCRIPT_DEFINITIONS: &str = r#"
(function_declaration
  name: (identifier) @name
) @definition

(class_declaration
  name: (type_identifier) @name
) @class_definition

(method_definition
  name: (property_identifier) @name
) @method_definition

(abstract_method_signature
  name: (property_identifier) @name
) @interface_method
"#;

/// TypeScript parameter extraction query
pub const TYPESCRIPT_PARAMETERS: &str = r#"
(function_declaration
  name: (identifier) @name
  parameters: (formal_parameters
    (required_parameter
      pattern: (identifier) @param.name
      type: (type_annotation (type_identifier) @param.type)?
    )
  )
) @function_with_params

(method_definition
  name: (property_identifier) @name
  parameters: (formal_parameters
    (required_parameter
      pattern: (identifier) @param.name
    )
  )
) @method_with_params
"#;

/// TypeScript class method context query
pub const TYPESCRIPT_CLASS_METHODS: &str = r#"
(class_declaration
  name: (type_identifier) @class.name
  body: (class_body
    (method_definition
      name: (property_identifier) @method.name
    ) @method
  )
) @class_with_methods
"#;

pub const TYPESCRIPT_CALLS: &str = r#"
(call_expression
  function: (identifier) @name
) @call

(call_expression
  function: (member_expression
    property: (property_identifier) @name
  )
) @method_call

(new_expression
  constructor: (identifier) @name
) @constructor_call
"#;

// =============================================================================
// Rust Queries
// =============================================================================

pub const RUST_DEFINITIONS: &str = r#"
(function_item
  name: (identifier) @name
) @definition

(impl_item
  type: (type_identifier) @type
) @impl_block
"#;

/// Rust parameter extraction query
pub const RUST_PARAMETERS: &str = r#"
(function_item
  name: (identifier) @name
  parameters: (parameters
    (parameter
      pattern: (identifier) @param.name
      type: (type_identifier) @param.type
    )
  )
) @function_with_params
"#;

/// Rust impl block method context query
pub const RUST_IMPL_METHODS: &str = r#"
(impl_item
  type: (type_identifier) @type.name
  body: (declaration_list
    (function_item
      name: (identifier) @method.name
    ) @method
  )
) @impl_with_methods
"#;

pub const RUST_CALLS: &str = r#"
(call_expression
  function: (identifier) @name
) @call

(call_expression
  function: (field_expression
    field: (field_identifier) @name
  )
) @method_call

(call_expression
  function: (scoped_identifier
    name: (identifier) @name
  )
) @scoped_call
"#;

// =============================================================================
// Go Queries
// =============================================================================

pub const GO_DEFINITIONS: &str = r#"
(function_declaration
  name: (identifier) @name
) @definition

(method_declaration
  name: (field_identifier) @name
) @method_definition
"#;

/// Go parameter extraction query
pub const GO_PARAMETERS: &str = r#"
(function_declaration
  name: (identifier) @name
  parameters: (parameter_list
    (parameter_declaration
      name: (identifier) @param.name
      type: (type_identifier) @param.type
    )
  )
) @function_with_params

(method_declaration
  receiver: (parameter_list
    (parameter_declaration
      name: (identifier) @receiver.name
      type: (_) @receiver.type
    )
  )
  name: (field_identifier) @name
) @method_with_receiver
"#;

/// Go struct method context query (via method receiver)
pub const GO_STRUCT_METHODS: &str = r#"
(method_declaration
  receiver: (parameter_list
    (parameter_declaration
      type: (pointer_type (type_identifier) @struct.name)
    )
  )
  name: (field_identifier) @method.name
) @struct_method_pointer

(method_declaration
  receiver: (parameter_list
    (parameter_declaration
      type: (type_identifier) @struct.name
    )
  )
  name: (field_identifier) @method.name
) @struct_method_value
"#;

pub const GO_CALLS: &str = r#"
(call_expression
  function: (identifier) @name
) @call

(call_expression
  function: (selector_expression
    field: (field_identifier) @name
  )
) @method_call
"#;

// =============================================================================
// C Queries
// =============================================================================

pub const C_DEFINITIONS: &str = r#"
(function_definition
  declarator: (function_declarator
    declarator: (identifier) @name
  )
) @definition
"#;

/// C parameter extraction query
pub const C_PARAMETERS: &str = r#"
(function_definition
  declarator: (function_declarator
    declarator: (identifier) @name
    parameters: (parameter_list
      (parameter_declaration
        declarator: (identifier) @param.name
        type: (type_identifier) @param.type
      )
    )
  )
) @function_with_params
"#;

pub const C_CALLS: &str = r#"
(call_expression
  function: (identifier) @name
) @call
"#;

// =============================================================================
// C++ Queries
// =============================================================================

pub const CPP_DEFINITIONS: &str = r#"
(function_definition
  declarator: (function_declarator
    declarator: (identifier) @name
  )
) @definition

(function_definition
  declarator: (function_declarator
    declarator: (field_identifier) @name
  )
) @method_definition
"#;

/// C++ parameter extraction query
pub const CPP_PARAMETERS: &str = r#"
(function_definition
  declarator: (function_declarator
    declarator: (identifier) @name
    parameters: (parameter_list
      (parameter_declaration
        declarator: (identifier) @param.name
      )
    )
  )
) @function_with_params
"#;

/// C++ class method context query
pub const CPP_CLASS_METHODS: &str = r#"
(class_specifier
  name: (type_identifier) @class.name
  body: (field_declaration_list
    (function_definition
      declarator: (function_declarator
        declarator: (field_identifier) @method.name
      )
    ) @method
  )
) @class_with_methods
"#;

pub const CPP_CALLS: &str = r#"
(call_expression
  function: (identifier) @name
) @call

(call_expression
  function: (field_expression
    field: (field_identifier) @name
  )
) @method_call
"#;
