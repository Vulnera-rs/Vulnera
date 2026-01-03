//! Tree-sitter queries for building the call graph
//!
//! These queries are used to extract function definitions and function calls
//! from source code references.

pub const PYTHON_DEFINITIONS: &str = r#"
(function_definition
  name: (identifier) @name
) @definition

(class_definition
  name: (identifier) @name
) @class_definition
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

pub const RUST_DEFINITIONS: &str = r#"
(function_item
  name: (identifier) @name
) @definition

(impl_item
  type: (type_identifier) @type
) @impl_block
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

pub const GO_DEFINITIONS: &str = r#"
(function_declaration
  name: (identifier) @name
) @definition

(method_declaration
  name: (field_identifier) @name
) @method_definition
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

pub const C_DEFINITIONS: &str = r#"
(function_definition
  declarator: (function_declarator
    declarator: (identifier) @name
  )
) @definition
"#;

pub const C_CALLS: &str = r#"
(call_expression
  function: (identifier) @name
) @call
"#;

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
