//! Production-ready taint detection queries
//!
//! Tree-sitter S-expression queries for detecting:
//! - Taint sources (user input, file I/O, environment)
//! - Taint sinks (dangerous functions where tainted data is risky)
//! - Sanitizers (functions that clean/validate tainted data)
//!
//! Supports custom patterns via TaintConfig for framework-specific sources.

use crate::domain::value_objects::Language;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// TaintConfig - Customizable taint patterns
// =============================================================================

/// Configuration for taint tracking with custom sources/sinks/sanitizers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintConfig {
    /// Custom taint sources per language
    #[serde(default)]
    pub custom_sources: HashMap<String, Vec<TaintPattern>>,
    /// Custom taint sinks per language
    #[serde(default)]
    pub custom_sinks: HashMap<String, Vec<TaintPattern>>,
    /// Custom sanitizers per language
    #[serde(default)]
    pub custom_sanitizers: HashMap<String, Vec<TaintPattern>>,
    /// Whether to include built-in patterns
    #[serde(default = "default_true")]
    pub include_builtin: bool,
    /// Confidence threshold for generic validation (0.0-1.0)
    /// Generic validators reduce confidence instead of clearing taint
    #[serde(default = "default_generic_confidence")]
    pub generic_validation_confidence: f32,
}

fn default_true() -> bool {
    true
}

fn default_generic_confidence() -> f32 {
    0.5
}

impl Default for TaintConfig {
    fn default() -> Self {
        Self {
            custom_sources: HashMap::new(),
            custom_sinks: HashMap::new(),
            custom_sanitizers: HashMap::new(),
            include_builtin: true,
            generic_validation_confidence: 0.5,
        }
    }
}

/// A taint pattern with query and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPattern {
    /// Tree-sitter S-expression query
    pub query: String,
    /// Human-readable name
    pub name: String,
    /// Category (e.g., "user_input", "file_io", "sql", "xss")
    pub category: String,
    /// Whether this is a known/strong pattern (vs generic)
    /// Known sanitizers clear taint; generic ones only reduce confidence
    #[serde(default = "default_true")]
    pub is_known: bool,
    /// Labels that this pattern introduces (for labeled taint tracking)
    #[serde(default)]
    pub labels: Vec<String>,
    /// For sanitizers: which labels this clears (None = all)
    #[serde(default)]
    pub clears_labels: Option<Vec<String>>,
}

impl TaintPattern {
    /// Create a new source pattern
    pub fn source(query: &str, name: &str, category: &str, labels: Vec<&str>) -> Self {
        Self {
            query: query.to_string(),
            name: name.to_string(),
            category: category.to_string(),
            is_known: true,
            labels: labels.into_iter().map(|s| s.to_string()).collect(),
            clears_labels: None,
        }
    }

    /// Create a new sink pattern
    pub fn sink(query: &str, name: &str, category: &str) -> Self {
        Self {
            query: query.to_string(),
            name: name.to_string(),
            category: category.to_string(),
            is_known: true,
            labels: vec![],
            clears_labels: None,
        }
    }

    /// Create a known sanitizer that clears taint
    pub fn sanitizer(query: &str, name: &str, category: &str) -> Self {
        Self {
            query: query.to_string(),
            name: name.to_string(),
            category: category.to_string(),
            is_known: true,
            labels: vec![],
            clears_labels: Some(vec![]), // Empty = clears all labels
        }
    }

    /// Create a generic sanitizer that only reduces confidence
    pub fn generic_sanitizer(query: &str, name: &str, category: &str) -> Self {
        Self {
            query: query.to_string(),
            name: name.to_string(),
            category: category.to_string(),
            is_known: false, // Generic = reduce confidence only
            labels: vec![],
            clears_labels: None, // None = doesn't clear, just reduces confidence
        }
    }
}

// =============================================================================
// Query Result Types
// =============================================================================

/// Result of a taint detection query
#[derive(Debug, Clone)]
pub struct TaintDetection {
    /// Type of detection
    pub detection_type: TaintDetectionType,
    /// Pattern name that matched
    pub pattern_name: String,
    /// Category of the taint
    pub category: String,
    /// Line number (1-indexed)
    pub line: u32,
    /// Column number
    pub column: u32,
    /// End line
    pub end_line: u32,
    /// End column
    pub end_column: u32,
    /// The matched expression/variable
    pub expression: String,
    /// Labels associated with this detection
    pub labels: Vec<String>,
    /// Whether this is a known pattern (vs generic heuristic)
    pub is_known: bool,
    /// For sanitizers: which labels this clears
    pub clears_labels: Option<Vec<String>>,
}

/// Type of taint detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintDetectionType {
    Source,
    Sink,
    Sanitizer,
}

// =============================================================================
// Built-in Queries - Python
// =============================================================================

/// Python taint source queries
pub fn python_source_queries() -> Vec<TaintPattern> {
    vec![
        // Flask request attributes
        TaintPattern::source(
            r#"(attribute
              object: (identifier) @obj
              attribute: (identifier) @attr
              (#eq? @obj "request")
              (#match? @attr "^(form|args|values|data|json|files|cookies|headers|get_json)$")
            ) @source"#,
            "Flask request data",
            "user_input",
            vec!["user_input", "web_request"],
        ),
        // FastAPI/Starlette path/query parameters
        TaintPattern::source(
            r#"(default_parameter
              name: (identifier) @param
              value: (call
                function: (identifier) @fn
                (#match? @fn "^(Query|Path|Body|Cookie|Header|Form|File)$"))
            ) @source"#,
            "FastAPI parameter",
            "user_input",
            vec!["user_input", "web_request"],
        ),
        // Django request
        TaintPattern::source(
            r#"(subscript
              value: (attribute
                object: (identifier) @obj
                attribute: (identifier) @attr)
              (#eq? @obj "request")
              (#match? @attr "^(GET|POST|FILES|COOKIES|META|body|data)$")
            ) @source"#,
            "Django request data",
            "user_input",
            vec!["user_input", "web_request"],
        ),
        // sys.argv access
        TaintPattern::source(
            r#"(subscript
              value: (attribute
                object: (identifier) @mod
                attribute: (identifier) @attr)
              (#eq? @mod "sys")
              (#eq? @attr "argv")
            ) @source"#,
            "Command line argument",
            "cli_input",
            vec!["user_input", "cli"],
        ),
        // os.environ access
        TaintPattern::source(
            r#"(subscript
              value: (attribute
                object: (identifier) @mod
                attribute: (identifier) @attr)
              (#eq? @mod "os")
              (#eq? @attr "environ")
            ) @source"#,
            "Environment variable",
            "environment",
            vec!["environment"],
        ),
        // os.getenv
        TaintPattern::source(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @fn)
              (#eq? @mod "os")
              (#eq? @fn "getenv")
            ) @source"#,
            "os.getenv",
            "environment",
            vec!["environment"],
        ),
        // input() builtin
        TaintPattern::source(
            r#"(call
              function: (identifier) @fn
              (#eq? @fn "input")
            ) @source"#,
            "input() builtin",
            "user_input",
            vec!["user_input"],
        ),
        // File read operations
        TaintPattern::source(
            r#"(call
              function: (attribute
                attribute: (identifier) @method)
              (#match? @method "^(read|readline|readlines)$")
            ) @source"#,
            "File read",
            "file_io",
            vec!["file_input"],
        ),
    ]
}

/// Python taint sink queries
pub fn python_sink_queries() -> Vec<TaintPattern> {
    vec![
        // SQL execution - execute/executemany with concatenation
        TaintPattern::sink(
            r#"(call
              function: (attribute
                attribute: (identifier) @method)
              arguments: (argument_list
                (binary_operator) @query)
              (#match? @method "^(execute|executemany|executescript)$")
            ) @sink"#,
            "SQL execution with concatenation",
            "sql_injection",
        ),
        // SQL execution - f-string
        TaintPattern::sink(
            r#"(call
              function: (attribute
                attribute: (identifier) @method)
              arguments: (argument_list
                (string
                  (interpolation)))
              (#match? @method "^(execute|executemany)$")
            ) @sink"#,
            "SQL execution with f-string",
            "sql_injection",
        ),
        // eval/exec with variable
        TaintPattern::sink(
            r#"(call
              function: (identifier) @fn
              arguments: (argument_list
                (identifier) @arg)
              (#match? @fn "^(eval|exec|compile)$")
            ) @sink"#,
            "Code execution",
            "code_injection",
        ),
        // subprocess with shell=True
        TaintPattern::sink(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @method)
              arguments: (argument_list
                (keyword_argument
                  name: (identifier) @kw
                  value: (true)))
              (#eq? @mod "subprocess")
              (#match? @method "^(run|call|Popen|check_output|check_call)$")
              (#eq? @kw "shell")
            ) @sink"#,
            "Subprocess with shell=True",
            "command_injection",
        ),
        // os.system with variable
        TaintPattern::sink(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @method)
              arguments: (argument_list
                (identifier) @arg)
              (#eq? @mod "os")
              (#eq? @method "system")
            ) @sink"#,
            "os.system",
            "command_injection",
        ),
        // Template rendering (SSTI)
        TaintPattern::sink(
            r#"(call
              function: (attribute
                attribute: (identifier) @method)
              arguments: (argument_list
                (identifier) @arg)
              (#match? @method "^(render|render_template_string)$")
            ) @sink"#,
            "Template rendering",
            "ssti",
        ),
        // YAML unsafe load
        TaintPattern::sink(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @method)
              (#eq? @mod "yaml")
              (#match? @method "^(load|unsafe_load)$")
            ) @sink"#,
            "Unsafe YAML load",
            "deserialization",
        ),
        // Pickle load
        TaintPattern::sink(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @method)
              (#eq? @mod "pickle")
              (#match? @method "^(load|loads)$")
            ) @sink"#,
            "Pickle deserialization",
            "deserialization",
        ),
        // Path traversal - open()
        TaintPattern::sink(
            r#"(call
              function: (identifier) @fn
              arguments: (argument_list
                (identifier) @path)
              (#eq? @fn "open")
            ) @sink"#,
            "File open with variable path",
            "path_traversal",
        ),
        // SSRF - requests
        TaintPattern::sink(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @method)
              arguments: (argument_list
                (identifier) @url)
              (#eq? @mod "requests")
              (#match? @method "^(get|post|put|delete|patch|head|options)$")
            ) @sink"#,
            "HTTP request with variable URL",
            "ssrf",
        ),
    ]
}

/// Python sanitizer queries
pub fn python_sanitizer_queries() -> Vec<TaintPattern> {
    vec![
        // html.escape - known XSS sanitizer
        TaintPattern::sanitizer(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @method)
              (#eq? @mod "html")
              (#eq? @method "escape")
            ) @sanitizer"#,
            "html.escape",
            "xss",
        ),
        // bleach.clean - known XSS sanitizer
        TaintPattern::sanitizer(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @method)
              (#eq? @mod "bleach")
              (#eq? @method "clean")
            ) @sanitizer"#,
            "bleach.clean",
            "xss",
        ),
        // urllib.parse.quote - URL encoding
        TaintPattern::sanitizer(
            r#"(call
              function: (attribute
                attribute: (identifier) @method)
              (#match? @method "^(quote|quote_plus|urlencode)$")
            ) @sanitizer"#,
            "URL encoding",
            "url",
        ),
        // Parameterized query (with placeholders)
        TaintPattern::sanitizer(
            r#"(call
              function: (attribute
                attribute: (identifier) @method)
              arguments: (argument_list
                (string) @query
                [(tuple) (list)] @params)
              (#match? @method "^(execute|executemany)$")
            ) @sanitizer"#,
            "Parameterized SQL query",
            "sql",
        ),
        // shlex.quote for command injection
        TaintPattern::sanitizer(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @method)
              (#eq? @mod "shlex")
              (#eq? @method "quote")
            ) @sanitizer"#,
            "shlex.quote",
            "command",
        ),
        // int()/float() type coercion
        TaintPattern::sanitizer(
            r#"(call
              function: (identifier) @fn
              (#match? @fn "^(int|float|bool)$")
            ) @sanitizer"#,
            "Type coercion",
            "type_coercion",
        ),
        // Generic validation (reduces confidence, doesn't clear)
        TaintPattern::generic_sanitizer(
            r#"(call
              function: (identifier) @fn
              (#match? @fn "^(validate|sanitize|clean|escape|encode|filter)$")
            ) @sanitizer"#,
            "Generic validation function",
            "generic",
        ),
        // Generic validation via method call
        TaintPattern::generic_sanitizer(
            r#"(call
              function: (attribute
                attribute: (identifier) @method)
              (#match? @method "^(validate|sanitize|clean|escape|encode|filter|strip)$")
            ) @sanitizer"#,
            "Generic validation method",
            "generic",
        ),
    ]
}

// =============================================================================
// Built-in Queries - JavaScript/TypeScript
// =============================================================================

/// JavaScript taint source queries
pub fn javascript_source_queries() -> Vec<TaintPattern> {
    vec![
        // Express request properties
        TaintPattern::source(
            r#"(member_expression
              object: (identifier) @req
              property: (property_identifier) @prop
              (#match? @req "^(req|request)$")
              (#match? @prop "^(body|query|params|cookies|headers|files)$")
            ) @source"#,
            "Express request data",
            "user_input",
            vec!["user_input", "web_request"],
        ),
        // document.location / window.location
        TaintPattern::source(
            r#"(member_expression
              object: (identifier) @obj
              property: (property_identifier) @prop
              (#match? @obj "^(document|window)$")
              (#match? @prop "^(location|URL|referrer|cookie|hash|search)$")
            ) @source"#,
            "DOM location/URL",
            "user_input",
            vec!["user_input", "dom"],
        ),
        // process.env
        TaintPattern::source(
            r#"(member_expression
              object: (member_expression
                object: (identifier) @obj
                property: (property_identifier) @prop)
              (#eq? @obj "process")
              (#eq? @prop "env")
            ) @source"#,
            "Environment variable",
            "environment",
            vec!["environment"],
        ),
        // process.argv
        TaintPattern::source(
            r#"(member_expression
              object: (identifier) @obj
              property: (property_identifier) @prop
              (#eq? @obj "process")
              (#eq? @prop "argv")
            ) @source"#,
            "Command line argument",
            "cli_input",
            vec!["user_input", "cli"],
        ),
        // URLSearchParams.get
        TaintPattern::source(
            r#"(call_expression
              function: (member_expression
                property: (property_identifier) @method)
              (#match? @method "^(get|getAll)$")
            ) @source"#,
            "URL search params",
            "user_input",
            vec!["user_input", "url"],
        ),
        // fs.readFile
        TaintPattern::source(
            r#"(call_expression
              function: (member_expression
                object: (identifier) @mod
                property: (property_identifier) @method)
              (#eq? @mod "fs")
              (#match? @method "^(readFile|readFileSync|read|readSync)$")
            ) @source"#,
            "File read",
            "file_io",
            vec!["file_input"],
        ),
    ]
}

/// JavaScript taint sink queries
pub fn javascript_sink_queries() -> Vec<TaintPattern> {
    vec![
        // innerHTML assignment
        TaintPattern::sink(
            r#"(assignment_expression
              left: (member_expression
                property: (property_identifier) @prop)
              right: (identifier) @value
              (#eq? @prop "innerHTML")
            ) @sink"#,
            "innerHTML assignment",
            "xss",
        ),
        // document.write
        TaintPattern::sink(
            r#"(call_expression
              function: (member_expression
                object: (identifier) @obj
                property: (property_identifier) @method)
              arguments: (arguments
                (identifier) @arg)
              (#eq? @obj "document")
              (#match? @method "^(write|writeln)$")
            ) @sink"#,
            "document.write",
            "xss",
        ),
        // eval
        TaintPattern::sink(
            r#"(call_expression
              function: (identifier) @fn
              arguments: (arguments
                (identifier) @arg)
              (#eq? @fn "eval")
            ) @sink"#,
            "eval",
            "code_injection",
        ),
        // Function constructor
        TaintPattern::sink(
            r#"(new_expression
              constructor: (identifier) @fn
              arguments: (arguments
                (identifier) @arg)
              (#eq? @fn "Function")
            ) @sink"#,
            "Function constructor",
            "code_injection",
        ),
        // child_process.exec
        TaintPattern::sink(
            r#"(call_expression
              function: (member_expression
                object: (identifier) @mod
                property: (property_identifier) @method)
              arguments: (arguments
                (identifier) @arg)
              (#match? @mod "^(child_process|cp)$")
              (#match? @method "^(exec|execSync|spawn|spawnSync)$")
            ) @sink"#,
            "child_process execution",
            "command_injection",
        ),
        // SQL query with template string
        TaintPattern::sink(
            r#"(call_expression
              function: (member_expression
                property: (property_identifier) @method)
              arguments: (arguments
                (template_string) @query)
              (#match? @method "^(query|execute|run|all|get)$")
            ) @sink"#,
            "SQL query with template string",
            "sql_injection",
        ),
        // React dangerouslySetInnerHTML
        TaintPattern::sink(
            r#"(jsx_attribute
              (property_identifier) @attr
              (#eq? @attr "dangerouslySetInnerHTML")
            ) @sink"#,
            "dangerouslySetInnerHTML",
            "xss",
        ),
        // window.location.href assignment (open redirect)
        TaintPattern::sink(
            r#"(assignment_expression
              left: (member_expression
                property: (property_identifier) @prop)
              right: (identifier) @value
              (#eq? @prop "href")
            ) @sink"#,
            "Location href assignment",
            "open_redirect",
        ),
    ]
}

/// JavaScript sanitizer queries
pub fn javascript_sanitizer_queries() -> Vec<TaintPattern> {
    vec![
        // encodeURIComponent/encodeURI
        TaintPattern::sanitizer(
            r#"(call_expression
              function: (identifier) @fn
              (#match? @fn "^(encodeURIComponent|encodeURI)$")
            ) @sanitizer"#,
            "URL encoding",
            "url",
        ),
        // DOMPurify.sanitize
        TaintPattern::sanitizer(
            r#"(call_expression
              function: (member_expression
                object: (identifier) @lib
                property: (property_identifier) @method)
              (#eq? @lib "DOMPurify")
              (#eq? @method "sanitize")
            ) @sanitizer"#,
            "DOMPurify.sanitize",
            "xss",
        ),
        // textContent assignment (safe)
        TaintPattern::sanitizer(
            r#"(assignment_expression
              left: (member_expression
                property: (property_identifier) @prop)
              (#eq? @prop "textContent")
            ) @sanitizer"#,
            "textContent (safe)",
            "xss",
        ),
        // parseInt/parseFloat
        TaintPattern::sanitizer(
            r#"(call_expression
              function: (identifier) @fn
              (#match? @fn "^(parseInt|parseFloat|Number)$")
            ) @sanitizer"#,
            "Numeric conversion",
            "type_coercion",
        ),
        // Generic validation
        TaintPattern::generic_sanitizer(
            r#"(call_expression
              function: (identifier) @fn
              (#match? @fn "^(validate|sanitize|clean|escape|encode|filter|trim)$")
            ) @sanitizer"#,
            "Generic validation",
            "generic",
        ),
    ]
}

// =============================================================================
// Built-in Queries - Go
// =============================================================================

/// Go taint source queries
pub fn go_source_queries() -> Vec<TaintPattern> {
    vec![
        // http.Request body/form
        TaintPattern::source(
            r#"(selector_expression
              operand: (identifier) @req
              field: (field_identifier) @field
              (#match? @field "^(Body|Form|PostForm|URL|Header|Cookie)$")
            ) @source"#,
            "HTTP request data",
            "user_input",
            vec!["user_input", "web_request"],
        ),
        // os.Args
        TaintPattern::source(
            r#"(selector_expression
              operand: (identifier) @pkg
              field: (field_identifier) @field
              (#eq? @pkg "os")
              (#eq? @field "Args")
            ) @source"#,
            "Command line arguments",
            "cli_input",
            vec!["user_input", "cli"],
        ),
        // os.Getenv
        TaintPattern::source(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn)
              (#eq? @pkg "os")
              (#match? @fn "^(Getenv|LookupEnv)$")
            ) @source"#,
            "Environment variable",
            "environment",
            vec!["environment"],
        ),
        // ioutil.ReadAll / io.ReadAll
        TaintPattern::source(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn)
              (#match? @pkg "^(ioutil|io)$")
              (#eq? @fn "ReadAll")
            ) @source"#,
            "Read all from reader",
            "file_io",
            vec!["file_input"],
        ),
    ]
}

/// Go taint sink queries
pub fn go_sink_queries() -> Vec<TaintPattern> {
    vec![
        // exec.Command with variable
        TaintPattern::sink(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn)
              arguments: (argument_list
                (identifier) @arg)
              (#eq? @pkg "exec")
              (#eq? @fn "Command")
            ) @sink"#,
            "exec.Command",
            "command_injection",
        ),
        // SQL with concatenation
        TaintPattern::sink(
            r#"(call_expression
              function: (selector_expression
                field: (field_identifier) @method)
              arguments: (argument_list
                (binary_expression) @query)
              (#match? @method "^(Exec|Query|QueryRow)$")
            ) @sink"#,
            "SQL with concatenation",
            "sql_injection",
        ),
        // fmt.Fprintf to writer
        TaintPattern::sink(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn)
              (#eq? @pkg "fmt")
              (#match? @fn "^(Fprintf|Fprint|Fprintln)$")
            ) @sink"#,
            "fmt.Fprintf",
            "xss",
        ),
        // template.HTML casting
        TaintPattern::sink(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn)
              arguments: (argument_list
                (identifier) @arg)
              (#eq? @pkg "template")
              (#eq? @fn "HTML")
            ) @sink"#,
            "template.HTML",
            "xss",
        ),
        // File open with variable
        TaintPattern::sink(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn)
              arguments: (argument_list
                (identifier) @path)
              (#eq? @pkg "os")
              (#match? @fn "^(Open|OpenFile|Create)$")
            ) @sink"#,
            "File open with variable",
            "path_traversal",
        ),
    ]
}

/// Go sanitizer queries
pub fn go_sanitizer_queries() -> Vec<TaintPattern> {
    vec![
        // html.EscapeString
        TaintPattern::sanitizer(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn)
              (#eq? @pkg "html")
              (#eq? @fn "EscapeString")
            ) @sanitizer"#,
            "html.EscapeString",
            "xss",
        ),
        // url.QueryEscape
        TaintPattern::sanitizer(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn)
              (#eq? @pkg "url")
              (#match? @fn "^(QueryEscape|PathEscape)$")
            ) @sanitizer"#,
            "URL escape",
            "url",
        ),
        // filepath.Clean
        TaintPattern::sanitizer(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn)
              (#eq? @pkg "filepath")
              (#eq? @fn "Clean")
            ) @sanitizer"#,
            "filepath.Clean",
            "path",
        ),
        // strconv.Atoi
        TaintPattern::sanitizer(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn)
              (#eq? @pkg "strconv")
              (#match? @fn "^(Atoi|ParseInt|ParseFloat|ParseUint)$")
            ) @sanitizer"#,
            "Numeric conversion",
            "type_coercion",
        ),
    ]
}

// =============================================================================
// Built-in Queries - Rust
// =============================================================================

/// Rust taint source queries
pub fn rust_source_queries() -> Vec<TaintPattern> {
    vec![
        // std::env::args
        TaintPattern::source(
            r#"(call_expression
              function: (scoped_identifier) @path
              (#match? @path "env::(args|args_os)")
            ) @source"#,
            "Command line args",
            "cli_input",
            vec!["user_input", "cli"],
        ),
        // std::env::var
        TaintPattern::source(
            r#"(call_expression
              function: (scoped_identifier) @path
              (#match? @path "env::(var|var_os)")
            ) @source"#,
            "Environment variable",
            "environment",
            vec!["environment"],
        ),
        // stdin read
        TaintPattern::source(
            r#"(call_expression
              function: (field_expression
                field: (field_identifier) @method)
              (#match? @method "^(read_line|read_to_string|read|read_exact)$")
            ) @source"#,
            "stdin read",
            "user_input",
            vec!["user_input"],
        ),
        // Web framework extractors (Axum/Actix)
        TaintPattern::source(
            r#"(parameter
              pattern: (identifier) @param
              type: (generic_type
                type: (type_identifier) @type)
              (#match? @type "^(Json|Query|Path|Form|Bytes)$")
            ) @source"#,
            "Web framework extractor",
            "user_input",
            vec!["user_input", "web_request"],
        ),
    ]
}

/// Rust taint sink queries
pub fn rust_sink_queries() -> Vec<TaintPattern> {
    vec![
        // Command::new with variable
        TaintPattern::sink(
            r#"(call_expression
              function: (scoped_identifier) @path
              arguments: (arguments
                (identifier) @arg)
              (#match? @path "Command::new")
            ) @sink"#,
            "Command::new",
            "command_injection",
        ),
        // format! macro (context-dependent)
        TaintPattern {
            query: r#"(macro_invocation
              macro: (identifier) @macro
              (#match? @macro "^(format|concat)$")
            ) @sink"#
                .to_string(),
            name: "format! macro".to_string(),
            category: "sql_injection".to_string(),
            is_known: false, // Context-dependent, lower confidence
            labels: vec![],
            clears_labels: None,
        },
        // Raw HTML output
        TaintPattern::sink(
            r#"(call_expression
              function: (scoped_identifier) @path
              (#match? @path "^(PreEscaped|Raw|raw)$")
            ) @sink"#,
            "Raw HTML",
            "xss",
        ),
        // File open with variable
        TaintPattern::sink(
            r#"(call_expression
              function: (scoped_identifier) @path
              arguments: (arguments
                (identifier) @arg)
              (#match? @path "File::(open|create)")
            ) @sink"#,
            "File open",
            "path_traversal",
        ),
    ]
}

/// Rust sanitizer queries
pub fn rust_sanitizer_queries() -> Vec<TaintPattern> {
    vec![
        // html_escape
        TaintPattern::sanitizer(
            r#"(call_expression
              function: (scoped_identifier) @path
              (#match? @path "html_escape::(encode|encode_text)")
            ) @sanitizer"#,
            "html_escape",
            "xss",
        ),
        // ammonia::clean
        TaintPattern::sanitizer(
            r#"(call_expression
              function: (scoped_identifier) @path
              (#match? @path "ammonia::clean")
            ) @sanitizer"#,
            "ammonia::clean",
            "xss",
        ),
        // .parse::<T>()
        TaintPattern::sanitizer(
            r#"(call_expression
              function: (field_expression
                field: (field_identifier) @method)
              (#eq? @method "parse")
            ) @sanitizer"#,
            "parse::<T>",
            "type_coercion",
        ),
        // sqlx query! macro
        TaintPattern::sanitizer(
            r#"(macro_invocation
              macro: (identifier) @macro
              (#match? @macro "^(query|query_as|query_scalar)$")
            ) @sanitizer"#,
            "sqlx query! macro",
            "sql",
        ),
    ]
}

// =============================================================================
// Built-in Queries - C/C++
// =============================================================================

/// C taint source queries
pub fn c_source_queries() -> Vec<TaintPattern> {
    vec![
        // getenv
        TaintPattern::source(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "getenv")
            ) @source"#,
            "getenv",
            "environment",
            vec!["environment"],
        ),
        // gets/fgets/scanf
        TaintPattern::source(
            r#"(call_expression
              function: (identifier) @fn
              (#match? @fn "^(gets|fgets|scanf|fscanf|sscanf|read|recv|recvfrom|fread)$")
            ) @source"#,
            "Input function",
            "user_input",
            vec!["user_input"],
        ),
        // argv usage
        TaintPattern::source(
            r#"(subscript_expression
              argument: (identifier) @arg
              (#eq? @arg "argv")
            ) @source"#,
            "argv access",
            "cli_input",
            vec!["user_input", "cli"],
        ),
    ]
}

/// C taint sink queries
pub fn c_sink_queries() -> Vec<TaintPattern> {
    vec![
        // system
        TaintPattern::sink(
            r#"(call_expression
              function: (identifier) @fn
              arguments: (argument_list
                (identifier) @arg)
              (#eq? @fn "system")
            ) @sink"#,
            "system",
            "command_injection",
        ),
        // exec family
        TaintPattern::sink(
            r#"(call_expression
              function: (identifier) @fn
              arguments: (argument_list
                (identifier) @arg)
              (#match? @fn "^(execl|execlp|execle|execv|execvp|execvpe|popen)$")
            ) @sink"#,
            "exec family",
            "command_injection",
        ),
        // sprintf/strcpy (buffer overflow)
        TaintPattern::sink(
            r#"(call_expression
              function: (identifier) @fn
              (#match? @fn "^(sprintf|vsprintf|gets|strcpy|strcat)$")
            ) @sink"#,
            "Unsafe string function",
            "buffer_overflow",
        ),
        // printf format string
        TaintPattern::sink(
            r#"(call_expression
              function: (identifier) @fn
              arguments: (argument_list
                (identifier) @format)
              (#match? @fn "^(printf|fprintf|sprintf|snprintf|syslog)$")
            ) @sink"#,
            "Format string",
            "format_string",
        ),
        // SQL execution
        TaintPattern::sink(
            r#"(call_expression
              function: (identifier) @fn
              arguments: (argument_list
                (identifier) @query)
              (#match? @fn "^(mysql_query|sqlite3_exec|PQexec)$")
            ) @sink"#,
            "SQL execution",
            "sql_injection",
        ),
    ]
}

/// C sanitizer queries
pub fn c_sanitizer_queries() -> Vec<TaintPattern> {
    vec![
        // snprintf (bounded)
        TaintPattern::sanitizer(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "snprintf")
            ) @sanitizer"#,
            "snprintf",
            "buffer",
        ),
        // strncpy/strncat
        TaintPattern::sanitizer(
            r#"(call_expression
              function: (identifier) @fn
              (#match? @fn "^(strncpy|strncat|strlcpy|strlcat)$")
            ) @sanitizer"#,
            "Bounded string copy",
            "buffer",
        ),
        // Prepared statements
        TaintPattern::sanitizer(
            r#"(call_expression
              function: (identifier) @fn
              (#match? @fn "^(mysql_stmt_bind_param|sqlite3_bind_|PQexecParams)$")
            ) @sanitizer"#,
            "Prepared statement",
            "sql",
        ),
    ]
}

// =============================================================================
// Query Provider
// =============================================================================

/// Get all source queries for a language (built-in + custom)
pub fn get_source_queries(language: &Language, config: &TaintConfig) -> Vec<TaintPattern> {
    let mut queries = Vec::new();

    if config.include_builtin {
        queries.extend(match language {
            Language::Python => python_source_queries(),
            Language::JavaScript | Language::TypeScript => javascript_source_queries(),
            Language::Go => go_source_queries(),
            Language::Rust => rust_source_queries(),
            Language::C | Language::Cpp => c_source_queries(),
        });
    }

    // Add custom sources
    let lang_key = format!("{:?}", language).to_lowercase();
    if let Some(custom) = config.custom_sources.get(&lang_key) {
        queries.extend(custom.clone());
    }

    queries
}

/// Get all sink queries for a language (built-in + custom)
pub fn get_sink_queries(language: &Language, config: &TaintConfig) -> Vec<TaintPattern> {
    let mut queries = Vec::new();

    if config.include_builtin {
        queries.extend(match language {
            Language::Python => python_sink_queries(),
            Language::JavaScript | Language::TypeScript => javascript_sink_queries(),
            Language::Go => go_sink_queries(),
            Language::Rust => rust_sink_queries(),
            Language::C | Language::Cpp => c_sink_queries(),
        });
    }

    // Add custom sinks
    let lang_key = format!("{:?}", language).to_lowercase();
    if let Some(custom) = config.custom_sinks.get(&lang_key) {
        queries.extend(custom.clone());
    }

    queries
}

/// Get all sanitizer queries for a language (built-in + custom)
pub fn get_sanitizer_queries(language: &Language, config: &TaintConfig) -> Vec<TaintPattern> {
    let mut queries = Vec::new();

    if config.include_builtin {
        queries.extend(match language {
            Language::Python => python_sanitizer_queries(),
            Language::JavaScript | Language::TypeScript => javascript_sanitizer_queries(),
            Language::Go => go_sanitizer_queries(),
            Language::Rust => rust_sanitizer_queries(),
            Language::C | Language::Cpp => c_sanitizer_queries(),
        });
    }

    // Add custom sanitizers
    let lang_key = format!("{:?}", language).to_lowercase();
    if let Some(custom) = config.custom_sanitizers.get(&lang_key) {
        queries.extend(custom.clone());
    }

    queries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TaintConfig::default();
        assert!(config.include_builtin);
        assert!(config.custom_sources.is_empty());
        assert!((config.generic_validation_confidence - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn test_python_sources_not_empty() {
        let sources = python_source_queries();
        assert!(!sources.is_empty());
        assert!(sources.iter().any(|s| s.category == "user_input"));
    }

    #[test]
    fn test_python_sinks_not_empty() {
        let sinks = python_sink_queries();
        assert!(!sinks.is_empty());
        assert!(sinks.iter().any(|s| s.category == "sql_injection"));
    }

    #[test]
    fn test_python_sanitizers_not_empty() {
        let sanitizers = python_sanitizer_queries();
        assert!(!sanitizers.is_empty());
        // Check we have both known and generic sanitizers
        assert!(sanitizers.iter().any(|s| s.is_known));
        assert!(sanitizers.iter().any(|s| !s.is_known));
    }

    #[test]
    fn test_get_queries_with_custom() {
        let mut config = TaintConfig::default();
        config.custom_sources.insert(
            "python".to_string(),
            vec![TaintPattern::source(
                "(identifier) @custom",
                "Custom source",
                "custom",
                vec!["custom"],
            )],
        );

        let sources = get_source_queries(&Language::Python, &config);
        assert!(sources.iter().any(|s| s.name == "Custom source"));
    }

    #[test]
    fn test_sanitizer_types() {
        // Known sanitizer should have clears_labels
        let known = TaintPattern::sanitizer("query", "test", "xss");
        assert!(known.is_known);
        assert!(known.clears_labels.is_some());

        // Generic sanitizer should NOT clear labels
        let generic = TaintPattern::generic_sanitizer("query", "test", "generic");
        assert!(!generic.is_known);
        assert!(generic.clears_labels.is_none());
    }

    #[test]
    fn test_all_languages_have_queries() {
        let config = TaintConfig::default();
        let languages = vec![
            Language::Python,
            Language::JavaScript,
            Language::TypeScript,
            Language::Go,
            Language::Rust,
            Language::C,
            Language::Cpp,
        ];

        for lang in languages {
            let sources = get_source_queries(&lang, &config);
            let sinks = get_sink_queries(&lang, &config);
            let sanitizers = get_sanitizer_queries(&lang, &config);

            assert!(!sources.is_empty(), "No sources for {:?}", lang);
            assert!(!sinks.is_empty(), "No sinks for {:?}", lang);
            assert!(!sanitizers.is_empty(), "No sanitizers for {:?}", lang);
        }
    }
}
