//! Call graph types for inter-procedural analysis
//!
//! Types for representing function call relationships.

use serde::{Deserialize, Serialize};

/// A node in the call graph representing a function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphNode {
    /// Unique identifier (fully qualified name)
    pub id: String,
    /// Function signature
    pub signature: FunctionSignature,
    /// File containing this function
    pub file_path: String,
    /// Start line in source
    pub start_line: u32,
    /// End line in source
    pub end_line: u32,
}

/// Function signature for call graph nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    /// Function name
    pub name: String,
    /// Module path (e.g., "mypackage.mymodule")
    pub module_path: Option<String>,
    /// Parameter names and types
    pub parameters: Vec<ParameterInfo>,
    /// Return type (if known)
    pub return_type: Option<String>,
}

impl FunctionSignature {
    /// Get fully qualified name
    pub fn fully_qualified_name(&self) -> String {
        match &self.module_path {
            Some(path) => format!("{}.{}", path, self.name),
            None => self.name.clone(),
        }
    }
}

/// Parameter information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterInfo {
    /// Parameter name
    pub name: String,
    /// Parameter type (if known)
    pub type_hint: Option<String>,
    /// Default value (if any)
    pub default_value: Option<String>,
}

/// A call site (where a function is called)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    /// ID of the called function
    pub target_id: String,
    /// Name of the called function (for display)
    pub target_name: String,
    /// Arguments passed to the call
    pub arguments: Vec<ArgumentInfo>,
    /// Line of the call
    pub line: u32,
    /// Column of the call
    pub column: u32,
}

/// Argument information at a call site
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgumentInfo {
    /// Argument expression (source text)
    pub expression: String,
    /// Whether this argument is tainted
    pub is_tainted: bool,
}
