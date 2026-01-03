//! Metavariable Pattern Support
//!
//! This module provides parsing and translation of Semgrep-style metavariable
//! patterns into tree-sitter queries.
//!
//! # Supported Syntax
//! - `$VAR` - matches any single expression
//! - `foo($ARG)` - matches function call with captured argument
//! - `$X + $Y` - matches binary expression with captured operands

use std::collections::HashMap;

use crate::domain::value_objects::Language;

/// Token types in a metavariable pattern
#[derive(Debug, Clone, PartialEq)]
pub enum MetavarToken {
    /// A metavariable like $X, $VAR, $ARG
    Metavar(String),
    /// A literal identifier like foo, bar
    Identifier(String),
    /// Operator: +, -, *, /, ==, etc.
    Operator(String),
    /// Opening parenthesis
    OpenParen,
    /// Closing parenthesis
    CloseParen,
    /// Opening bracket
    OpenBracket,
    /// Closing bracket
    CloseBracket,
    /// Comma
    Comma,
    /// Dot for member access
    Dot,
    /// String literal
    StringLiteral(String),
    /// Whitespace (for structure detection)
    Whitespace,
}

/// Parsed pattern structure
#[derive(Debug, Clone)]
pub struct ParsedMetavarPattern {
    /// The tokens that make up the pattern
    pub tokens: Vec<MetavarToken>,
    /// Detected pattern structure
    pub structure: PatternStructure,
    /// Map of metavariable names to their indices
    pub metavar_indices: HashMap<String, usize>,
}

/// High-level pattern structure detected from tokens
#[derive(Debug, Clone)]
pub enum PatternStructure {
    /// Function call: name(args)
    FunctionCall { name: String, is_metavar: bool },
    /// Binary expression: left op right
    BinaryExpression { operator: String },
    /// Member access: obj.member
    MemberAccess,
    /// Simple expression (identifier, metavar, or literal)
    SimpleExpression,
    /// Unknown/complex structure
    Unknown,
}

/// Parse a metavariable pattern string into tokens
pub fn parse_metavar_pattern(pattern: &str) -> ParsedMetavarPattern {
    let tokens = tokenize(pattern);
    let structure = detect_structure(&tokens);
    let metavar_indices = extract_metavar_indices(&tokens);

    ParsedMetavarPattern {
        tokens,
        structure,
        metavar_indices,
    }
}

/// Tokenize a pattern string
fn tokenize(pattern: &str) -> Vec<MetavarToken> {
    let mut tokens = Vec::new();
    let mut chars = pattern.chars().peekable();

    while let Some(&c) = chars.peek() {
        match c {
            // Metavariable: starts with $
            '$' => {
                chars.next();
                let mut name = String::from("$");
                while let Some(&c) = chars.peek() {
                    if c.is_alphanumeric() || c == '_' {
                        name.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                tokens.push(MetavarToken::Metavar(name));
            }
            // Identifier: starts with letter or underscore
            'a'..='z' | 'A'..='Z' | '_' => {
                let mut name = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_alphanumeric() || c == '_' {
                        name.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                tokens.push(MetavarToken::Identifier(name));
            }
            // Parentheses
            '(' => {
                chars.next();
                tokens.push(MetavarToken::OpenParen);
            }
            ')' => {
                chars.next();
                tokens.push(MetavarToken::CloseParen);
            }
            // Brackets
            '[' => {
                chars.next();
                tokens.push(MetavarToken::OpenBracket);
            }
            ']' => {
                chars.next();
                tokens.push(MetavarToken::CloseBracket);
            }
            // Comma
            ',' => {
                chars.next();
                tokens.push(MetavarToken::Comma);
            }
            // Dot
            '.' => {
                chars.next();
                tokens.push(MetavarToken::Dot);
            }
            // String literals
            '"' | '\'' => {
                let quote = chars.next().unwrap();
                let mut content = String::new();
                while let Some(&c) = chars.peek() {
                    if c == quote {
                        chars.next();
                        break;
                    } else if c == '\\' {
                        chars.next();
                        // Handle escape sequences properly
                        if let Some(escaped_char) = chars.next() {
                            let unescaped = match escaped_char {
                                'n' => '\n',
                                't' => '\t',
                                'r' => '\r',
                                '\\' => '\\',
                                '"' => '"',
                                '\'' => '\'',
                                '0' => '\0',
                                other => other, // Pass through unknown escapes
                            };
                            content.push(unescaped);
                        }
                    } else {
                        content.push(chars.next().unwrap());
                    }
                }
                tokens.push(MetavarToken::StringLiteral(content));
            }
            // Operators
            '+' | '-' | '*' | '/' | '=' | '!' | '<' | '>' | '&' | '|' | '%' | '^' => {
                let mut op = String::new();
                while let Some(&c) = chars.peek() {
                    if "+-*/=!<>&|%^".contains(c) {
                        op.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                tokens.push(MetavarToken::Operator(op));
            }
            // Whitespace
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
                // Collapse whitespace
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() {
                        chars.next();
                    } else {
                        break;
                    }
                }
                tokens.push(MetavarToken::Whitespace);
            }
            // Skip other characters
            _ => {
                chars.next();
            }
        }
    }

    tokens
}

/// Detect the high-level structure of the pattern
fn detect_structure(tokens: &[MetavarToken]) -> PatternStructure {
    // Filter out whitespace for structure detection
    let filtered: Vec<_> = tokens
        .iter()
        .filter(|t| !matches!(t, MetavarToken::Whitespace))
        .collect();

    if filtered.is_empty() {
        return PatternStructure::Unknown;
    }

    // Check for function call: name(...) or $VAR(...)
    if filtered.len() >= 3 {
        if let (first, MetavarToken::OpenParen) = (&filtered[0], &filtered[1]) {
            match first {
                MetavarToken::Identifier(name) => {
                    return PatternStructure::FunctionCall {
                        name: name.clone(),
                        is_metavar: false,
                    };
                }
                MetavarToken::Metavar(name) => {
                    return PatternStructure::FunctionCall {
                        name: name.clone(),
                        is_metavar: true,
                    };
                }
                _ => {}
            }
        }
    }

    // Check for binary expression: expr op expr
    for (i, token) in filtered.iter().enumerate() {
        if let MetavarToken::Operator(op) = token {
            if i > 0 && i < filtered.len() - 1 {
                return PatternStructure::BinaryExpression {
                    operator: op.clone(),
                };
            }
        }
    }

    // Check for member access: obj.member
    for token in filtered.iter() {
        if matches!(token, MetavarToken::Dot) {
            return PatternStructure::MemberAccess;
        }
    }

    // Simple expression
    if filtered.len() == 1 {
        return PatternStructure::SimpleExpression;
    }

    PatternStructure::Unknown
}

/// Extract metavariable names and their positions
fn extract_metavar_indices(tokens: &[MetavarToken]) -> HashMap<String, usize> {
    let mut indices = HashMap::new();
    let mut counter = 0;

    for token in tokens {
        if let MetavarToken::Metavar(name) = token {
            if !indices.contains_key(name) {
                indices.insert(name.clone(), counter);
                counter += 1;
            }
        }
    }

    indices
}

/// Translate a parsed pattern into a tree-sitter query
pub fn translate_to_tree_sitter(
    pattern: &ParsedMetavarPattern,
    language: &Language,
) -> Option<String> {
    match &pattern.structure {
        PatternStructure::FunctionCall { name, is_metavar } => {
            translate_function_call(name, *is_metavar, &pattern.tokens, language)
        }
        PatternStructure::BinaryExpression { operator } => {
            translate_binary_expression(operator, language)
        }
        PatternStructure::MemberAccess => translate_member_access(&pattern.tokens, language),
        PatternStructure::SimpleExpression => {
            translate_simple_expression(&pattern.tokens, language)
        }
        PatternStructure::Unknown => None,
    }
}

/// Translate function call pattern
fn translate_function_call(
    name: &str,
    is_metavar: bool,
    tokens: &[MetavarToken],
    language: &Language,
) -> Option<String> {
    let (call_node, func_field, args_node) = match language {
        Language::Python => ("call", "function", "arguments"),
        Language::JavaScript | Language::TypeScript => ("call_expression", "function", "arguments"),
        Language::Rust => ("call_expression", "function", "arguments"),
        Language::Go => ("call_expression", "function", "arguments"),
        Language::C | Language::Cpp => ("call_expression", "function", "arguments"),
    };

    // Extract argument patterns from tokens
    let arg_patterns = extract_argument_patterns(tokens);

    // Build argument matching based on extracted patterns
    let args_query = if arg_patterns.is_empty() {
        // No specific arguments, match any
        format!("{args_node}: (_)* @args")
    } else {
        // Generate specific argument captures
        let arg_captures: Vec<String> = arg_patterns
            .iter()
            .enumerate()
            .map(|(i, pattern)| match pattern {
                ArgumentPattern::Metavar(_name) => format!("(_) @arg{i}"),
                ArgumentPattern::Identifier(_) | ArgumentPattern::StringLiteral(_) => {
                    format!("(_) @arg{i}")
                }
            })
            .collect();
        format!("{args_node}: (argument_list {})", arg_captures.join(" "))
    };

    // Build constraints for literal arguments
    let constraints: Vec<String> = arg_patterns
        .iter()
        .enumerate()
        .filter_map(|(i, pattern)| match pattern {
            ArgumentPattern::Identifier(lit) => Some(format!(r#"(#eq? @arg{i} "{lit}")"#)),
            ArgumentPattern::StringLiteral(lit) => Some(format!(r#"(#match? @arg{i} "{lit}")"#)),
            ArgumentPattern::Metavar(_) => None,
        })
        .collect();

    let constraint_str = if constraints.is_empty() {
        String::new()
    } else {
        format!("\n  {}", constraints.join("\n  "))
    };

    if is_metavar {
        // Match any function call, capture the function name
        Some(format!(
            r#"({call_node}
  {func_field}: (identifier) @func
  {args_query}{constraint_str}) @call"#
        ))
    } else {
        // Match specific function name
        Some(format!(
            r#"({call_node}
  {func_field}: (identifier) @func
  (#eq? @func "{name}")
  {args_query}{constraint_str}) @call"#
        ))
    }
}

/// Argument pattern type
#[derive(Debug, Clone)]
enum ArgumentPattern {
    Metavar(String),
    Identifier(String),
    StringLiteral(String),
}

/// Extract argument patterns from tokens (between parentheses, split by commas)
fn extract_argument_patterns(tokens: &[MetavarToken]) -> Vec<ArgumentPattern> {
    let mut patterns = Vec::new();
    let mut inside_parens = false;

    for token in tokens {
        match token {
            MetavarToken::OpenParen => inside_parens = true,
            MetavarToken::CloseParen => break,
            MetavarToken::Metavar(name) if inside_parens => {
                patterns.push(ArgumentPattern::Metavar(name.clone()));
            }
            MetavarToken::Identifier(name) if inside_parens => {
                patterns.push(ArgumentPattern::Identifier(name.clone()));
            }
            MetavarToken::StringLiteral(content) if inside_parens => {
                patterns.push(ArgumentPattern::StringLiteral(content.clone()));
            }
            MetavarToken::Comma | MetavarToken::Whitespace => {}
            _ => {}
        }
    }

    patterns
}

/// Translate binary expression pattern
fn translate_binary_expression(operator: &str, language: &Language) -> Option<String> {
    let node_type = match language {
        Language::Python => "binary_operator",
        Language::JavaScript | Language::TypeScript => "binary_expression",
        Language::Rust => "binary_expression",
        Language::Go => "binary_expression",
        Language::C | Language::Cpp => "binary_expression",
    };

    // Map operators to tree-sitter operator names if needed
    let op_match = match operator {
        "+" => Some("+"),
        "-" => Some("-"),
        "*" => Some("*"),
        "/" => Some("/"),
        "==" => Some("=="),
        "!=" => Some("!="),
        "<" => Some("<"),
        ">" => Some(">"),
        "<=" => Some("<="),
        ">=" => Some(">="),
        "&&" | "and" => Some("&&"),
        "||" | "or" => Some("||"),
        _ => None,
    };

    if let Some(op) = op_match {
        // Generate operator-specific query with operator field
        // Python uses a child node for operator, others use an operator field
        let op_clause = match language {
            Language::Python => {
                // Python binary_operator has operator as a direct child
                format!(r#"operator: "{op}""#)
            }
            _ => {
                // Most languages use operator field
                format!(r#"operator: "{op}""#)
            }
        };
        Some(format!(
            r#"({node_type}
  left: (_) @left
  {op_clause}
  right: (_) @right) @expr"#
        ))
    } else {
        // Generic binary expression - match any operator
        Some(format!(
            r#"({node_type}
  left: (_) @left
  right: (_) @right) @expr"#
        ))
    }
}

/// Translate member access pattern
fn translate_member_access(tokens: &[MetavarToken], language: &Language) -> Option<String> {
    let (node_type, obj_field, attr_field) = match language {
        Language::Python => ("attribute", "object", "attribute"),
        Language::JavaScript | Language::TypeScript => ("member_expression", "object", "property"),
        Language::Rust => ("field_expression", "value", "field"),
        Language::Go => ("selector_expression", "operand", "field"),
        Language::C | Language::Cpp => ("field_expression", "argument", "field"),
    };

    // Parse tokens to find object and attribute patterns
    let dot_pos = tokens.iter().position(|t| matches!(t, MetavarToken::Dot));

    if let Some(dot_idx) = dot_pos {
        // Get object token (first non-whitespace before dot)
        let object_token = tokens[..dot_idx]
            .iter()
            .filter(|t| !matches!(t, MetavarToken::Whitespace))
            .next();

        // Get attribute token (first non-whitespace after dot)
        let attr_token = tokens[dot_idx + 1..]
            .iter()
            .filter(|t| !matches!(t, MetavarToken::Whitespace))
            .next();

        // Build object pattern and constraint
        let (obj_pattern, obj_constraint) = match object_token {
            Some(MetavarToken::Identifier(name)) => (
                "(identifier) @object",
                Some(format!(r#"(#eq? @object "{name}")"#)),
            ),
            Some(MetavarToken::Metavar(_)) => ("(_) @object", None),
            _ => ("(_) @object", None),
        };

        // Build attribute pattern and constraint
        let (attr_pattern, attr_constraint) = match attr_token {
            Some(MetavarToken::Identifier(name)) => (
                "(property_identifier) @attribute",
                Some(format!(r#"(#eq? @attribute "{name}")"#)),
            ),
            Some(MetavarToken::Metavar(_)) => ("(_) @attribute", None),
            _ => ("(_) @attribute", None),
        };

        // Combine constraints
        let constraints: Vec<String> = [obj_constraint, attr_constraint]
            .into_iter()
            .flatten()
            .collect();

        let constraint_str = if constraints.is_empty() {
            String::new()
        } else {
            format!("\n  {}", constraints.join("\n  "))
        };

        Some(format!(
            r#"({node_type}
  {obj_field}: {obj_pattern}
  {attr_field}: {attr_pattern}{constraint_str}) @access"#
        ))
    } else {
        // No dot found, generate generic member access
        Some(format!(
            r#"({node_type}
  {obj_field}: (_) @object
  {attr_field}: (_) @attribute) @access"#
        ))
    }
}

/// Translate simple expression pattern
fn translate_simple_expression(tokens: &[MetavarToken], language: &Language) -> Option<String> {
    if tokens.is_empty() {
        return None;
    }

    // Use language-specific node types
    let (id_node, string_node) = match language {
        Language::Python => ("identifier", "string"),
        Language::JavaScript | Language::TypeScript => ("identifier", "string"),
        Language::Rust => ("identifier", "string_literal"),
        Language::Go => ("identifier", "interpreted_string_literal"),
        Language::C | Language::Cpp => ("identifier", "string_literal"),
    };

    match &tokens[0] {
        MetavarToken::Metavar(_) => {
            // Match any identifier
            Some(format!("({id_node}) @expr"))
        }
        MetavarToken::Identifier(name) => {
            // Match specific identifier
            Some(format!(
                r#"(({id_node}) @expr
  (#eq? @expr "{name}"))"#
            ))
        }
        MetavarToken::StringLiteral(content) => {
            // Match string literals, optionally with content match
            if content.is_empty() {
                Some(format!("({string_node}) @expr"))
            } else {
                Some(format!(
                    r#"(({string_node}) @expr
  (#match? @expr "{content}"))"#
                ))
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize_function_call() {
        let tokens = tokenize("foo($ARG)");
        assert_eq!(tokens.len(), 4);
        assert!(matches!(&tokens[0], MetavarToken::Identifier(n) if n == "foo"));
        assert!(matches!(&tokens[1], MetavarToken::OpenParen));
        assert!(matches!(&tokens[2], MetavarToken::Metavar(n) if n == "$ARG"));
        assert!(matches!(&tokens[3], MetavarToken::CloseParen));
    }

    #[test]
    fn test_tokenize_binary_expr() {
        let tokens = tokenize("$X + $Y");
        // Filter whitespace
        let filtered: Vec<_> = tokens
            .into_iter()
            .filter(|t| !matches!(t, MetavarToken::Whitespace))
            .collect();
        assert_eq!(filtered.len(), 3);
        assert!(matches!(&filtered[0], MetavarToken::Metavar(n) if n == "$X"));
        assert!(matches!(&filtered[1], MetavarToken::Operator(o) if o == "+"));
        assert!(matches!(&filtered[2], MetavarToken::Metavar(n) if n == "$Y"));
    }

    #[test]
    fn test_detect_function_call_structure() {
        let parsed = parse_metavar_pattern("foo($ARG)");
        assert!(matches!(
            parsed.structure,
            PatternStructure::FunctionCall { name, is_metavar: false } if name == "foo"
        ));
    }

    #[test]
    fn test_detect_binary_expression_structure() {
        let parsed = parse_metavar_pattern("$X + $Y");
        assert!(matches!(
            parsed.structure,
            PatternStructure::BinaryExpression { operator } if operator == "+"
        ));
    }

    #[test]
    fn test_translate_function_call() {
        let parsed = parse_metavar_pattern("foo($ARG)");
        let query = translate_to_tree_sitter(&parsed, &Language::Python);
        assert!(query.is_some());
        let q = query.unwrap();
        assert!(q.contains("call"));
        assert!(q.contains("foo"));
    }
}
