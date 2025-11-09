# Vulnera SAST

Static Application Security Testing (SAST) module for the Vulnera security analysis platform.

## Overview

The `vulnera-sast` crate provides static code analysis capabilities to detect security vulnerabilities in source code. It supports multiple programming languages and uses configurable rule sets to identify potential security issues.

## Supported Languages

- **Python** - Using tree-sitter-python for AST parsing
- **JavaScript/TypeScript** - Using tree-sitter-javascript for AST parsing
- **Rust** - Using syn for AST parsing

## Features

- **Configurable Rule Repository**: Load security rules from TOML or JSON files
- **Default Rule Set**: Built-in rules for common vulnerabilities (SQL injection, command injection, unsafe deserialization, etc.)
- **Confidence Scoring**: Automatic confidence calculation based on pattern specificity
- **File Counting**: Tracks the number of files scanned during analysis
- **Comprehensive Logging**: Integrated with `tracing` for observability
- **Configurable Scanning**: Customizable scan depth and exclude patterns

## Configuration

The SAST module is configured through `vulnera-core::Config::SastConfig`:

```toml
[sast]
max_scan_depth = 10
exclude_patterns = ["node_modules", ".git", "target", "__pycache__"]
rule_file_path = "path/to/rules.toml"  # Optional
enable_logging = true
```

### Configuration Options

- `max_scan_depth`: Maximum directory depth to scan (default: 10)
- `exclude_patterns`: List of directory/file name patterns to exclude from scanning
- `rule_file_path`: Optional path to a TOML or JSON file containing custom rules
- `enable_logging`: Whether to enable logging for SAST operations (default: true)

## Rule Format

Rules can be defined in TOML or JSON format:

### TOML Example

```toml
[[rules]]
id = "custom-sql-injection"
name = "Custom SQL Injection"
description = "Detects potential SQL injection vulnerabilities"
severity = "High"
languages = ["Python", "JavaScript"]
pattern = { FunctionCall = "query" }
```

### JSON Example

```json
{
  "rules": [
    {
      "id": "custom-sql-injection",
      "name": "Custom SQL Injection",
      "description": "Detects potential SQL injection vulnerabilities",
      "severity": "High",
      "languages": ["Python", "JavaScript"],
      "pattern": {
        "FunctionCall": "query"
      }
    }
  ]
}
```

### Rule Pattern Types

- `AstNodeType`: Matches AST nodes by type (e.g., `"call"`, `"function_definition"`)
- `FunctionCall`: Matches function calls by name (e.g., `"execute"`, `"eval"`)
- `Regex`: Matches using a regular expression pattern
- `Custom`: Reserved for future custom pattern matchers

### Severity Levels

- `Critical`
- `High`
- `Medium`
- `Low`
- `Info`

### Confidence Levels

Confidence is automatically calculated based on pattern specificity:

- **High**: Regex patterns, or function call patterns matching exact node types
- **Medium**: Function call patterns, AST node type patterns with context
- **Low**: AST node type patterns without context

## Usage

### Basic Usage

```rust
use vulnera_sast::SastModule;
use vulnera_core::config::SastConfig;

// Create module with default configuration
let module = SastModule::new();

// Or with custom configuration
let config = SastConfig {
    max_scan_depth: 5,
    exclude_patterns: vec!["node_modules".to_string()],
    rule_file_path: Some("custom-rules.toml".into()),
    enable_logging: true,
};
let module = SastModule::with_config(&config);
```

### Programmatic Rule Creation

```rust
use vulnera_sast::infrastructure::rules::RuleRepository;
use vulnera_sast::infrastructure::rules::default_rules::get_default_rules;

// Use default rules
let repository = RuleRepository::new();

// Load from file (with defaults as fallback)
let repository = RuleRepository::with_file_and_defaults("rules.toml");

// Use only file rules (no defaults)
let repository = RuleRepository::from_file("rules.toml");
```

## Architecture

The SAST module follows a layered architecture:

- **Domain Layer**: Core entities (Finding, Rule, Location, etc.)
- **Application Layer**: Use cases (ScanProjectUseCase)
- **Infrastructure Layer**: 
  - Parsers (Python, JavaScript, Rust)
  - Rules engine and repository
  - Directory scanner
  - Rule loaders (TOML/JSON)

## Limitations

1. **Rust Parser**: Currently provides basic parsing support. Full AST traversal for Rust is limited.
2. **Custom Patterns**: Custom pattern matchers are not yet implemented.
3. **Context Analysis**: Confidence calculation is based on pattern type and basic context. More sophisticated context analysis may be added in the future.
4. **Rule Validation**: Rule validation is basic. More comprehensive validation may be added.

## Testing

Run tests with:

```bash
cargo test -p vulnera-sast
```

## Contributing

When adding new rules or patterns:

1. Add default rules to `src/infrastructure/rules/default_rules.rs`
2. Update this README with rule documentation
3. Add tests for new rules in the appropriate test module
4. Ensure confidence calculation works correctly for new pattern types

## License

See the main project LICENSE file.








