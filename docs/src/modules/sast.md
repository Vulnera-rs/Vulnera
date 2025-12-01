# SAST (Static Application Security Testing)

The SAST Module performs static code analysis to detect security vulnerabilities directly in your source code using Abstract Syntax Tree (AST) parsing.

## Supported Languages

| Language | Parser | File Extensions |
|----------|--------|-----------------|
| **Python** | tree-sitter-python | `.py` |
| **JavaScript/TypeScript** | tree-sitter-javascript | `.js`, `.ts`, `.jsx`, `.tsx` |
| **Rust** | syn crate (proc-macro) | `.rs` |

## Features

- **AST-Based Analysis** — Deep understanding of code structure
- **Configurable Rule Repository** — Load custom security rules from TOML or JSON
- **Default Rule Set** — Built-in rules for common vulnerabilities
- **Pattern-Based Detection** — Multiple matcher types for flexible rule definition
- **Automatic Confidence Scoring** — Based on pattern specificity
- **Severity Classification** — Critical, High, Medium, Low, Info

## Default Security Rules

The module includes built-in rules for detecting:

- SQL injection vulnerabilities
- Command injection risks
- Unsafe deserialization patterns
- Hardcoded credentials and secrets
- Insecure cryptographic operations
- Path traversal vulnerabilities
- Cross-site scripting (XSS)

## API Usage

SAST analysis is automatically executed through the orchestrator:

## Custom Rules

### TOML Format

```toml
[[rules]]
id = "custom-sql-injection"
name = "Custom SQL Injection"
description = "Detects potential SQL injection vulnerabilities"
severity = "High"
languages = ["Python", "JavaScript"]
pattern = { FunctionCall = "query" }

[[rules]]
id = "unsafe-eval"
name = "Unsafe Eval Usage"
description = "Detects usage of eval() function"
severity = "Critical"
languages = ["Python", "JavaScript"]
pattern = { FunctionCall = "eval" }
```

### JSON Format

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

## Confidence Levels

| Level | Description |
|-------|-------------|
| **High** | Strong match, high likelihood of true positive |
| **Medium** | Moderate match, may require manual review |
| **Low** | Weak match, higher chance of false positive |

## Severity Classification

| Severity | Description | Examples |
|----------|-------------|----------|
| **Critical** | Immediate exploitation risk | SQL injection, command injection |
| **High** | Significant security risk | Hardcoded credentials, unsafe deserialization |
| **Medium** | Moderate security concern | Missing input validation |
| **Low** | Minor security issue | Information disclosure |
| **Info** | Best practice recommendation | Code quality suggestions |
