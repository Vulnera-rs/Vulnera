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

```bash
curl -X POST http://localhost:3000/api/v1/analyze/job \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "source_type": "git",
    "source_uri": "https://github.com/my-org/my-project.git",
    "analysis_depth": "full"
  }'
```

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

## Pattern Types

### Function Call Matching

```toml
pattern = { FunctionCall = "eval" }
```

Matches calls to specific functions.

### AST Node Type Matching

```toml
pattern = { NodeType = "string_literal" }
```

Matches specific AST node types.

### Regular Expression Matching

```toml
pattern = { Regex = "password\\s*=\\s*['\"][^'\"]+['\"]" }
```

Matches patterns using regular expressions.

## Response Format

```json
{
  "findings": [
    {
      "module": "sast",
      "rule_id": "sql-injection",
      "severity": "high",
      "confidence": "high",
      "file": "src/database.py",
      "line": 42,
      "column": 8,
      "message": "Potential SQL injection vulnerability detected",
      "code_snippet": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
      "remediation": "Use parameterized queries instead of string formatting"
    }
  ]
}
```

## Configuration

```bash
# Maximum scan depth
VULNERA__SAST__MAX_SCAN_DEPTH=10

# Exclude patterns (JSON array)
VULNERA__SAST__EXCLUDE_PATTERNS='["node_modules", ".git", "target", "__pycache__"]'

# Custom rule file path
VULNERA__SAST__RULE_FILE_PATH=/path/to/custom-rules.toml

# Enable logging
VULNERA__SAST__ENABLE_LOGGING=true
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
