# AI-Assisted Code Analysis (ML-Powered AST Pattern Matching)

Detect security vulnerabilities in source code using machine learning-powered Abstract Syntax Tree (AST) analysis and intelligent pattern matching.

## What Is Code Analysis?

Code analysis (SAST - Static Application Security Testing) automatically finds vulnerabilities in your source code:

- 💉 SQL Injection, command injection, LDAP injection
- 🎯 Cross-Site Scripting (XSS), HTML injection
- 🔓 Insecure deserialization, unsafe object instantiation
- 🔐 Hardcoded credentials and API keys
- 🛡️ Missing input validation and output encoding
- 🚫 Unsafe cryptography and weak randomness
- 📦 Unsafe package loads and dynamic code execution

## How It Works: ML-Powered AST Analysis

### Technology Stack

Vulnera's code analysis uses **machine learning-based AST parsing and pattern matching**:

### AST-Based Pattern Matching

**How it works:**

```
Input: 
    user_id = request.GET['id']
    query = f"SELECT * FROM users WHERE id={user_id}"
    db.execute(query)

AST Parser
  ↓
Abstract Syntax Tree
  ├─ assignment: user_id ← function_call (request.GET)
  ├─ assignment: query ← f-string with interpolation
  └─ function_call: db.execute(query)

ML Pattern Matcher
  ├─ Detects: user input → SQL query
  ├─ Recognizes: direct interpolation (not parameterized)
  └─ Analysis: Taint flow from input to SQL
  
Output: "SQL Injection (95% confidence) - Use parameterized queries"
```

**Why it's ML:** Understands code semantics (not just regex), recognizes taint flow patterns.

## Supported Languages

### Python

**Detections:**

- SQL Injection (SQLi), command injection
- XSS in templates (Jinja2, Django)
- Hardcoded secrets
- Unsafe pickle/eval usage

**Example:**

```python
# Vulnerable ❌
username = request.args.get('username')
query = f"SELECT * FROM users WHERE username='{username}'"
results = db.execute(query)

# Secure ✅
username = request.args.get('username')
query = "SELECT * FROM users WHERE username=?"
results = db.execute(query, [username])
```

### JavaScript/TypeScript

**Detections:**

- XSS in DOM operations
- Unsafe SQL operations
- Command injection
- Unsafe eval/Function usage

**Example:**

```javascript
// Vulnerable ❌
const userId = req.query.id;
const sql = `SELECT * FROM users WHERE id=${userId}`;
db.query(sql);

// Secure ✅
const userId = req.query.id;
const sql = "SELECT * FROM users WHERE id=?";
db.query(sql, [userId]);
```

### Rust

**Detections:**

- Unsafe code blocks without proper justification
- Panic-inducing operations on untrusted input
- Unsafe serialization

**Example:**

```rust
// Vulnerable ❌
let user_input: String = get_user_input();
let buffer = unsafe { String::from_utf8_unchecked(user_input.into_bytes()) };

// Secure ✅
let user_input: String = get_user_input();
let buffer = String::from_utf8(user_input.into_bytes())?;
```

## ML Pattern Models

### SQL Injection Detection

```
ML Model: Taint-Flow Analyzer
├─ Identifies: User input sources (request.GET, request.POST, sys.argv, etc.)
├─ Traces: Data flow through functions
├─ Detects: Direct string concatenation to SQL queries
└─ Confidence: 95%+ (very reliable ML model)

Rule Example:
  IF (source == user_input) AND
     (sink == sql_query) AND
     (concatenation_or_interpolation == true) AND
     (parameterized_query == false)
  THEN
    Alert: SQL Injection vulnerability
```

### XSS (Cross-Site Scripting)

```
ML Model: Output Encoding Analyzer
├─ Identifies: Untrusted user input
├─ Traces: Data flow to HTML output
├─ Detects: Missing HTML escaping/encoding
└─ Confidence: 90%+ (context-dependent)

Types Detected:
  ├─ Reflected XSS (user input directly in HTML)
  ├─ Stored XSS (database data without escaping)
  ├─ DOM-based XSS (JavaScript DOM manipulation)
  └─ Template XSS (Jinja2, Django without autoescape)
```

### Command Injection

```
ML Model: Shell Command Analyzer
├─ Identifies: System command execution calls (os.system, subprocess, exec)
├─ Traces: User input reaching command strings
├─ Detects: Unsanitized user input in shell commands
└─ Confidence: 98%+ (very clear vulnerability pattern)

Dangerous Patterns:
  ├─ os.system(f"command {user_input}")
  ├─ subprocess.run(f"cmd {user_input}", shell=True)
  ├─ exec(f"code {user_input}")
  └─ eval(user_input)
```

## Running Code Analysis

### Standalone Code Analysis

```bash
# Scan all source files for vulnerabilities
vulnera sast /path/to/project

# Scan specific file
vulnera sast app.py

# Show only high/critical severity
vulnera sast . --severity high
```

### As Part of Full Analysis

```bash
vulnera analyze /path/to/project
# Includes SAST automatically
```

### Output

```
CODE ANALYSIS REPORT (SAST)
════════════════════════════════════════════════════════

🔴 CRITICAL (2)
  ├─ SQL Injection (app.py:42)
  │  Severity: Critical (CWE-89)
  │  Confidence: 95%
  │  Issue: User input directly interpolated into SQL query
  │  Fix: Use parameterized queries
  │
  └─ Command Injection (utils.py:120)
     Severity: Critical (CWE-78)
     Confidence: 98%
     Issue: os.system() with unsanitized user input
     Fix: Use subprocess.run() with list args, shell=False

🟡 MEDIUM (1)
  └─ Missing Input Validation (forms.py:35)
     Severity: Medium (CWE-20)
     Confidence: 85%
     Issue: No length/type validation on email field
     Fix: Add validation: len(email) < 255 and '@' in email
```

## Configuration

### Fine-Tune Detection Rules

```toml
# .vulnera.toml
[analysis.sast]
enabled = true
languages = ["python", "javascript", "rust"]

# Custom rules file
rules_file = ".vulnera-sast-rules.toml"

# Severity overrides
[analysis.sast.severity_overrides]
"SQL_INJECTION" = "critical"
"XSS" = "high"
"MISSING_INPUT_VALIDATION" = "medium"

# Exclude patterns
exclude_patterns = [
  "test/*",
  "vendor/*",
  "node_modules/*"
]
```

### Creating Custom Rules

```toml
# .vulnera-sast-rules.toml
[[rules]]
id = "CUSTOM-AUTH-001"
name = "Missing API Key Validation"
severity = "high"
language = "python"
pattern = """
  (function_definition
    name: (identifier) @name
    (#match? @name "^login")
    body: (block
      (expression_statement
        (function_call
          function: (identifier) @func
          (#match? @func "authenticate")))
      ))
"""
message = "Authentication function doesn't validate API key format"

[[rules]]
id = "CUSTOM-CONFIG-001"
name = "Hardcoded Configuration"
severity = "medium"
language = "javascript"
pattern = "DATABASE_URL.*=.*password"
message = "Database password appears to be hardcoded"
```

## Best Practices

### 1. Use Parameterized Queries

❌ **Vulnerable:**

```python
user_id = request.GET.get('id')
query = f"SELECT * FROM users WHERE id={user_id}"
```

✅ **Secure:**

```python
user_id = request.GET.get('id')
query = "SELECT * FROM users WHERE id=?"
results = db.execute(query, [user_id])
```

### 2. Escape HTML Output

❌ **Vulnerable:**

```javascript
document.innerHTML = `<p>${userInput}</p>`;
```

✅ **Secure:**

```javascript
const p = document.createElement('p');
p.textContent = userInput;  // textContent = escape
container.appendChild(p);
```

### 3. Avoid Shell Command Execution

❌ **Vulnerable:**

```python
os.system(f"convert {filename} output.png")
```

✅ **Secure:**

```python
subprocess.run(["convert", filename, "output.png"], check=True)
```

### 4. Validate All Input

❌ **Vulnerable:**

```python
email = request.POST.get('email')
send_confirmation(email)
```

✅ **Secure:**

```python
email = request.POST.get('email')
if validate_email(email):
    send_confirmation(email)
else:
    raise ValueError("Invalid email format")
```

## Comparing AST vs Regex Detection

| Aspect | AST Analysis | Regex Patterns |
|--------|-------------|-----------------|
| **Accuracy** | 95%+ (understands semantics) | 60-70% (pattern matching) |
| **False Positives** | <10% | >20% |
| **Speed** | Slower (parsing required) | Very fast |
| **Language Awareness** | Full (understands syntax) | Limited (text-based) |
| **Taint Tracking** | ✅ Yes | ❌ No |
| **Data Flow Analysis** | ✅ Yes | ❌ No |

**Vulnera uses AST analysis because it's more accurate and reduces false positives.**

## Offline Analysis

Code analysis works completely offline:

```bash
# No server needed
vulnera sast /path/to/project --offline

# ML models are embedded in the CLI
# Rules are stored locally
```

**Performance:** 0.5-5 seconds for typical project

## Troubleshooting

**Q: Why isn't my SQL injection detected?**  
A: ML model may not recognize the injection point. Add custom rule or check if it's actually parameterized.


**Q: Scan is slow**  
A: SAST requires parsing. Larger projects take longer. Run in background or narrow scope with `exclude_patterns`.

**Q: Want to skip certain files**  
A: Use `exclude_patterns` in config or `.vulnera.toml`.

## Next Steps

- [Configure analysis rules](../user-guide/configuration.md)
- [Get AI-powered explanations for findings](../user-guide/llm-features.md)
- [Integrate into CI/CD](../integration/cicd.md)
- [View all analysis capabilities](overview.md)
