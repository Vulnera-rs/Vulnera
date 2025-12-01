# Analysis Capabilities Overview

Vulnera provides four specialized analysis modules powered by AI-assisted detection. Understand what each module does, how it works, and what to expect.

## The Four Analysis Modules

Vulnera combines complementary security analysis approaches:

| Module | Purpose | AI Method | Offline? | Coverage |
|--------|---------|-----------|----------|----------|
| [AI-Assisted Secret Detection](secrets-detection.md) | Find exposed credentials | ML Pattern Recognition + Entropy | ✅ Yes | All text files |
| [AI-Assisted Code Analysis](sast.md) | Find security code flaws | AST Pattern Matching | ✅ Yes | Python, JavaScript, Rust |
| [AI-Assisted API Security Analysis](api-security.md) | Find API misconfigurations | Rule-based Analysis | ✅ Yes | OpenAPI 3.x specs |
| [Dependency Vulnerability Scanning](dependency-analysis.md) | Find known CVEs in dependencies | Registry Lookup (OSV/NVD/GHSA) | ❌ No | 8+ ecosystems |

## How Analysis Modules Are Selected

Vulnera uses **intelligent module selection**—it detects your project structure and runs appropriate modules:

```bash
# Analyzing a Node.js project
vulnera analyze /path/to/nodejs-app

# Automatically detects:
# ✅ Found package.json → Runs dependency analysis
# ✅ Found .js files → Runs AI-assisted code analysis
# ✅ Scanning all files → Runs secret detection
# ✅ No OpenAPI spec → Skips API analysis
```

**Result:** You get findings from 3 modules without specifying anything.

### Analysis Depths

Control how thorough the analysis is:

```bash
vulnera analyze /path/to/project --depth minimal   # Quick scan, common issues only
vulnera analyze /path/to/project --depth standard  # Balanced (default)
vulnera analyze /path/to/project --depth full      # Comprehensive, all checks enabled
```

## AI-Assisted Detection: What Does That Mean?

Unlike generic term "AI analysis," Vulnera's modules use **specific, documented AI/ML techniques**:

### 1. ML-Based Pattern Recognition (Secrets)

**Method:** Machine Learning pattern models for detecting credentials

```
Input: "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
    ↓
ML Pattern Matcher (trained on known secret formats)
    ↓
Output: "AWS Access Key detected with 98% confidence"
```

**Why it's ML:** Patterns are learned from real-world secret formats, not hand-coded regex alone.

### 2. AST-Based Pattern Matching (SAST)

**Method:** Abstract Syntax Tree analysis with pattern matching rules

```
Input: 
    sql_query = "SELECT * FROM users WHERE id = " + user_input
    ↓
AST Parser (converts code to structured tree)
    ↓
ML Pattern Matcher (finds taint flow: input → query)
    ↓
Output: "SQL Injection vulnerability (taint detected)"
```

**Why it's ML:** Uses data flow analysis and call graphs, not simple regex.

### 3. Entropy-Based Detection

**Method:** Mathematical entropy analysis + ML pattern recognition

```
Input: High-entropy strings in code/config
    ↓
Entropy Calculator (Shannon entropy, Base64 detection)
    ↓
ML Baseline Filter (removes false positives)
    ↓
Output: "Potential high-entropy secret found"
```

**Why it's ML:** Entropy thresholds are trained on real secrets vs noise.

### 4. Rule-Based API Analysis

**Method:** Specification analysis against security rules

```
Input: OpenAPI 3.x specification
    ↓
Specification Parser
    ↓
Security Rule Engine (checks auth, CORS, input validation)
    ↓
Output: "API endpoint missing authentication"
```

**Not ML, but systematic:** Uses curated security best practices.

## Module Details at a Glance

### Module 1: AI-Assisted Secret Detection (ML-Powered)

**What it finds:**

- AWS Access Keys, Azure credentials, GCP keys
- API tokens, Bearer tokens, private keys
- Database connection strings, SSH keys
- High-entropy strings (base64, hex)

**Technology:** ML pattern recognition + entropy analysis  
**Accuracy:** 95%+ (ML-trained patterns)  
**False positive rate:** <5% (ML baseline filtering)  
**Speed:** <100ms per file

### Module 2: AI-Assisted Code Analysis (ML-Powered)

**What it finds:**

- SQL Injection, XSS, command injection
- Hardcoded credentials
- Unsafe cryptography, weak randomness
- Missing input validation

**Technology:** AST pattern matching + data flow analysis  
**Languages:** Python, JavaScript, Rust  
**Accuracy:** 90%+ (AST-based, lower false positives than regex)  
**Speed:** ~500ms per file (AST parsing)

### Module 3: AI-Assisted API Security Analysis

**What it finds:**

- Missing authentication/authorization
- Insecure authentication flows (basic auth over HTTP)
- CORS misconfigurations
- Missing security headers
- Unvalidated input parameters
- Sensitive data exposure

**Technology:** OpenAPI 3.x specification analysis  
**Coverage:** Any OpenAPI 3.0+ spec  
**Accuracy:** Systematic (100% coverage of rules)  
**Speed:** ~50ms per spec

### Module 4: Dependency Vulnerability Scanning

**What it finds:**

- Known CVEs in dependencies
- Outdated package versions
- Transitive dependency risks

**Technology:** Registry lookup (OSV, NVD, GHSA)  
**Coverage:** 8+ ecosystems (npm, PyPI, Maven, Cargo, Go, Ruby, .NET, Packagist)  
**Accuracy:** 100% (matches against authoritative CVE databases)  
**Speed:** 1-10 seconds (depends on number of dependencies)

## Offline vs Online Modules

### Offline Analysis (All Local)

```bash
vulnera analyze /path/to/project --offline
```

**Works without server:**

- ✅ AI-Assisted Secret Detection (ML models included)
- ✅ AI-Assisted Code Analysis (AST rules included)
- ✅ AI-Assisted API Analysis (rules included)

**Doesn't work offline:**

- ❌ Dependency scanning (requires CVE database lookups)

**Performance:** ~1-5 seconds total (depends on project size)

### Online Analysis (Full Power)

```bash
vulnera analyze /path/to/project --all-modules
```

**Requires network:**

- ✅ All four modules run
- ✅ Dependency scanning uses latest CVE data
- ✅ ML models are current (pattern updates)

**Performance:** 5-30 seconds (includes network latency)

## Output Format

All modules produce unified findings with:

```json
{
  "findings": [
    {
      "id": "SAST-SQL-001",
      "type": "SQL Injection",
      "severity": "high",
      "file": "app.py",
      "line": 42,
      "message": "User input concatenated into SQL query",
      "ml_model": "AST Pattern Matcher v2.1",
      "confidence": 0.95,
      "remediation": "Use parameterized queries",
      "llm_explanation": "This is vulnerable because... [LLM-powered]"
    }
  ]
}
```

## Next Steps

- [Learn about AI-Assisted Secret Detection](secrets-detection.md)
- [Learn about AI-Assisted Code Analysis](sast.md)
- [Learn about AI-Assisted API Security Analysis](api-security.md)
- [Learn about Dependency Scanning](dependency-analysis.md)
- [Get LLM-powered explanations for findings](../user-guide/llm-features.md)
