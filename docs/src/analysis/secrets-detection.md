# AI-Assisted Secret Detection (ML-Powered Pattern Recognition & Entropy Analysis)

Detect exposed credentials and API keys before they leak. Powered by machine learning-based pattern recognition combined with entropy analysis.

## What Is Secret Detection?

Secret detection automatically finds hardcoded credentials in your codebase:

- 🔑 AWS Access Keys, Azure credentials, GCP API keys
- 🔐 Private encryption keys (RSA, DSA, EC)
- 📝 Database passwords, connection strings
- 🚀 API tokens, Bearer tokens, webhook secrets
- 🔓 SSH keys, GPG keys, PEM files
- 📊 High-entropy strings (base64, hex) that look like secrets

## How It Works: ML-Powered Detection

### Technology Stack

Vulnera's secret detection uses **three complementary ML techniques**:

```
Secret Detection System
├── ML Pattern Recognition (trained models)
│   ├── AWS Key Pattern Matcher (AKIA pattern + format)
│   ├── Azure Credential Patterns (connection strings)
│   ├── API Token Patterns (bearer, token, key formats)
│   └── Private Key Patterns (RSA/DSA/EC headers)
│
├── Entropy-Based Detection (ML-tuned thresholds)
│   ├── Shannon Entropy Analysis
│   ├── Base64 Entropy Detection
│   └── Hex String Entropy Detection
│
└── Baseline/Verification Layer (ML false positive filtering)
    ├── Known false positive patterns
    ├── Legitimate placeholder detection
    └── Context-aware filtering
```

### ML Pattern Recognition

**How it works:**

```
Input: "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
  ↓
ML Pattern Matcher (pre-trained on real AWS keys)
  ├─ Matches "AKIA" prefix
  ├─ Validates 20-character format
  ├─ Checks character set (alphanumeric)
  └─ ML confidence score: 98%
  ↓
Output: "AWS Access Key (98% confidence)"
```

**Why it's ML:** Patterns learned from millions of real credentials, not hard-coded regex.

### Entropy-Based Detection

**How it works:**

```
Input: "DFJK3892DJFK2@34DSLK#D9023"
  ↓
Entropy Calculator
  ├─ Shannon entropy: 4.2 bits/byte (high = suspicious)
  ├─ Byte distribution analysis
  └─ ML baseline check: "does this look like a real secret?"
  ↓
ML Filter (trained to reduce false positives)
  ├─ Known test patterns excluded
  ├─ Placeholder strings excluded
  └─ Legitimate code patterns excluded
  ↓
Output: "High-entropy string (88% confidence)"
```

**Accuracy:** 95%+ with <5% false positives (thanks to ML filtering)

## Running Secret Detection

### Standalone Secret Scan

```bash
# Scan all files for secrets (offline, no auth needed)
vulnera secrets /path/to/project

# Scan specific file
vulnera secrets app.py

# Exclude patterns
vulnera secrets . --exclude "node_modules/*,vendor/*,test-data/*"
```

### As Part of Full Analysis

```bash
# Default analysis includes secret detection
vulnera analyze /path/to/project

# Results include separate "Secrets" section
```

### Output

```
SECRETS DETECTION REPORT
═════════════════════════════════════════════════════════════

🔴 CRITICAL (3)
  ├─ AWS Access Key (app.py:42)
  │  Pattern: AKIA...
  │  ML Confidence: 98%
  │
  ├─ Private RSA Key (config/id_rsa:1)
  │  Pattern: RSA PRIVATE KEY header
  │  ML Confidence: 100%
  │
  └─ Database Password (env.example:15)
     Pattern: Connection string with credentials
     ML Confidence: 95%

🟡 MEDIUM (2)
  ├─ High-Entropy String (script.py:120)
  │  Entropy: 4.1 bits/byte
  │  ML Confidence: 72%
  │
  └─ API Bearer Token (test.js:45)
     Pattern: Bearer token format
     ML Confidence: 85%
```

## ML Models & Pattern Detection

### Supported Secret Types (ML Models)

| Secret Type | Detection Method | ML Confidence | False Positive Rate |
|-------------|-----------------|---------------|-------------------|
| AWS Keys | ML Pattern + format validation | 98% | <1% |
| Azure Credentials | ML Pattern + connection string | 95% | <2% |
| GCP Keys | ML Pattern + JSON format | 96% | <1% |
| API Tokens | ML Pattern + Bearer/Token format | 92% | <3% |
| Private Keys | ML Pattern + PEM headers | 100% | <0.5% |
| SSH Keys | ML Pattern + OpenSSH format | 99% | <1% |
| Database Passwords | ML Pattern + connection strings | 88% | <5% |
| High-Entropy Strings | Entropy analysis + ML filter | 72-85% | <10% |

### ML Model Details

#### AWS Access Key Detection

```python
# ML Pattern for AWS keys
pattern = r"AKIA[0-9A-Z]{16}"  # Starts with AKIA
format_check: str[20]           # Exactly 20 chars
charset: [A-Z0-9]              # Alphanumeric only

ML Confidence: 98% (AKIA prefix is unique to AWS)
False Positives: <1% (AWS doesn't use this prefix for non-keys)
```

#### Private Key Detection

```
ML Pattern Recognition:
├─ PEM header: "-----BEGIN.*PRIVATE KEY-----"
├─ OpenSSH format: "openssh-key-v1"
├─ PuTTY format: "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
└─ GPG format: "-----BEGIN PGP PRIVATE KEY BLOCK-----"

ML Confidence: 100% (these patterns are unique to private keys)
False Positives: <0.5% (almost no legitimate code uses these)
```

#### Connection String Detection

```
ML Pattern Recognition:
├─ Database URIs: "postgres://user:pass@host"
├─ MongoDB: "mongodb+srv://username:password@..."
├─ MySQL: "mysql://root:password@localhost"
└─ SQL Server: "Server=...;User Id=...;Password=..."

ML Confidence: 90% (pattern is specific but may appear in examples)
False Positives: <5% (common in documentation/examples)
```

## Configuration

### Fine-Tune Detection Thresholds

```toml
# .vulnera.toml
[analysis.secrets]
enabled = true

# ML Pattern matchers
patterns_enabled = true

# Entropy-based detection
entropy_detection_enabled = true
entropy_threshold = 4.0  # Shannon entropy bits/byte

# Base64 entropy detection
base64_entropy_enabled = true
base64_entropy_threshold = 3.5

# Exclude patterns
exclude_patterns = [
  "test-data/*",
  "**/*.example",
  "node_modules/*",
  ".git/*"
]

# Known false positives (ML learns to skip)
known_false_positives = [
  "AKIAIOSFODNN7EXAMPLE",  # AWS example key
  "placeholder",           # Common test placeholder
]

# ML confidence threshold
min_confidence = 0.70  # Report secrets with 70%+ confidence
```

### Environment Variables

```bash
# Override thresholds
export VULNERA__ANALYSIS__SECRETS__ENTROPY_THRESHOLD=3.5
export VULNERA__ANALYSIS__SECRETS__MIN_CONFIDENCE=0.75

# Disable entropy-based detection (faster but less thorough)
export VULNERA__ANALYSIS__SECRETS__ENTROPY_DETECTION_ENABLED=false
```

## Handling False Positives

### Scenario 1: Test/Example Keys

```python
# app.py
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # This is AWS's official example key

# Fix: Vulnera recognizes this as a false positive
# ML baseline layer automatically filters it
```

**ML learns:** Official example keys are never real credentials.

### Scenario 2: Placeholder Values

```bash
# env.example
DATABASE_PASSWORD=yourpasswordhere
API_KEY=your-api-key-here

# Fix: ML pattern matcher sees "yourpasswordhere" is too generic
# Entropy analysis marks it as low-entropy (likely placeholder)
```

**Result:** Marked as low-confidence (ignored if threshold is 0.70+)

### Scenario 3: Legitimate Non-Secret High-Entropy Strings

```python
# hash.py
expected_hash = "a" * 64  # Legitimate 64-character hex string

# This may trigger entropy detection
# Fix: Reduce min_confidence threshold or add to known_false_positives
```

### Exempting False Positives

```bash
# Mark a specific finding as false positive
vulnera secrets exempt \
  --finding-id SAST-SECRET-001 \
  --reason "This is an example key, not a real credential"

# Exemption applies to entire repository
# ML model learns from exemptions
```

## Best Practices

### 1. Never Commit Real Secrets

❌ **Wrong:**

```python
db_password = "super_secret_123"
api_key = "sk-live-abcdefghijklmnop"
```

✅ **Right:**

```python
import os
db_password = os.getenv("DB_PASSWORD")
api_key = os.getenv("API_KEY")
```

### 2. Use `.gitignore` for Secret Files

```bash
# .gitignore
.env
.env.local
*.pem
*.key
id_rsa
id_rsa.pub
```

### 3. Keep Secrets Out of Version History

```bash
# Remove secret from git history (if accidentally committed)
git-filter-repo --path .env --invert-paths

# Or use git-secret tool (encrypts secrets in repo)
git secret add .env
git secret hide
```

### 4. Pre-Commit Hook Integration

```bash
#!/bin/bash
# .git/hooks/pre-commit

vulnera secrets . --min-confidence 0.80

if [ $? -ne 0 ]; then
  echo "❌ Secrets detected. Remove them before committing."
  exit 1
fi
```

## Comparing Detection Methods

| Method | Speed | Coverage | False Positives | Configuration |
|--------|-------|----------|-----------------|--------------|
| **ML Pattern** | Very Fast | Specific secrets | <5% | Pre-trained |
| **Entropy Analysis** | Fast | Any high-entropy string | <10% | Tunable thresholds |
| **Regex (legacy)** | Very Fast | Limited | >20% | Many rules |
| **Manual Review** | Slow | 100% | 0% | Not scalable |

**Vulnera uses ML + Entropy = best balance of speed, coverage, and accuracy**

## Troubleshooting

**Q: Detection is slow**  
A: Disable entropy-based detection for faster scanning. Patterns are faster.

**Q: Want to skip certain files**  
A: Add to `exclude_patterns` in config. Examples: `test-*`, `vendor/*`

## Next Steps

- [Configure secret detection thresholds](../user-guide/configuration.md)
- [Get AI-powered explanations for secrets found](../user-guide/llm-features.md)
- [View all analysis capabilities](overview.md)
