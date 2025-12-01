# Developer Quick Start (5 Minutes)

**For:** Individual developers who want offline vulnerability scanning integrated into their workflow.

**Goal:** Run your first security analysis on a local project in under 5 minutes.

## Install Vulnera CLI

Choose your platform:

### macOS

```bash
curl -L https://github.com/k5602/Vulnera/releases/latest/download/vulnera-macos-x86_64 -o vulnera
chmod +x vulnera
sudo mv vulnera /usr/local/bin/
```

### Linux

```bash
curl -L https://github.com/k5602/Vulnera/releases/latest/download/vulnera-linux-x86_64 -o vulnera
chmod +x vulnera
sudo mv vulnera /usr/local/bin/
```

### Windows

Download from [GitHub Releases](https://github.com/k5602/Vulnera/releases), add to PATH.

### Verify Installation

```bash
vulnera --version
# Output: Vulnera 0.3.0
```

## Run Your First Analysis (Offline)

```bash
# Analyze your current project
vulnera analyze .

# Or any directory
vulnera analyze /path/to/my/nodejs-app
```

**What happens:**

- ✅ Scans all code files for security issues
- ✅ Detects hardcoded secrets (API keys, tokens, credentials)
- ✅ Checks for code injection vulnerabilities
- ✅ Analyzes OpenAPI specs if present
- ⏱️ Takes 1-10 seconds depending on project size

**Output (default table view):**

```
┌────────────────────────────────────────────────────────────┐
│ Vulnera Security Analysis Report                           │
├────────────────────────────────────────────────────────────┤
│ Analysis Duration: 2.3 seconds                              │
│ Modules Run: SAST, Secrets, API                             │
│ Total Findings: 5                                           │
├────────────────────────────────────────────────────────────┤
│ SEVERITY │ COUNT │ MODULE        │ REMEDIATION               │
├──────────┼───────┼───────────────┼──────────────────────────┤
│ HIGH     │ 2     │ Secrets       │ Remove hardcoded keys    │
│ MEDIUM   │ 2     │ SAST (Python) │ Use parameterized queries│
│ LOW      │ 1     │ API Spec      │ Add security headers     │
└────────────────────────────────────────────────────────────┘
```

## See Detailed Findings

```bash
vulnera analyze . --format json | jq '.findings[]'
```

**Sample finding:**

```json
{
  "id": "SAST-SQL-001",
  "type": "SQL Injection",
  "severity": "high",
  "file": "app.py",
  "line": 42,
  "message": "User input concatenated into SQL query",
  "code": "query = f\"SELECT * FROM users WHERE id={user_id}\"",
  "remediation": "Use parameterized queries: db.query('SELECT * FROM users WHERE id=?', [user_id])"
}
```

## Get AI-Powered Explanations

Want to understand why a finding is important?

```bash
# Option 1: Output directly shows summaries
vulnera analyze . --format table

# Option 2: Export to JSON and filter
vulnera analyze . --format json | jq '.findings[] | {id, type, message, remediation}'
```

## Authenticate for Extra Features

Get 4x more quota and enable dependency scanning:

```bash
# Get API key at: https://vulnera.studio/dashboard/keys
vulnera auth login --api-key YOUR_API_KEY

# Now you can scan dependencies
vulnera analyze . --all-modules
```

## Pre-Commit Integration

Automatically scan before commits:

### Add to `.git/hooks/pre-commit`

```bash
#!/bin/sh
# Run Vulnera analysis on staged files
vulnera analyze . --severity high

if [ $? -ne 0 ]; then
  echo "❌ Security issues found. Fix before committing."
  exit 1
fi
```

### Make it Executable

```bash
chmod +x .git/hooks/pre-commit
```

### Test It

```bash
git add .
git commit -m "test"
# Will run Vulnera scan before commit
```

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/security.yml`:

```yaml
name: Security Analysis

on: [push, pull_request]

jobs:
  vulnera:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
        with:
          name: vulnera
      - run: chmod +x vulnera && ./vulnera analyze . --severity high
```

### GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
security:
  script:
    - curl -L https://github.com/k5602/Vulnera/releases/latest/download/vulnera-linux-x86_64 -o vulnera
    - chmod +x vulnera
    - ./vulnera analyze . --severity high
```

## Common Commands

```bash
# Analyze only secrets (skip code analysis)
vulnera analyze . --skip-sast

# Show only high/critical severity
vulnera analyze . --severity high

# Export to SARIF (for IDE integration)
vulnera analyze . --format sarif > report.sarif

# Check your quota
vulnera quota

# Offline mode (don't use dependency scanning)
vulnera analyze . --offline
```

## Next Steps

1. **Integrate into your IDE** → [IDE Extensions](../../integration/extensions.md)
2. **Learn about all analysis types** → [Analysis Capabilities](../../analysis/overview.md)
3. **Get AI-powered explanations** → [LLM Features](../../user-guide/llm-features.md)
4. **Setup for team usage** → [DevSecOps Quick Start](devsecops-quickstart.md)

## Troubleshooting

**Q: No findings found—is it working?**  
A: That's good! Your code is secure. Try with `--show-passed` to see all checks run.

**Q: Getting "permission denied" error?**  
A: Make sure the binary is executable: `chmod +x vulnera`

**Q: Want to see what's detected?**  
A: Run with verbose output: `vulnera analyze . -v`

**Q: Dependency scanning not working?**  
A: You need to authenticate. Get an API key at <https://vulnera.studio/dashboard/keys>

---

**Questions?** Join us on [Discord](https://discord.gg/vulnera) or check the [full documentation](../../README.md).
