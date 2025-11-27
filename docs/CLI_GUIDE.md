# Vulnera CLI Guide

A comprehensive guide to using the Vulnera command-line interface for vulnerability analysis.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Authentication](#authentication)
- [Commands](#commands)
- [Output Formats](#output-formats)
- [CI/CD Integration](#cicd-integration)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Building from Source

```bash
# Clone the repository
git clone https://github.com/k5602/Vulnera.git
cd Vulnera

# Build with CLI feature enabled
cargo build --release --features cli

# The binary will be at ./target/release/vulnera-rust
# Optionally, add to PATH or create an alias
alias vulnera='./target/release/vulnera-rust'
there will be a better distribution method in the future.
```

### Verify Installation

```bash
vulnera-rust --version
vulnera-rust --help
```

---

## Quick Start

### 1. Check Your Quota

Before running scans, check your available quota:

```bash
vulnera-rust quota
```

Output:

```
Quota Status
Usage: [░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 0/10
Remaining: 10 requests
Resets in: 8h 12m (UTC midnight)
Account: Unauthenticated (10 requests/day)
```

### 2. Run Your First Scan

Analyze a project directory for all vulnerabilities:

```bash
# Full analysis (dependencies + SAST + secrets + API)
vulnera-rust analyze /path/to/project

# Or use the short alias
vulnera-rust a /path/to/project
```

### 3. Scan Dependencies Only

```bash
# Scan current directory
vulnera-rust deps .

# Scan a specific manifest file
vulnera-rust deps --file package.json

# Scan with specific severity threshold
vulnera-rust deps . --severity high
```

### 4. Run SAST (Static Analysis)

```bash
vulnera-rust sast /path/to/project
```

### 5. Detect Secrets

```bash
vulnera-rust secrets /path/to/project
```

---

## Authentication

### Why Authenticate?

| Feature | Unauthenticated | Authenticated |
|---------|-----------------|---------------|
| Daily requests | 10 | 40 |
| Vulnerability data | Cached only | Live + cached |
| Priority support | ❌ | ✅ |

### Login with API Key

```bash
# Interactive login (prompts for API key)
vulnera-rust auth login

# Login with API key directly
vulnera-rust auth login --api-key YOUR_API_KEY

# In CI/CD, use environment variable
export VULNERA_API_KEY=your_api_key
vulnera-rust --ci auth login
```

### Check Authentication Status

```bash
vulnera-rust auth status
```

Output:

```
Authentication Status
✓ Authenticated
Daily limit: 40 requests
Storage: OS Keyring
Server connection: Online
```

### Logout

```bash
vulnera-rust auth logout
```

### Credential Storage

Vulnera stores credentials securely:

1. **OS Keyring** (preferred): Uses your system's native credential store
   - macOS: Keychain
   - Linux: Secret Service (GNOME Keyring, KWallet)
   - Windows: Credential Manager

2. **Encrypted File** (fallback): AES-256-GCM encrypted file at `~/.config/vulnera-cli/credentials.enc`

Check where credentials are stored:

```bash
vulnera-rust auth info
```

---

## Commands

### `analyze` - Full Vulnerability Analysis

Run all analysis types on a project.

```bash
vulnera-rust analyze [OPTIONS] [PATH]

# Examples
vulnera-rust analyze .                    # Current directory
vulnera-rust analyze /path/to/project     # Specific path
vulnera-rust a . --severity critical      # Only critical issues
vulnera-rust a . --skip-deps              # Skip dependency analysis
vulnera-rust a . --skip-sast              # Skip SAST
vulnera-rust a . --skip-secrets           # Skip secret detection
```

Options:

- `--severity <LEVEL>`: Filter by minimum severity (low, medium, high, critical)
- `--skip-deps`: Skip dependency vulnerability scanning
- `--skip-sast`: Skip static analysis
- `--skip-secrets`: Skip secret detection
- `--skip-api`: Skip API security analysis

### `deps` - Dependency Analysis

Scan dependencies for known vulnerabilities.

```bash
vulnera-rust deps [OPTIONS] [PATH]

# Examples
vulnera-rust deps .                       # Scan current directory
vulnera-rust deps --file Cargo.toml       # Specific manifest
vulnera-rust deps . --ecosystem npm       # Force ecosystem detection
vulnera-rust d . --severity high          # High+ severity only
```

Supported ecosystems:

- **npm**: `package.json`, `package-lock.json`
- **PyPI**: `requirements.txt`, `Pipfile`, `pyproject.toml`
- **Cargo**: `Cargo.toml`, `Cargo.lock`
- **Maven**: `pom.xml`
- **Go**: `go.mod`, `go.sum`
- **Composer**: `composer.json`, `composer.lock`
- **RubyGems**: `Gemfile`, `Gemfile.lock`
- **NuGet**: `*.csproj`, `packages.config`

### `sast` - Static Analysis

Run static application security testing.

```bash
vulnera-rust sast [OPTIONS] [PATH]

# Examples
vulnera-rust sast .                       # Current directory
vulnera-rust sast src/                    # Specific folder
vulnera-rust s . --severity medium        # Medium+ severity
```

Detects:

- SQL injection vulnerabilities
- Cross-site scripting (XSS)
- Path traversal
- Command injection
- Insecure deserialization
- And more...

### `secrets` - Secret Detection

Find hardcoded secrets and credentials.

```bash
vulnera-rust secrets [OPTIONS] [PATH]

# Examples
vulnera-rust secrets .                    # Current directory
vulnera-rust secrets --include-tests      # Include test files
vulnera-rust sec . --severity high        # High+ severity only
```

Detects:

- API keys (AWS, GCP, Azure, GitHub, etc.)
- Database credentials
- Private keys (RSA, SSH, PGP)
- OAuth tokens
- JWT secrets
- Generic passwords and secrets

### `api` - API Security Analysis

Analyze API endpoints for security issues.

```bash
vulnera-rust api [OPTIONS] [PATH]

# Examples
vulnera-rust api .                        # Scan for API definitions
vulnera-rust api --file openapi.yaml      # Specific OpenAPI spec
```

### `quota` - Quota Management

View and manage your usage quota.

```bash
vulnera-rust quota [COMMAND]

# Commands
vulnera-rust quota              # Show quota status (default)
vulnera-rust quota show         # Show quota status
vulnera-rust quota sync         # Sync with server
vulnera-rust q                  # Short alias
```

### `config` - Configuration Management

View and modify configuration.

```bash
vulnera-rust config [COMMAND]

# Commands
vulnera-rust config show        # Show current configuration
vulnera-rust config path        # Show config file locations
vulnera-rust config get server.port       # Get specific value
vulnera-rust config set server.port 8080  # Set value
vulnera-rust config init        # Create default config file
vulnera-rust config init --local          # Create in project directory
vulnera-rust config reset       # Reset to defaults
```

---

## Output Formats

### Table (Default)

Human-readable tabular format, ideal for terminal use.

```bash
vulnera-rust deps .
```

```
┌──────────────────┬──────────┬──────────┬────────────────────┐
│ Package          │ Version  │ Severity │ Vulnerability      │
├──────────────────┼──────────┼──────────┼────────────────────┤
│ lodash           │ 4.17.15  │ Critical │ CVE-2021-23337     │
│ axios            │ 0.21.0   │ High     │ CVE-2021-3749      │
└──────────────────┴──────────┴──────────┴────────────────────┘

Found 2 vulnerabilities (1 critical, 1 high)
```

### JSON

Machine-readable JSON output for scripting and integrations.

```bash
vulnera-rust --format json deps .
```

```json
{
  "vulnerabilities": [
    {
      "package": "lodash",
      "version": "4.17.15",
      "severity": "critical",
      "cve": "CVE-2021-23337",
      "description": "Command Injection in lodash"
    }
  ],
  "summary": {
    "total": 2,
    "critical": 1,
    "high": 1,
    "medium": 0,
    "low": 0
  }
}
```

### Plain

Minimal text output without formatting.

```bash
vulnera-rust --format plain deps .
```

```
lodash@4.17.15 - CRITICAL - CVE-2021-23337
axios@0.21.0 - HIGH - CVE-2021-3749
```

### SARIF

Static Analysis Results Interchange Format for IDE integration.

```bash
vulnera-rust --format sarif deps . > results.sarif
```

Compatible with:

- VS Code (SARIF Viewer extension)
- GitHub Code Scanning
- Azure DevOps
- SonarQube

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  vulnera-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Vulnera CLI
        run: |
          curl -L https://github.com/k5602/Vulnera/releases/latest/download/vulnera-linux-amd64 -o vulnera
          chmod +x vulnera
      
      - name: Run vulnerability scan
        env:
          VULNERA_API_KEY: ${{ secrets.VULNERA_API_KEY }}
          VULNERA_CI: "true"
        run: |
          ./vulnera analyze . --format sarif > results.sarif
        continue-on-error: true
      
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  stage: test
  image: rust:latest
  variables:
    VULNERA_CI: "true"
    VULNERA_API_KEY: $VULNERA_API_KEY
  script:
    - cargo install --git https://github.com/k5602/Vulnera --features cli
    - vulnera-rust analyze . --format json > vulnera-report.json
  artifacts:
    reports:
      security: vulnera-report.json
    paths:
      - vulnera-report.json
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: vulnera-secrets
        name: Check for secrets
        entry: vulnera-rust secrets . --ci
        language: system
        pass_filenames: false
        always_run: true
```

Or manually in `.git/hooks/pre-commit`:

```bash
#!/bin/bash
set -e

echo "Running Vulnera security checks..."

# Check for secrets (critical only to avoid false positives)
vulnera-rust --ci secrets . --severity critical
if [ $? -ne 0 ]; then
    echo "❌ Secrets detected! Please remove them before committing."
    exit 1
fi

echo "✅ Security checks passed"
```

### Exit Codes

Use exit codes in CI pipelines:

| Code | Meaning |
|------|---------|
| 0 | Success - no issues found |
| 1 | Vulnerabilities found (at or above threshold) |
| 2 | Configuration or input error |
| 3 | Network error (when online mode required) |
| 4 | Quota exceeded |
| 5 | Authentication required |
| 99 | Internal error |

Example usage:

```bash
vulnera-rust --ci deps . --severity high
case $? in
    0) echo "No vulnerabilities found" ;;
    1) echo "Vulnerabilities found - failing build" && exit 1 ;;
    4) echo "Quota exceeded - skipping scan" ;;
    *) echo "Error occurred" && exit 1 ;;
esac
```

---

## Configuration

### Configuration Files

Vulnera looks for configuration in this order:

1. `.vulnera.toml` (project directory)
2. `vulnera.toml` (project directory)
3. `~/.config/vulnera-cli/config.toml` (user config)
4. `/etc/vulnera/config.toml` (system config - Unix only)

### Environment Variables

Override any config value with `VULNERA__` prefix:

```bash
# Override server port
export VULNERA__SERVER__PORT=9000

# Override cache URL
export VULNERA__CACHE__DRAGONFLY_URL=redis://localhost:6380

# Enable CI mode
export VULNERA_CI=true

# Set API key
export VULNERA_API_KEY=your_api_key
```

### Sample Configuration

Create with `vulnera-rust config init`:

```toml
# ~/.config/vulnera-cli/config.toml

[server]
host = "127.0.0.1"
port = 8080

[server.rate_limit]
enabled = true
storage_backend = "dragonfly"

[server.rate_limit.tiers.api_key]
requests_per_minute = 100
requests_per_hour = 2000

[server.rate_limit.tiers.authenticated]
requests_per_minute = 60
requests_per_hour = 1000

[server.rate_limit.tiers.anonymous]
requests_per_minute = 20
requests_per_hour = 100

[analysis]
max_concurrent_packages = 10

[cache]
dragonfly_url = "redis://127.0.0.1:6379"
```

### Offline Mode

Run analysis without network connectivity:

```bash
# Force offline mode
vulnera-rust --offline analyze .

# Or set environment variable
export VULNERA_OFFLINE=true
```

In offline mode:

- ✅ SAST analysis works fully
- ✅ Secret detection works fully
- ✅ API analysis works fully
- ⚠️ Dependency analysis uses cached vulnerability data only

---

## Troubleshooting

### "Quota exceeded"

```
Error: Daily quota exceeded (10/10 requests used)
Resets in: 5h 23m
```

**Solutions:**

1. Wait for quota reset at UTC midnight
2. Authenticate for 40 requests/day: `vulnera-rust auth login`
3. Use `--offline` mode for SAST/secrets (doesn't consume quota)

### "Failed to connect to cache"

```
Warning: Failed to connect to cache, running in offline mode
```

This is normal if you don't have Dragonfly/Redis running locally. The CLI will work in offline mode.

### "Credentials not found"

```
Error: No API key found
```

**Solutions:**

1. Login: `vulnera-rust auth login`
2. Set environment variable: `export VULNERA_API_KEY=your_key`
3. Check storage: `vulnera-rust auth info`

### "Permission denied" on Linux

If keyring access fails:

```bash
# Install secret service
sudo apt install gnome-keyring  # Debian/Ubuntu
sudo dnf install gnome-keyring  # Fedora

# Or use file-based storage (will use encrypted file fallback)
```

### Verbose Output

For debugging, enable verbose mode:

```bash
vulnera-rust -v analyze .      # Verbose
vulnera-rust -vv analyze .     # Very verbose (if supported)
```

### Check System Info

```bash
# Show version
vulnera-rust --version

# Show config locations
vulnera-rust config path

# Show auth storage method
vulnera-rust auth info
```

---

## Examples

### Scan a Node.js Project

```bash
cd my-node-project
vulnera-rust analyze . --format json > security-report.json
```

### Scan Only for Critical Issues

```bash
vulnera-rust deps . --severity critical
```

### CI Pipeline with Failure Threshold

```bash
#!/bin/bash
# Fail if any high or critical vulnerabilities found
vulnera-rust --ci analyze . --severity high
exit_code=$?

if [ $exit_code -eq 1 ]; then
    echo "❌ High/Critical vulnerabilities found"
    exit 1
elif [ $exit_code -eq 0 ]; then
    echo "✅ No high/critical vulnerabilities"
    exit 0
else
    echo "⚠️ Scan error (exit code: $exit_code)"
    exit $exit_code
fi
```

### Generate SARIF Report for VS Code

```bash
vulnera-rust --format sarif analyze . > .vscode/vulnera.sarif
```

Then install the "SARIF Viewer" VS Code extension to see results inline.

---

## Getting Help

```bash
# General help
vulnera-rust --help

# Command-specific help
vulnera-rust analyze --help
vulnera-rust deps --help
vulnera-rust auth --help

# Check quota and status
vulnera-rust quota
vulnera-rust auth status
```

## Feedback

Report issues or request features at: <https://github.com/k5602/Vulnera/issues>
