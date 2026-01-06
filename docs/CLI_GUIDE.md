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

### From Pre-built Binaries

The easiest way to get Vulnera is to download the latest binary for your platform from the [GitHub Releases](https://github.com/k5602/Vulnera/releases) page:

```bash
# Linux (x86_64)
curl -L https://github.com/k5602/Vulnera/releases/latest/download/vulnera-linux-x86_64 -o vulnera
chmod +x vulnera
sudo mv vulnera /usr/local/bin/

# macOS (universal)
curl -L https://github.com/k5602/Vulnera/releases/latest/download/vulnera-macos -o vulnera
chmod +x vulnera
sudo mv vulnera /usr/local/bin/
```

### Building from Source

If you have Rust installed, you can build the CLI directly from the source:

```bash
# Clone the repository
git clone https://github.com/k5602/Vulnera.git
cd Vulnera/vulnera-cli

# Build the standalone CLI
cargo build --release

# The binary will be at ./target/release/vulnera
# Optionally, install it to your cargo bin directory
cargo install --path .
```

### Verify Installation

```bash
vulnera --version
vulnera --help
```

---

## Quick Start

### 1. Check Your Quota

Before running scans, check your available quota:

```bash
vulnera quota
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
vulnera analyze /path/to/project

# Or use the short alias
vulnera a /path/to/project
```

### 3. Scan Dependencies Only

```bash
# Scan current directory
vulnera deps .

# Scan a specific manifest file
vulnera deps --file package.json

# Scan with specific severity threshold
vulnera deps . --severity high
```

### 4. Run SAST (Static Analysis)

```bash
vulnera sast /path/to/project
```

### 5. Detect Secrets

```bash
vulnera secrets /path/to/project
```

---

## Authentication

### Why Authenticate?

| Feature            | Unauthenticated | Authenticated |
| ------------------ | --------------- | ------------- |
| Daily requests     | 10              | 40            |
| Vulnerability data | Cached only     | Live + cached |
| Priority support   | ❌              | ✅            |

### Login with API Key

```bash
# Interactive login (prompts for API key)
vulnera auth login

# Login with API key directly
vulnera auth login --api-key YOUR_API_KEY

# In CI/CD, use environment variable
export VULNERA_API_KEY=your_api_key
vulnera --ci auth login
```

### Check Authentication Status

```bash
vulnera auth status
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
vulnera auth logout
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
vulnera auth info
```

---

## Commands

### `analyze` - Full Vulnerability Analysis

Run all analysis types on a project.

```bash
vulnera analyze [OPTIONS] [PATH]

# Examples
vulnera analyze .                    # Current directory
vulnera analyze /path/to/project     # Specific path
vulnera a . --severity critical      # Only critical issues
vulnera a . --skip-deps              # Skip dependency analysis
vulnera a . --skip-sast              # Skip SAST
vulnera a . --skip-secrets           # Skip secret detection
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
vulnera deps [OPTIONS] [PATH]

# Examples
vulnera deps .                       # Scan current directory
vulnera deps --file Cargo.toml       # Specific manifest
vulnera deps . --ecosystem npm       # Force ecosystem detection
vulnera d . --severity high          # High+ severity only
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
vulnera sast [OPTIONS] [PATH]

# Examples
vulnera sast .                       # Current directory
vulnera sast src/                    # Specific folder
vulnera s . --severity medium        # Medium+ severity
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
vulnera secrets [OPTIONS] [PATH]

# Examples
vulnera secrets .                    # Current directory
vulnera secrets --include-tests      # Include test files
vulnera sec . --severity high        # High+ severity only
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
vulnera api [OPTIONS] [PATH]

# Examples
vulnera api .                        # Scan for API definitions
vulnera api --file openapi.yaml      # Specific OpenAPI spec
```

### `quota` - Quota Management

View and manage your usage quota.

```bash
vulnera quota [COMMAND]

# Commands
vulnera quota              # Show quota status (default)
vulnera quota show         # Show quota status
vulnera quota sync         # Sync with server
vulnera q                  # Short alias
```

### `config` - Configuration Management

View and modify configuration.

```bash
vulnera config [COMMAND]

# Commands
vulnera config show        # Show current configuration
vulnera config path        # Show config file locations
vulnera config get server.port       # Get specific value
vulnera config set server.port 8080  # Set value
vulnera config init        # Create default config file
vulnera config init --local          # Create in project directory
vulnera config reset       # Reset to defaults
```

---

## Output Formats

### Table (Default)

Human-readable tabular format, ideal for terminal use.

```bash
vulnera deps .
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
vulnera --format json deps .
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
vulnera --format plain deps .
```

```
lodash@4.17.15 - CRITICAL - CVE-2021-23337
axios@0.21.0 - HIGH - CVE-2021-3749
```

### SARIF

Static Analysis Results Interchange Format for IDE integration.

```bash
vulnera --format sarif deps . > results.sarif
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
    - cargo install --git https://github.com/k5602/Vulnera --target-dir vulnera-cli
    - vulnera analyze . --format json > vulnera-report.json
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
        entry: vulnera secrets . --ci
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
vulnera --ci secrets . --severity critical
if [ $? -ne 0 ]; then
    echo "❌ Secrets detected! Please remove them before committing."
    exit 1
fi

echo "✅ Security checks passed"
```

### Exit Codes

Use exit codes in CI pipelines:

| Code | Meaning                                       |
| ---- | --------------------------------------------- |
| 0    | Success - no issues found                     |
| 1    | Vulnerabilities found (at or above threshold) |
| 2    | Configuration or input error                  |
| 3    | Network error (when online mode required)     |
| 4    | Quota exceeded                                |
| 5    | Authentication required                       |
| 99   | Internal error                                |

Example usage:

```bash
vulnera --ci deps . --severity high
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
vulnera --offline analyze .

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
vulnera -v analyze .      # Verbose
vulnera -vv analyze .     # Very verbose (if supported)
```

### Check System Info

```bash
# Show version
vulnera --version

# Show config locations
vulnera config path

# Show auth storage method
vulnera auth info
```

---

## Examples

### Scan a Node.js Project

```bash
cd my-node-project
vulnera analyze . --format json > security-report.json
```

### Scan Only for Critical Issues

```bash
vulnera deps . --severity critical
```

### CI Pipeline with Failure Threshold

```bash
#!/bin/bash
# Fail if any high or critical vulnerabilities found
vulnera --ci analyze . --severity high
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
vulnera --format sarif analyze . > .vscode/vulnera.sarif
```

Then install the "SARIF Viewer" VS Code extension to see results inline.

---

## Getting Help

```bash
# General help
vulnera --help

# Command-specific help
vulnera analyze --help
vulnera deps --help
vulnera auth --help

# Check quota and status
vulnera quota
vulnera auth status
```

## Feedback

Report issues or request features at: <https://github.com/k5602/Vulnera/issues>
