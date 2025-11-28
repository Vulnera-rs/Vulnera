# CLI Reference

A comprehensive guide to using the Vulnera command-line interface for vulnerability analysis.

The Vulnera CLI is a standalone, distributable tool with offline-first architecture. It provides local vulnerability scanning (SAST, secrets, API analysis) and integrates with the Vulnera server for dependency analysis.

## Installation

### Building from Source

```bash
# Clone the repository
git clone https://github.com/k5602/Vulnera.git
cd Vulnera

# Build the CLI binary
cargo build -p vulnera-cli --release

# The binary will be at ./target/release/vulnera
alias vulnera='./target/release/vulnera'
```

### Download Pre-built Binary

Pre-built binaries available at: [GitHub Releases](https://github.com/k5602/Vulnera/releases)

```bash
# Linux
curl -L https://github.com/k5602/Vulnera/releases/latest/download/vulnera-linux-x86_64 -o vulnera
chmod +x vulnera

# macOS
curl -L https://github.com/k5602/Vulnera/releases/latest/download/vulnera-macos-x86_64 -o vulnera
chmod +x vulnera

# Windows: Download from releases page
```

### Verify Installation

```bash
vulnera --version
vulnera --help
```

## Quick Start

### 1. Check Your Quota

```bash
vulnera quota
```

Output:

```text
Quota Status
Usage: [░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 0/10
Remaining: 10 requests
Resets in: 8h 12m (UTC midnight)
Account: Unauthenticated (10 requests/day)
```

### 2. Run Your First Scan

```bash
# Full analysis (SAST + secrets + API + optional dependencies)
vulnera analyze /path/to/project

# Or use the short alias
vulnera a /path/to/project
```

### 3. Scan Dependencies Only (Requires Server)

```bash
vulnera deps .
vulnera deps --file package.json
vulnera deps . --severity high
```

## Authentication

### Why Authenticate?

| Feature | Unauthenticated | Authenticated |
|---------|-----------------|---------------|
| Daily requests | 10 | 40 |
| Dependency analysis | Server required | ✅ |
| Local analysis (SAST/secrets) | ✅ | ✅ |
| Offline mode | ✅ | ✅ |

### Login

```bash
# Interactive login
vulnera auth login

# Login with API key directly
vulnera auth login --api-key YOUR_API_KEY

# In CI/CD, use environment variable
export VULNERA_API_KEY=your_api_key
vulnera auth login
```

### Check Status

```bash
vulnera auth status
```

### Credential Storage

Vulnera stores credentials securely:

1. **OS Keyring** (preferred): Uses your system's native credential store
   - macOS: Keychain
   - Linux: Secret Service (GNOME Keyring, KWallet)
   - Windows: Credential Manager

2. **Encrypted File** (fallback): AES-256-GCM encrypted file at `~/.config/vulnera-cli/credentials.enc`

## Commands

### `analyze` — Full Vulnerability Analysis

```bash
vulnera analyze [OPTIONS] [PATH]

# Examples
vulnera analyze .                    # Current directory
vulnera analyze /path/to/project     # Specific path
vulnera a . --severity critical      # Only critical issues
```

**Options:**

| Option | Description |
|--------|-------------|
| `--severity <LEVEL>` | Filter by minimum severity (low, medium, high, critical) |
| `-f, --format <FORMAT>` | Output format (table, json, plain, sarif) |

**Behavior:**

- Runs SAST, secret detection, and API analysis locally (always works offline)
- Attempts dependency analysis if server is available; skips with warning if offline

### `deps` — Dependency Analysis

```bash
vulnera deps [OPTIONS] [PATH]

# Examples
vulnera deps .                       # Scan current directory
vulnera deps --file Cargo.toml       # Specific manifest
vulnera deps . --severity high       # High+ severity only
```

**Requires:** Vulnera server running or API key configured

**Supported ecosystems:**

- **npm**: `package.json`, `package-lock.json`
- **PyPI**: `requirements.txt`, `Pipfile`, `pyproject.toml`
- **Cargo**: `Cargo.toml`, `Cargo.lock`
- **Maven**: `pom.xml`
- **Go**: `go.mod`, `go.sum`
- **Composer**: `composer.json`, `composer.lock`
- **RubyGems**: `Gemfile`, `Gemfile.lock`
- **NuGet**: `*.csproj`, `packages.config`

### `sast` — Static Analysis (Offline)

```bash
vulnera sast [OPTIONS] [PATH]

# Examples
vulnera sast .                       # Current directory
vulnera sast src/                    # Specific folder
vulnera s . --severity medium        # Medium+ severity
```

**Detects:** SQL injection, XSS, path traversal, command injection, insecure deserialization, and more.

### `secrets` — Secret Detection (Offline)

```bash
vulnera secrets [OPTIONS] [PATH]

# Examples
vulnera secrets .                    # Current directory
vulnera secrets --include-tests      # Include test files
vulnera sec . --severity high        # High+ severity only
```

**Detects:** API keys (AWS, GCP, Azure, GitHub), database credentials, private keys, OAuth tokens, JWT secrets, generic passwords.

### `api` — API Security Analysis (Offline)

```bash
vulnera api [OPTIONS] [PATH]

# Examples
vulnera api .                        # Scan for API definitions
vulnera api --file openapi.yaml      # Specific OpenAPI spec
```

### `quota` — Quota Management

```bash
vulnera quota              # Show quota status
vulnera quota show         # Show quota status
vulnera quota sync         # Sync with server
```

### `auth` — Authentication

```bash
vulnera auth login         # Login interactively
vulnera auth logout        # Logout
vulnera auth status        # Check authentication status
vulnera auth info          # Show API key info
```

### `config` — Configuration Management

```bash
vulnera config show        # Show current configuration
vulnera config path        # Show config file locations
vulnera config get server.port       # Get specific value
vulnera config set server.port 8080  # Set value
vulnera config init        # Create default config file
vulnera config reset       # Reset to defaults
```

## Output Formats

### Table (Default)

```bash
vulnera deps .
```

Output:

```text
┌──────────────────┬──────────┬──────────┬────────────────────┐
│ Package          │ Version  │ Severity │ Vulnerability      │
├──────────────────┼──────────┼──────────┼────────────────────┤
│ lodash           │ 4.17.15  │ Critical │ CVE-2021-23337     │
│ axios            │ 0.21.0   │ High     │ CVE-2021-3749      │
└──────────────────┴──────────┴──────────┴────────────────────┘
```

### JSON

```bash
vulnera --format json deps .
```

### Plain

```bash
vulnera --format plain deps .
```

### SARIF

```bash
vulnera --format sarif deps . > results.sarif
```

Compatible with VS Code (SARIF Viewer), GitHub Code Scanning, Azure DevOps, SonarQube.

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
      
      - name: Download Vulnera CLI
        run: |
          curl -L https://github.com/k5602/Vulnera/releases/latest/download/vulnera-linux-x86_64 -o vulnera
          chmod +x vulnera
      
      - name: Run vulnerability scan
        env:
          VULNERA_API_KEY: ${{ secrets.VULNERA_API_KEY }}
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
    VULNERA_API_KEY: $VULNERA_API_KEY
  script:
    - curl -L https://github.com/k5602/Vulnera/releases/latest/download/vulnera-linux-x86_64 -o vulnera
    - chmod +x vulnera
    - ./vulnera analyze . --format json > vulnera-report.json
  artifacts:
    reports:
      security: vulnera-report.json
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success — no issues found |
| 1 | Vulnerabilities found (at or above threshold) |
| 2 | Configuration or input error |
| 3 | Network error (when server required) |
| 4 | Quota exceeded |
| 5 | Authentication required |
| 99 | Internal error |

## Configuration

### Configuration Files

Vulnera looks for configuration in this order:

1. `.vulnera.toml` (project directory)
2. `vulnera.toml` (project directory)
3. `~/.config/vulnera-cli/config.toml` (user config)
4. `/etc/vulnera/config.toml` (system config — Unix only)

### Environment Variables

```bash
# Set server host/port for dependency analysis
export VULNERA__SERVER__HOST=localhost
export VULNERA__SERVER__PORT=9000

# Set API key for authentication
export VULNERA_API_KEY=your_api_key
```

### Offline Mode

```bash
# Force offline mode (skips dependency analysis)
vulnera --offline analyze .

# Or set environment variable
export VULNERA_OFFLINE=true
```

In offline mode:

- ✅ SAST analysis works fully
- ✅ Secret detection works fully
- ✅ API analysis works fully
- ⚠️ Dependency analysis is skipped with warning

## Troubleshooting

### "Quota exceeded"

**Solutions:**

1. Wait for quota reset at UTC midnight
2. Authenticate for 40 requests/day: `vulnera auth login`
3. Use offline analysis (SAST/secrets) which doesn't consume quota

### "Failed to connect to server"

This is normal if the Vulnera server isn't running. The CLI will work in offline mode.

**Solutions:**

1. Start the server: `cargo run -p vulnera-orchestrator`
2. Use offline modules: `vulnera analyze .` (runs SAST/secrets/API locally)
3. Set server address: `export VULNERA__SERVER__HOST=your-server`

### "Credentials not found"

**Solutions:**

1. Login: `vulnera auth login`
2. Set environment variable: `export VULNERA_API_KEY=your_key`
3. Check storage: `vulnera auth info`

### Verbose Output

```bash
vulnera -v analyze .      # Verbose
vulnera -vv analyze .     # Very verbose
```

## Getting Help

```bash
vulnera --help
vulnera analyze --help
vulnera deps --help
```

Report issues at: [GitHub Issues](https://github.com/k5602/Vulnera/issues)
