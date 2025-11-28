# CLI Reference

A comprehensive guide to using the Vulnera command-line interface for vulnerability analysis.

## Installation

### Building from Source

```bash
# Clone the repository
git clone https://github.com/k5602/Vulnera.git
cd Vulnera

# Build with CLI feature enabled
cargo build --release --features cli

# The binary will be at ./target/release/vulnera-rust
alias vulnera='./target/release/vulnera-rust'
```

### Verify Installation

```bash
vulnera-rust --version
vulnera-rust --help
```

## Quick Start

### 1. Check Your Quota

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

```bash
# Full analysis (dependencies + SAST + secrets + API)
vulnera-rust analyze /path/to/project

# Or use the short alias
vulnera-rust a /path/to/project
```

### 3. Scan Dependencies Only

```bash
vulnera-rust deps .
vulnera-rust deps --file package.json
vulnera-rust deps . --severity high
```

## Authentication

### Why Authenticate?

| Feature | Unauthenticated | Authenticated |
|---------|-----------------|---------------|
| Daily requests | 10 | 40 |
| Vulnerability data | Cached only | Live + cached |
| Priority support | ❌ | ✅ |

### Login

```bash
# Interactive login
vulnera-rust auth login

# Login with API key directly
vulnera-rust auth login --api-key YOUR_API_KEY

# In CI/CD, use environment variable
export VULNERA_API_KEY=your_api_key
vulnera-rust --ci auth login
```

### Check Status

```bash
vulnera-rust auth status
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
vulnera-rust analyze [OPTIONS] [PATH]

# Examples
vulnera-rust analyze .                    # Current directory
vulnera-rust analyze /path/to/project     # Specific path
vulnera-rust a . --severity critical      # Only critical issues
vulnera-rust a . --skip-deps              # Skip dependency analysis
vulnera-rust a . --skip-sast              # Skip SAST
vulnera-rust a . --skip-secrets           # Skip secret detection
```

**Options:**

| Option | Description |
|--------|-------------|
| `--severity <LEVEL>` | Filter by minimum severity (low, medium, high, critical) |
| `--skip-deps` | Skip dependency vulnerability scanning |
| `--skip-sast` | Skip static analysis |
| `--skip-secrets` | Skip secret detection |
| `--skip-api` | Skip API security analysis |

### `deps` — Dependency Analysis

```bash
vulnera-rust deps [OPTIONS] [PATH]

# Examples
vulnera-rust deps .                       # Scan current directory
vulnera-rust deps --file Cargo.toml       # Specific manifest
vulnera-rust deps . --ecosystem npm       # Force ecosystem detection
vulnera-rust d . --severity high          # High+ severity only
```

**Supported ecosystems:**

- **npm**: `package.json`, `package-lock.json`
- **PyPI**: `requirements.txt`, `Pipfile`, `pyproject.toml`
- **Cargo**: `Cargo.toml`, `Cargo.lock`
- **Maven**: `pom.xml`
- **Go**: `go.mod`, `go.sum`
- **Composer**: `composer.json`, `composer.lock`
- **RubyGems**: `Gemfile`, `Gemfile.lock`
- **NuGet**: `*.csproj`, `packages.config`

### `sast` — Static Analysis

```bash
vulnera-rust sast [OPTIONS] [PATH]

# Examples
vulnera-rust sast .                       # Current directory
vulnera-rust sast src/                    # Specific folder
vulnera-rust s . --severity medium        # Medium+ severity
```

**Detects:** SQL injection, XSS, path traversal, command injection, insecure deserialization, and more.

### `secrets` — Secret Detection

```bash
vulnera-rust secrets [OPTIONS] [PATH]

# Examples
vulnera-rust secrets .                    # Current directory
vulnera-rust secrets --include-tests      # Include test files
vulnera-rust sec . --severity high        # High+ severity only
```

**Detects:** API keys (AWS, GCP, Azure, GitHub), database credentials, private keys, OAuth tokens, JWT secrets, generic passwords.

### `api` — API Security Analysis

```bash
vulnera-rust api [OPTIONS] [PATH]

# Examples
vulnera-rust api .                        # Scan for API definitions
vulnera-rust api --file openapi.yaml      # Specific OpenAPI spec
```

### `quota` — Quota Management

```bash
vulnera-rust quota              # Show quota status
vulnera-rust quota show         # Show quota status
vulnera-rust quota sync         # Sync with server
```

### `config` — Configuration Management

```bash
vulnera-rust config show        # Show current configuration
vulnera-rust config path        # Show config file locations
vulnera-rust config get server.port       # Get specific value
vulnera-rust config set server.port 8080  # Set value
vulnera-rust config init        # Create default config file
vulnera-rust config reset       # Reset to defaults
```

## Output Formats

### Table (Default)

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
```

### JSON

```bash
vulnera-rust --format json deps .
```

### Plain

```bash
vulnera-rust --format plain deps .
```

### SARIF

```bash
vulnera-rust --format sarif deps . > results.sarif
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
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success — no issues found |
| 1 | Vulnerabilities found (at or above threshold) |
| 2 | Configuration or input error |
| 3 | Network error (when online mode required) |
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
# Override server port
export VULNERA__SERVER__PORT=9000

# Override cache URL
export VULNERA__CACHE__DRAGONFLY_URL=redis://localhost:6380

# Enable CI mode
export VULNERA_CI=true

# Set API key
export VULNERA_API_KEY=your_api_key
```

### Offline Mode

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

## Troubleshooting

### "Quota exceeded"

**Solutions:**

1. Wait for quota reset at UTC midnight
2. Authenticate for 40 requests/day: `vulnera-rust auth login`
3. Use `--offline` mode for SAST/secrets (doesn't consume quota)

### "Failed to connect to cache"

This is normal if you don't have Dragonfly/Redis running locally. The CLI will work in offline mode.

### "Credentials not found"

**Solutions:**

1. Login: `vulnera-rust auth login`
2. Set environment variable: `export VULNERA_API_KEY=your_key`
3. Check storage: `vulnera-rust auth info`

### Verbose Output

```bash
vulnera-rust -v analyze .      # Verbose
vulnera-rust -vv analyze .     # Very verbose
```

## Getting Help

```bash
vulnera-rust --help
vulnera-rust analyze --help
vulnera-rust deps --help
```

Report issues at: <https://github.com/k5602/Vulnera/issues>
