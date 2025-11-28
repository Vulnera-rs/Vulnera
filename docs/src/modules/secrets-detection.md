# Secrets Detection

The Secrets Detection Module identifies exposed secrets, credentials, API keys, and other sensitive information in source code and repositories.

## Detection Methods

| Method | Description |
|--------|-------------|
| **Regex-based** | Pattern matching for known secret formats with high precision |
| **Entropy-based** | Statistical analysis detecting high-entropy strings |
| **Git History** | Optional analysis of commit history for removed secrets |

## Supported Secret Types

### Cloud Credentials

- AWS access keys, secret keys, session tokens
- Azure credentials and connection strings
- GCP service account keys

### API Keys

- Generic API keys
- Stripe keys
- Twilio tokens
- SendGrid keys
- Slack tokens
- And many more...

### Authentication Tokens

- OAuth tokens
- JWT tokens
- Bearer tokens
- Session tokens

### Database Credentials

- Connection strings
- Database passwords
- MongoDB URIs
- Redis passwords

### Private Keys

- SSH keys
- RSA keys
- EC keys
- PGP private keys

### Version Control Tokens

- GitHub tokens (classic and fine-grained)
- GitLab tokens
- Bitbucket tokens

### High-Entropy Strings

- Base64-encoded secrets
- Hexadecimal secrets
- Random tokens

## API Usage

Secrets detection is automatically executed through the orchestrator:

```bash
curl -X POST http://localhost:3000/api/v1/analyze/job \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "source_type": "directory",
    "source_uri": "/path/to/project",
    "analysis_depth": "standard"
  }'
```

## Response Format

```json
{
  "findings": [
    {
      "module": "secrets",
      "type": "aws_access_key",
      "severity": "critical",
      "file": "config/settings.py",
      "line": 15,
      "secret_preview": "AKIA...XXXX",
      "message": "AWS Access Key ID detected",
      "remediation": "Remove the secret and rotate the AWS credentials immediately"
    },
    {
      "module": "secrets",
      "type": "high_entropy_base64",
      "severity": "medium",
      "file": "src/auth.js",
      "line": 42,
      "entropy": 4.8,
      "message": "High-entropy Base64 string detected (possible secret)",
      "remediation": "Review this string and move to environment variables if it's a secret"
    }
  ]
}
```

## Entropy Detection

### How It Works

Entropy measures the randomness of a string. High-entropy strings are likely to be secrets because they appear random (unlike normal code or text).

### Thresholds

| Type | Default Threshold | Description |
|------|-------------------|-------------|
| **Base64** | 4.5 | Strings matching Base64 pattern |
| **Hexadecimal** | 3.0 | Strings matching hex pattern |

### Configuration

```bash
# Base64 entropy threshold
VULNERA__SECRETS__ENTROPY_THRESHOLD_BASE64=4.5

# Hex entropy threshold  
VULNERA__SECRETS__ENTROPY_THRESHOLD_HEX=3.0
```

## Git History Scanning

Optional deep scanning of commit history:

```bash
VULNERA__SECRETS__ENABLE_GIT_HISTORY=true
VULNERA__SECRETS__GIT_HISTORY_DEPTH=100
```

This detects secrets that were committed and later removed but remain in git history.

## Configuration

```bash
# Entropy thresholds
VULNERA__SECRETS__ENTROPY_THRESHOLD_BASE64=4.5
VULNERA__SECRETS__ENTROPY_THRESHOLD_HEX=3.0

# File size limits
VULNERA__SECRETS__MAX_FILE_SIZE_BYTES=1000000

# Git history scanning
VULNERA__SECRETS__ENABLE_GIT_HISTORY=false
VULNERA__SECRETS__GIT_HISTORY_DEPTH=100

# Baseline file (for tracking known secrets)
VULNERA__SECRETS__BASELINE_FILE=.vulnera-baseline.json
```

## Exclude Patterns

The module automatically excludes:

- Build artifacts (`target/`, `dist/`, `build/`)
- Dependencies (`node_modules/`, `vendor/`)
- Generated files (`*.min.js`, `*.bundle.js`)
- Binary files

## Baseline Support

Track known secrets to reduce false positives:

```json
{
  "known_secrets": [
    {
      "file": "tests/fixtures/test_config.py",
      "line": 10,
      "type": "test_api_key",
      "reason": "Test fixture, not a real secret"
    }
  ]
}
```

## Severity Classification

| Severity | Secret Types |
|----------|--------------|
| **Critical** | AWS credentials, private keys, database passwords |
| **High** | API keys, OAuth tokens, JWT secrets |
| **Medium** | High-entropy strings, generic tokens |
| **Low** | Potential false positives, test credentials |
