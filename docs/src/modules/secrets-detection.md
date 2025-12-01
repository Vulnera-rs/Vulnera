# Secrets Detection

The Secrets Detection Module identifies exposed secrets, credentials, API keys, and other sensitive information in source code and repositories.

## Detection Methods

| Method            | Description                                             |
| ----------------- | ------------------------------------------------------- |
| **ML-based**      | ML Based Pattern Analyzer                               |
| **Entropy-based** | Statistical analysis detecting high-entropy strings     |
| **Git History**   | Optional analysis of commit history for removed secrets |

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

## Entropy Detection

### How It Works

Entropy measures the randomness of a string. High-entropy strings are likely to be secrets because they appear random (unlike normal code or text).

### Thresholds

| Type            | Default Threshold | Description                     |
| --------------- | ----------------- | ------------------------------- |
| **Base64**      | 4.5               | Strings matching Base64 pattern |
| **Hexadecimal** | 3.0               | Strings matching hex pattern    |

## Git History Scanning

Optional deep scanning of commit history:

This detects secrets that were committed and later removed but remain in git history.

## Exclude Patterns

The module automatically excludes:

- Build artifacts (`target/`, `dist/`, `build/`)
- Dependencies (`node_modules/`, `vendor/`)
- Generated files (`*.min.js`, `*.bundle.js`)
- Binary files
- what's in `.gitignore`

## Baseline Support

Track known secrets to reduce false positives:

## Severity Classification

| Severity     | Secret Types                                      |
| ------------ | ------------------------------------------------- |
| **Critical** | AWS credentials, private keys, database passwords |
| **High**     | API keys, OAuth tokens, JWT secrets               |
| **Medium**   | High-entropy strings, generic tokens              |
| **Low**      | Potential false positives, test credentials       |
