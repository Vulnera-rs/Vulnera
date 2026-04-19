# vulnera-secrets

Entropy and pattern-based secret detection with verification.

## Purpose

Detect hardcoded credentials and sensitive data in source code:

- **Pattern matching** - 40+ built-in regex rules for common secret formats
- **Entropy analysis** - Shannon entropy detection for high-entropy strings
- **AST context** - Tree-sitter parsing for false-positive reduction
- **Live verification** - Confirm if detected tokens are actually valid

## Detection Pipeline (3-Pass)

1. **Pattern/Entropy Collection** - Regex rules + entropy scoring
2. **AST Analysis** - Context extraction using tree-sitter
3. **Semantic Validation** - Language-specific heuristics

## Supported Secret Types

- AWS credentials (Access Key, Secret Key, Session Token)
- GitHub/GitLab tokens
- Stripe, Twilio API keys
- JWT tokens, OAuth tokens
- Database passwords
- SSH/RSA/EC private keys
- Azure, GCP service account keys
- High-entropy Base64/Hex strings

## Verification

Live verification against actual providers:
- AWS STS (token validation)
- GitHub API (token scopes)
- GitLab API (token validation)

## CLI Features

```bash
vulnera secrets .                    # Basic scan
vulnera secrets . --baseline         # Differential scanning
vulnera secrets . --save-baseline    # Create baseline
vulnera secrets . --only-new         # Show only new secrets
```

## License

AGPL-3.0-or-later. See [LICENSE](../LICENSE) for details.
