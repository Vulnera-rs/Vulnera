# Secrets Detection

Vulnera Secrets detects hardcoded credentials and sensitive tokens using regex-based rules and entropy heuristics. It runs fully offline by default, with optional provider verification.

## What It Detects

Common categories include:

- Cloud credentials (AWS, Azure, GCP)
- API keys and tokens (Stripe, Twilio, GitHub, GitLab, generic API keys)
- OAuth/JWT/Bearer tokens
- Database connection strings and passwords
- Private keys (RSA/EC/PGP/SSH)
- High-entropy strings (Base64/hex/generic tokens)

## How It Works

**Pipeline overview:**

1. **Discovery** — Walks files within the scan root.
2. **Regex rules** — Applies built-in secret patterns (rule pack).
3. **Entropy detection** — Flags high-entropy strings (Base64/hex + generic heuristics).
4. **Optional verification** — Provider-specific verification (disabled by default).
5. **Post-process** — Dedupes and emits unified findings.

## Detection Methods

| Method       | Description                                       | Offline |
| ------------ | ------------------------------------------------- | ------- |
| Regex rules  | Known secret patterns with context keywords       | ✅ Yes  |
| Entropy      | High-entropy token detection (Base64/hex/generic) | ✅ Yes  |
| Verification | Optional provider checks (AWS/GitHub/GitLab)      | ❌ No   |

## CLI Usage (Actual Flags)

Secrets detection runs via `vulnera secrets`:

```/dev/null/commands.txt#L1-16
# Basic scan
vulnera secrets .

# Only changed files (git required)
vulnera secrets . --changed-only

# Specific files
vulnera secrets . --files src/config.rs,src/lib.rs

# Exclude paths (glob patterns)
vulnera secrets . --exclude "tests/*,vendor/*"

# Include entropy-based detections (more noise)
vulnera secrets . --include-entropy
```

**Available flags:**

- `--fail-on-secret`
- `--changed-only`
- `--files <path1,path2,...>`
- `--exclude <glob1,glob2,...>`
- `--include-tests`
- `--include-entropy`
- `--no-cache`
- `--watch`

## Output

Secrets findings follow the unified finding schema. For secret findings:

- `secret_metadata` is populated
- `vulnerability_metadata` may be empty
- `enrichment` is optional (LLM)

You can emit SARIF:

```/dev/null/commands.txt#L1-2
vulnera secrets . --format sarif > report.sarif
```

## Configuration (Server + Library)

Secrets detection is configured via `vulnera_core::config::SecretDetectionConfig`.

Key settings:

- `enable_entropy_detection`
- `base64_entropy_threshold`, `hex_entropy_threshold`
- `exclude_patterns`, `exclude_extensions`
- `baseline_file_path`, `update_baseline`
- `scan_git_history`, `max_commits_to_scan`
- `enable_verification` (default: false)

Example (TOML):

```/dev/null/config.toml#L1-16
[secret_detection]
enable_entropy_detection = true
base64_entropy_threshold = 4.5
hex_entropy_threshold = 3.0
exclude_patterns = ["node_modules", ".git", "target"]
exclude_extensions = ["md", "markdown", "rst", "html"]
scan_git_history = false
enable_verification = false
```

## Offline Guarantees

Secrets detection runs fully offline by default:

- No network calls
- Regex rules and entropy heuristics are local
- Verification is opt-in and requires network access

## Limitations

- Entropy detection can surface false positives in test fixtures and generated tokens.
- Markdown and certain doc extensions are excluded by default unless explicitly included.
- Verification is limited to supported providers.

## Next Steps

- [Analysis Overview](overview.md)
- [Module Reference: Secrets Detection](../modules/secrets-detection.md)
- [Configuration Reference](../reference/configuration.md)
