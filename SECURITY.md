# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4   | :x:                |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

If you discover a security vulnerability in Vulnera, please report it responsibly:

1. **GitHub Security Advisories (preferred):** Use [GitHub's private vulnerability reporting](https://github.com/Vulnera-rs/Vulnera/security/advisories/new) to file a confidential advisory.
2. **Email:** Send a detailed report to **<security@vulnera.studio>**.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 5 business days
- **Fix release:** Coordinated disclosure within 90 days

### Scope

This policy covers the Vulnera server, CLI, all analysis modules (`vulnera-core`, `vulnera-sast`, `vulnera-deps`, `vulnera-secrets`, `vulnera-api`, `vulnera-sandbox`), and the web platform at [vulnera.studio](https://vulnera.studio).

### Out of Scope

- Vulnerabilities in third-party dependencies (report upstream, but let us know)
- Social engineering attacks
- Denial of service attacks that require excessive resources

## Security Design

Vulnera follows defense-in-depth principles:

- **Sandbox isolation:** All analysis modules execute within sandboxed environments (Landlock + seccomp on Linux)
- **Input validation:** Zero-trust model for all user inputs
- **Authentication:** JWT + API key with Argon2 password hashing
- **Database:** Parameterized queries via SQLx compile-time checks
- **Dependencies:** Regularly audited via `cargo audit`
