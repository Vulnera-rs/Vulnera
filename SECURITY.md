# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.5.x   | :white_check_mark: |
| 0.4.x   | :x:                |
| < 0.4   | :x:                |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

If you discover a security vulnerability in Vulnera, please report it responsibly through one of the following channels:

1. **GitHub Security Advisories (preferred):** Use [GitHub's private vulnerability reporting](https://github.com/vulnera-rs/Vulnera/security/advisories/new) to file a confidential advisory.
2. **Email:** Send a detailed report to **<security@vulnera.studio>**.

### What to Include

- Description of the vulnerability and its potential impact
- Affected component(s) and version(s)
- Detailed steps to reproduce
- Proof-of-concept code or exploit (if available)
- Suggested fix or mitigation (if any)

### Response Timeline

| Stage              | Target                      |
| ------------------ | --------------------------- |
| Acknowledgment     | Within 48 hours             |
| Initial assessment | Within 5 business days      |
| Fix & disclosure   | Coordinated, within 90 days |

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). We will credit reporters in release notes unless anonymity is requested.

### Scope

This policy covers:

- `vulnera-rust` (HTTP server binary)
- `vulnera-core`
- `vulnera-orchestrator`
- `vulnera-sast`
- `vulnera-deps`
- `vulnera-secrets`
- `vulnera-api`
- `vulnera-llm`
- `vulnera-sandbox`
- `vulnera-cli`
- `advisors`
- `adapter`
- The web platform at [vulnera.studio](https://vulnera.studio)

### Out of Scope

- Vulnerabilities in third-party dependencies (report upstream; notify us if Vulnera is directly affected)
- Social engineering or phishing attacks
- Denial-of-service attacks requiring excessive external resources
- Issues requiring physical access to infrastructure

---

## Security Design

Vulnera follows defense-in-depth principles across every layer:

### Sandbox Isolation

Analysis modules execute inside sandboxed environments. On Linux 5.13+, Landlock filesystem restrictions and seccomp syscall filtering are applied before any analysis code runs. The sandbox policy is a first-class typed domain concept — not an optional wrapper. `fail_closed` mode is available for environments that must hard-fail rather than degrade gracefully.

### Input Validation

All user-supplied input is validated at the presentation layer before reaching domain logic. SQL queries use SQLx compile-time `query!` macros — no string-interpolated SQL in production paths. This is enforced by a CI audit script that rejects non-macro `query()` calls.

### Authentication & Authorization

- Passwords are hashed with Argon2id.
- JWTs are signed with a configurable secret (minimum 32 bytes enforced at startup).
- API keys are stored as SHA-256 hashes; the raw key is shown only once at creation time.
- Cookie-based sessions use `HttpOnly`, `Secure`, and `SameSite=Lax` flags with CSRF token protection on all state-changing routes.
- Role-based access control (Owner / Admin / Analyst / Viewer) is enforced at the use-case layer.

### Dependency Auditing

Production dependencies are audited with `cargo audit`. The CI pipeline runs `cargo clippy` with `clippy::unwrap_used`, `clippy::expect_used`, and `clippy::panic` set to deny — panics in production code paths are blocked before merge.

### Secrets in Logs

Sensitive configuration values (JWT secret, API keys, database passwords) are never emitted to structured logs. Fields are explicitly suppressed in `tracing` instrumentation.
