# Vulnera Rust – High-Performance Vulnerability Analysis API

[![CI](https://github.com/k5602/Vulnera/actions/workflows/main-azure-web.yml/badge.svg?branch=main)](https://github.com/k5602/Vulnera/actions/workflows/main-azure-web.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.82%2B-orange.svg)](https://www.rust-lang.org/tools/install)

Vulnera is a fast, scalable, multi-ecosystem vulnerability analysis toolkit and testing platform built in Rust. While it excels at analyzing dependency manifests, Vulnera is intended as a comprehensive vulnerability analysis and testing toolkit—supporting not only dependency scanning, but also future features like codebase auditing, security testing, and integration with CI/CD workflows. It aggregates results from OSV, NVD, and GHSA, and exposes a robust HTTP API with OpenAPI docs. Designed for cloud-native workflows, Vulnera leverages async Rust, domain-driven design, and smart caching for reliability and speed.

---

## 🚀 Key Features

- **Multi-Ecosystem Support:** npm, PyPI, Maven/Gradle, Cargo, Go, Packagist, and more
- **Aggregated Vulnerability Data:** Combines OSV, NVD, and GitHub Security Advisories
- **Authentication & Authorization:** JWT tokens and API keys with PostgreSQL-backed user management
- **Async & Concurrent:** Built with Tokio for high throughput and bounded concurrency
- **Smart Caching & Recommendations:** Filesystem-based, TTL-configurable cache for reduced API calls; safe version recommendations (nearest and most up-to-date), upgrade impact classification (major/minor/patch), and next safe minor within current major, with a prerelease exclusion toggle
- **Domain-Driven Design:** Clean separation of domain, application, infrastructure, and presentation layers
- **OpenAPI Documentation:** Auto-generated Swagger UI for easy API exploration
- **Secure by Default:** Input validation, rate limiting, secure API handling, bcrypt password hashing
- **Container Ready:** Docker and Kubernetes support for production deployments
- **Developer Friendly:** Comprehensive tooling, linting, and CI/CD integration

---

## ⚡ Quick Start

### Prerequisites

- **Rust 1.82+**
- **PostgreSQL 12+** (or Docker for quick setup)
- **SQLx CLI** (for migrations): `cargo install sqlx-cli --no-default-features --features postgres`

### Installation

#### From Source

```bash
git clone https://github.com/vulnera/vulnera.git
cd vulnera

# Install Rust (stable) if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# System deps (Ubuntu/Debian)
sudo apt-get install -y pkg-config libssl-dev

# Setup database
# Local PostgreSQL
export DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'
sqlx migrate run --source migrations

# Build and run
cargo build --release
cargo run
```

#### Using Docker

```bash
docker build -t vulnera-rust .
docker run -p 3000:3000 vulnera-rust
```

---

## 🛠️ Usage

- **API Docs:** [http://localhost:3000/docs](http://localhost:3000/docs)
- **Health Check:** [http://localhost:3000/health](http://localhost:3000/health)

### Example: Analyze a Dependency File

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"file_content": "django==3.2.0\nrequests>=2.25.0", "ecosystem": "PyPI", "filename": "requirements.txt"}'
```

### Example: Analyze a GitHub Repository

```bash
curl -X POST http://localhost:3000/api/v1/analyze/repository \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "https://github.com/rust-lang/cargo", "ref": "main"}'
```

---

## 🔐 Authentication & Authorization

Vulnera includes a complete authentication system with support for both JWT tokens and API keys.

### Quick Setup

### User Registration

```bash
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123"
  }'
```

Returns access and refresh tokens immediately.

### Login

```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123"
  }'
```

### Authentication Methods

#### Method 1: JWT Bearer Token (Interactive Sessions)

```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"ecosystem": "npm", "content": "express@4.17.1"}'
```

**Best for:**

- Web applications
- Interactive API clients
- Short-lived sessions (default 24 hours)

#### Method 2: API Keys (Service Integration)

First, create an API key:

```bash
curl -X POST http://localhost:3000/api/v1/auth/api-keys \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "CI/CD Integration"}'
```

Then use it:

```bash
# Option A: X-API-Key header
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "X-API-Key: vuln_abc123..." \
  -H "Content-Type: application/json" \
  -d '{"ecosystem": "npm", "content": "express@4.17.1"}'

# Option B: Authorization header
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Authorization: ApiKey vuln_abc123..." \
  -H "Content-Type: application/json" \
  -d '{"ecosystem": "npm", "content": "express@4.17.1"}'
```

**Best for:**

- CI/CD pipelines
- Automated scripts
- Service-to-service communication
- Long-lived integrations

### API Endpoints

| Endpoint                     | Method | Auth          | Description                  |
| ---------------------------- | ------ | ------------- | ---------------------------- |
| `/api/v1/auth/register`      | POST   | None          | Create new user account      |
| `/api/v1/auth/login`         | POST   | None          | Login with email/password    |
| `/api/v1/auth/refresh`       | POST   | None          | Refresh expired access token |
| `/api/v1/auth/api-keys`      | POST   | Bearer        | Create new API key           |
| `/api/v1/auth/api-keys`      | GET    | Bearer/ApiKey | List your API keys           |
| `/api/v1/auth/api-keys/{id}` | DELETE | Bearer        | Revoke an API key            |

### Configuration

```bash
# Required
DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'

# Authentication settings
VULNERA__AUTH__JWT_SECRET='your-secret-minimum-32-characters'
VULNERA__AUTH__TOKEN_TTL_HOURS=24
VULNERA__AUTH__REFRESH_TOKEN_TTL_HOURS=720  # 30 days
VULNERA__AUTH__API_KEY_LENGTH=32
```

### Security Features

- ✅ Bcrypt password hashing (cost factor 12)
- ✅ API keys hashed before storage (never retrievable)
- ✅ JWT tokens with HMAC-SHA256 signing
- ✅ Configurable token expiration
- ✅ API key masking in list operations
- ✅ Role-based access control support

### Documentation

- **Detailed Testing Guide:** [docs/API_TESTING.md](docs/API_TESTING.md)
- **Database Setup:** [docs/SQLX_SETUP.md](docs/SQLX_SETUP.md)
- **Quick Start:** [QUICK_START.md](QUICK_START.md)

---

## 📦 Supported Ecosystems & File Formats

</text>

<old_text line=95>

- Example environment overrides:

  ```bash
  VULNERA__SERVER__PORT=8080
  VULNERA__CACHE__TTL_HOURS=24
  VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES=3
  VULNERA__RECOMMENDATIONS__EXCLUDE_PRERELEASES=false
  VULNERA__RECOMMENDATIONS__MAX_VERSION_QUERIES_PER_REQUEST=50
  VULNERA__APIS__NVD__API_KEY=your_nvd_api_key
  VULNERA__APIS__GHSA__TOKEN=your_github_token
  VULNERA__APIS__GITHUB__TOKEN=your_github_token
  VULNERA__APIS__GITHUB__REUSE_GHSA_TOKEN=true
  ```

- **Python:** `requirements.txt`, `Pipfile`, `pyproject.toml`
- **Node.js:** `package.json`, `package-lock.json`, `yarn.lock`
- **Java:** `pom.xml`, `build.gradle`
- **Rust:** `Cargo.toml`, `Cargo.lock`
- **Go:** `go.mod`, `go.sum`
- **PHP:** `composer.json`, `composer.lock`
- **Ruby:** `Gemfile`, `Gemfile.lock`
- **.NET (NuGet):** `packages.config`, `*.csproj` (PackageReference), `*.props`/`*.targets` (central management)

---

## ⚙️ Configuration

- Configurable via TOML files in `config/` and environment variables (prefix `VULNERA__`)

- Profiles: `development`, `production` (set via `ENV`)

- Example environment overrides:

  ```bash
  # Server
  VULNERA__SERVER__PORT=8080
  VULNERA__SERVER__ALLOWED_ORIGINS='["*"]'  # Use specific origins in production

  # Database (Required)
  DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'

  # Authentication (Required for production)
  VULNERA__AUTH__JWT_SECRET='your-secret-minimum-32-characters'
  VULNERA__AUTH__TOKEN_TTL_HOURS=24
  VULNERA__AUTH__REFRESH_TOKEN_TTL_HOURS=720
  VULNERA__AUTH__API_KEY_LENGTH=32
  VULNERA__AUTH__API_KEY_TTL_DAYS=365

  # Analysis & Caching
  VULNERA__CACHE__TTL_HOURS=24
  VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES=3

  # Recommendations
  VULNERA__RECOMMENDATIONS__EXCLUDE_PRERELEASES=false
  VULNERA__RECOMMENDATIONS__MAX_VERSION_QUERIES_PER_REQUEST=50

  # External APIs
  VULNERA__APIS__NVD__API_KEY=your_nvd_api_key
  VULNERA__APIS__GHSA__TOKEN=your_github_token
  VULNERA__APIS__GITHUB__TOKEN=your_github_token
  VULNERA__APIS__GITHUB__REUSE_GHSA_TOKEN=true
  ```

---

## 🏗️ Architecture & Design

Vulnera is built with **Domain-Driven Design (DDD)** and a layered architecture:

- **Domain Layer:** Pure business logic, entities, value objects
- **Application Layer:** Use cases, orchestration, error mapping
- **Infrastructure Layer:** API clients, parsers, caching, repositories
- **Presentation Layer:** HTTP API, DTOs, OpenAPI, middleware

**Core Flow:**
Dependency file → Parser → Concurrent package processing (default: 3 packages in parallel) → AggregatingVulnerabilityRepository (parallel API calls per package, merge results) → AnalysisReport → Optional reporting/caching.

**Caching:**
Filesystem-based, SHA256 keys, TTL configurable. Always use provided cache key helpers.

**Error Handling:**
Early mapping to domain/application errors, graceful degradation, and clear API responses.

---

## ⚡ Performance Tuning

Vulnera supports several configuration options to optimize performance for your specific use case:

### Concurrent Package Processing

Control how many packages are analyzed simultaneously:

```bash
# Default: 3 packages processed in parallel
VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES=3

# For larger systems with better resources
VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES=8

# For systems with API rate limits or resource constraints
VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES=1
```

**Performance Impact:**

- **3 packages (default)**: ~3x faster than sequential processing, balanced for API rate limits
- **Higher values**: Better performance for large dependency files, but may hit API rate limits
- **Lower values**: Safer for constrained environments or strict rate limits

### Other Performance Settings

```bash
# Vulnerability data caching (reduces API calls)
VULNERA__CACHE__TTL_HOURS=24

# File fetching concurrency for repository analysis
VULNERA__APIS__GITHUB__MAX_CONCURRENT_FILE_FETCHES=8

# Version query limits for recommendations
VULNERA__RECOMMENDATIONS__MAX_VERSION_QUERIES_PER_REQUEST=50
```

---

## 🧑‍💻 Development & Contribution

- **Dev Setup:**

  ```bash
  make -C scripts/build_workflow install-deps
  pre-commit install
  make dev
  ```

- **Testing:**
  `make test` (unit/integration), `make ci-check` (lint, format, audit)

- **Contribution:**
  Fork, branch, code, test, document, PR. Follow DDD, Rust best practices, and update OpenAPI docs for API changes.

### Testing guidance

- Run all checks locally:
  - `make -C scripts/build_workflow ci-check`
  - or `cargo test`
- Run only parser tests (substring filter):
  - `cargo test parsers`
- Mock HTTP clients:
  - Use the `mockito` crate. Start a mock server, stub endpoints, point the client base URL to the mock, assert responses.

See tests under `src/infrastructure/parsers/` and `tests/` for patterns.

### Contribution docs

Please read `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` before opening PRs. We welcome issues and feature requests—use the provided templates.

---

- **Production:**
  Harden config, disable docs, restrict CORS, provide API keys.

---

## 🛡️ Security Considerations

- HTTPS for all external API calls
- Input validation and sanitization
- Rate limiting and abuse protection
- Runs as non-root in containers
- Secure API key management

---

## 🐞 Troubleshooting

- **Build errors:** Update Rust, install system dependencies

- **API rate limits:** Provide API keys for OSV/NVD/GHSA
- **Token sharing:** GitHub token automatically shared with GHSA client when enabled (default: enabled)

- **Cache issues:** Clear `.vulnera_cache` or adjust TTL

- **Debugging:**

  ```bash
  VULNERA__LOGGING__LEVEL=debug cargo run
  ```

---

## 📜 Changelog

- See CHANGELOG.md for the latest updates, including safe version recommendations, extended registry support (Packagist, Go proxy, Maven Central), upgrade impact metadata, next safe minor hints, prerelease exclusion toggle, and request-level caps on version queries.
- Planned items are tracked in “Roadmap: Next Features” at the end of this file.

---

## 🦀 Why Rust? (vs Python)

- **Performance:** Rust is compiled and memory-safe, enabling much faster analysis and lower latency than Python’s interpreter.
- **Concurrency:** Tokio async runtime allows true parallelism and efficient IO, while Python’s async is limited by the GIL.
- **Reliability:** Rust’s strict type system and error handling prevent many runtime bugs common in Python.
- **Security:** Rust eliminates entire classes of memory safety vulnerabilities (buffer overflows, use-after-free) that can affect Python extensions.
- **Scalability:** Rust’s async and concurrency model scales to thousands of requests with minimal resources.
- **Ecosystem:** Rust’s package ecosystem (crates.io) and tooling (cargo, clippy, rustfmt) support modern development practices.

---

## 🌐 Azure Cloud Architecture

![Azure Architecture](./docs/Azure_Arch.png)

**Summary:**
Vulnera is designed for cloud-native deployment on Microsoft Azure.

- Edge: Azure Front Door for global entry, TLS, and WAF
- Identity: Entra Managed Identities for workload identity (no secrets in code)
- API Gateway: Azure API Management for routing, throttling, policies, and versioning
- Compute: Azure App Service or Azure Container Apps for running the Rust API
- Images: Azure Container Registry (ACR) for container images
- Secrets: Azure Key Vault for API keys and configuration
- Observability: Application Insights + Azure Monitor dashboards and logs
- CI/CD: GitHub Actions builds the app and container, pushes to ACR, and deploys to App Service/Container Apps; APIM can be updated as part of the pipeline

This architecture provides global reach, strong identity and secret management, and first-class observability while keeping operations streamlined.

---

## 👥 Team

- Khaled Mahmoud — Project Manager, Main Developer, Rust Backend Developer
- Abd El-Rahman Mossad — Frontend Developer - Extension , LSP Server Developer and Maintainer
- Amr Medhat — Cloud Engineer
- Gasser Mohammed — Frontend Developer

---

## 📝 License

Affero GPL v3.0 or later — see [LICENSE](./LICENSE).

---

## 🌐 Vulnera Frontend

Looking for the web UI?
Find the official Vulnera Frontend at: [https://github.com/k5602/Vulnera-Frontend](https://github.com/k5602/Vulnera-Frontend)

---

## 🗺️ Roadmap: Next Features

This section outlines concrete, near-term work we plan to deliver across the toolkit, editor integrations, and platform.

### Toolkit expansions

- More scanners and utilities integrated under a single CLI/API:
  - SBOM generation and ingestion (CycloneDX/SPDX), dependency graph, license compliance
  - Container image scanning (e.g., Trivy-like capabilities) and base image advisory mapping
  - Secrets detection, basic SAST rules, and config hardening checks
  - IaC scanning: Terraform/Kubernetes manifests with policy violations surfaced
  - SARIF export for CI/CD and code-host integrations
- Repository and PR scanning: diff-aware analysis and severity gating
- Policy-as-code: fail-the-build thresholds, rules engine, and optional OPA/Rego integration

### Editor ecosystem

- VS Code extension: live diagnostics, quick fixes, “Analyze file/repo” commands, status bar, and SARIF viewer wiring
- LSP server (Rust, JSON-RPC/stdio) exposing diagnostics and code actions:
  - Clients: Neovim (nvim-lspconfig) and Zed (extension) with zero-config defaults
  - Features: on-save analysis, inline severities, version bump suggestions, suppress/justification workflow
  - Protocol: initialize → didOpen/didChange → diagnostics; custom method for “vulnera/analyzeProject”

### Platform and backend

- Redis optional cache backend with shared TTLs and cache key parity to filesystem cache
- Resilience: centralized backoff/retry budgets and per-provider rate limiting
- Observability: OpenTelemetry traces/metrics, enriched Application Insights dashboards
- Security: API keys/OAuth, RBAC roles, audit logs, and secret-less auth via Entra Managed Identities on Azure
- Offline/air-gapped mode with mirrored OSV/NVD snapshots and scheduled refresh

### Nice-to-haves (suggested)

- Dependency upgrade assistant (safe version bump planner per ecosystem)
- Risk scoring that combines CVSS, exploit signals, and package health
- Webhooks and GitHub/GitLab apps for automated PR comments with findings
- First-class SBOM endpoint: POST SBOM → normalized analysis → report
- Multi-tenant org/projects model and usage quotas

If you want a dedicated tracking issue and milestone plan, open an issue and we’ll convert this roadmap into tasks with timelines.

---

## 🔐 Security Policy

- Responsible disclosure: Please use GitHub Security Advisories (Report a vulnerability) for private coordination. Avoid public issues for security reports.
- Secret management: On Azure, prefer Entra Managed Identities and Key Vault; avoid committing secrets or storing long‑lived tokens in plaintext env vars.
- Target response time: within 72 hours.

---

## 🔁 Versioning & Releases

- Semantic Versioning (SemVer): MAJOR.MINOR.PATCH.
- Release notes and changelogs are published in GitHub Releases for this repo.
- Every release is tagged; breaking changes are highlighted in notes.
